import os
import time
import base64
import requests
from collections import deque
from loguru import logger

# Rate limiter: max 4 requests per 60 seconds
request_times = deque()

def _wait_for_rate_limit():
    global request_times
    now = time.time()

    # Remove times older than 60 seconds
    while request_times and now - request_times[0] > 60:
        request_times.popleft()

    if len(request_times) >= 4:
        # We need to wait until the oldest request is older than 60 seconds
        sleep_time = 60 - (now - request_times[0]) + 0.1 # Add small buffer
        if sleep_time > 0:
            logger.info(f"[Threat Intel] Rate limit reached. Sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)

        # Re-evaluate after sleeping
        now = time.time()
        while request_times and now - request_times[0] > 60:
            request_times.popleft()

    request_times.append(time.time())

def _get_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _saturating_threat_score(flagged: int) -> float:
    """
    Saturating threat score based on number of engines that flagged the URL.
    Produces a human-meaningful risk score that saturates towards 100:
      0 flags -> 0
      1 flag  -> ~25
      2 flags -> ~40
      3-4     -> ~60
      5-7     -> ~80
      8+      -> 100
    """
    if flagged <= 0:
        return 0.0
    if flagged == 1:
        return 25.0
    if flagged == 2:
        return 40.0
    if flagged <= 4:
        return 60.0
    if flagged <= 7:
        return 80.0
    return 100.0


def check_threat_intel(url: str) -> dict:
    result = {
        "total_engines_flagged": 0,
        "total_engines_checked": 0,
        "threat_score": 0.0,
        "threat_intel_failed": False,
        "never_seen_before": False,
        "rate_limited_incomplete": False
    }

    api_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    if not api_key:
        logger.warning("[Threat Intel] No VIRUSTOTAL_API_KEY or VT_API_KEY found.")
        result["threat_intel_failed"] = True
        return result

    headers = {
        "x-apikey": api_key
    }

    url_id = _get_url_id(url)

    try:
        # Step 1: Check if already scanned
        _wait_for_rate_limit()
        get_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        logger.info(f"[Threat Intel] Querying existing VT report for {url}")
        resp = requests.get(get_url, headers=headers, timeout=5)

        if resp.status_code == 200:
            # VT has a cached record — extract stats
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)

            total_flagged = malicious + suspicious
            total_checked = malicious + suspicious + undetected + harmless

            if total_checked == 0:
                # VT returned a record but with no engines — treat as never seen
                result["never_seen_before"] = True
            else:
                result["total_engines_flagged"] = total_flagged
                result["total_engines_checked"] = total_checked
                result["threat_score"] = _saturating_threat_score(total_flagged)

            return result

        elif resp.status_code == 404:
            # Definitive: VT has no prior record of this URL at all.
            # This is the "never seen before" signal — costs no polling.
            logger.info(f"[Threat Intel] URL never seen by VT (404): {url}")
            result["never_seen_before"] = True

            # Optional enrichment: submit for scanning so future lookups have data.
            # This is fire-and-forget within our time budget.
            try:
                _wait_for_rate_limit()
                post_url = "https://www.virustotal.com/api/v3/urls"
                post_data = {"url": url}
                post_headers = {"x-apikey": api_key, "Content-Type": "application/x-www-form-urlencoded"}

                logger.info(f"[Threat Intel] Submitting for enrichment scan: {url}")
                post_resp = requests.post(post_url, headers=post_headers, data=post_data, timeout=5)

                if post_resp.status_code != 200:
                    logger.warning(f"[Threat Intel] Enrichment submission failed (status {post_resp.status_code}), but never_seen_before is already set.")
                else:
                    analysis_id = post_resp.json().get("data", {}).get("id")
                    if analysis_id:
                        # Try polling for results within remaining time budget
                        start_time = time.time()
                        max_wait = 6.0  # Leave margin within the 8s hard cap

                        while time.time() - start_time < max_wait:
                            # Check if rate limiter would block us past our budget
                            now = time.time()
                            if len(request_times) >= 4 and now - request_times[0] <= 60:
                                sleep_needed = 60 - (now - request_times[0])
                                if (now - start_time) + sleep_needed >= max_wait:
                                    logger.info(f"[Threat Intel] Rate limit wait ({sleep_needed:.2f}s) exceeds enrichment budget. Keeping never_seen_before.")
                                    break

                            _wait_for_rate_limit()

                            if time.time() - start_time >= max_wait:
                                break

                            poll_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                            logger.info(f"[Threat Intel] Polling enrichment: {analysis_id}")
                            poll_resp = requests.get(poll_url, headers=headers, timeout=5)

                            if poll_resp.status_code == 200:
                                poll_data = poll_resp.json().get("data", {}).get("attributes", {})
                                status = poll_data.get("status")

                                if status == "completed":
                                    stats = poll_data.get("stats", {})
                                    malicious = stats.get("malicious", 0)
                                    suspicious = stats.get("suspicious", 0)
                                    undetected = stats.get("undetected", 0)
                                    harmless = stats.get("harmless", 0)

                                    total_flagged = malicious + suspicious
                                    total_checked = malicious + suspicious + undetected + harmless

                                    if total_checked > 0:
                                        # Enrichment succeeded — upgrade from never_seen_before
                                        result["never_seen_before"] = False
                                        result["total_engines_flagged"] = total_flagged
                                        result["total_engines_checked"] = total_checked
                                        result["threat_score"] = _saturating_threat_score(total_flagged)
                                        logger.info(f"[Threat Intel] Enrichment completed: {total_flagged}/{total_checked} flagged")
                                    break
                                else:
                                    logger.info(f"[Threat Intel] Enrichment status: {status}. Waiting 2s...")
                                    time.sleep(2)
                            else:
                                logger.warning(f"[Threat Intel] Enrichment poll failed (status {poll_resp.status_code})")
                                break
            except Exception as enrich_err:
                # Enrichment is best-effort; never_seen_before is already set
                logger.warning(f"[Threat Intel] Enrichment failed: {enrich_err}")

            return result

        elif resp.status_code == 429:
            # API rate limited by VirusTotal itself
            logger.error(f"[Threat Intel] VT API rate limited (429)")
            result["rate_limited_incomplete"] = True
            return result

        else:
            logger.error(f"[Threat Intel] VT get url failed with status {resp.status_code}, body: {resp.text}")
            result["threat_intel_failed"] = True
            return result

    except requests.exceptions.Timeout:
        logger.error("[Threat Intel] Request timed out")
        result["threat_intel_failed"] = True
        return result
    except requests.exceptions.ConnectionError:
        logger.error("[Threat Intel] Connection error — VT unreachable")
        result["threat_intel_failed"] = True
        return result
    except Exception as e:
        logger.error(f"[Threat Intel] Exception during VT check: {e}")
        result["threat_intel_failed"] = True
        return result
