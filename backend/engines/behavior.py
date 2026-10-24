"""
PhishLens — Website Behavior Analysis Engine

Uses Playwright (headless Chromium) to render a page and inspect it for
phishing-indicative behaviors: login forms, hidden iframes, JS redirects,
external form actions, and popup attempts.

Every operation is wrapped so that a failure (timeout, blocked, DNS error)
returns a safe default result instead of crashing.

No imports from database.py, models.py, or schemas.py.
"""

import socket
import time
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
from loguru import logger

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from url_guard import resolve_and_guard, check_url_after_redirect, PrivateTargetError

# Fixed score bump when the page tries to load sub-resources from
# private/internal addresses.  Not large enough to dominate the score,
# but a clear signal that the page is doing something suspicious.
_PRIVATE_SUBREQUEST_PENALTY = 10


def _same_domain(url_a: str, url_b: str) -> bool:
    """Return True if two URLs share the same registered domain."""
    try:
        host_a = (urlparse(url_a).hostname or "").lower()
        host_b = (urlparse(url_b).hostname or "").lower()
        
        if host_a.startswith("www."): host_a = host_a[4:]
        if host_b.startswith("www."): host_b = host_b[4:]
            
        if host_a == host_b:
            return True
        if host_a.endswith("." + host_b) or host_b.endswith("." + host_a):
            return True
        return False
    except Exception:
        return True


def _safe_result(failed: bool = True, failure_reason: str | None = None) -> dict:
    """Return a zeroed-out result when analysis could not be performed."""
    return {
        "has_login_form": False,
        "has_hidden_iframe": False,
        "has_js_redirect": False,
        "external_form_action": False,
        "popup_detected": False,
        "behavior_score": 0.0,
        "behavior_analysis_failed": failed,
        "behavior_failure_reason": failure_reason,
        "blocked_private_requests": 0,
    }


def _compute_behavior_score(
    has_login_form: bool,
    has_hidden_iframe: bool,
    has_js_redirect: bool,
    external_form_action: bool,
    popup_detected: bool,
) -> float:
    """
    Combine behavior signals into a 0-100 risk score.

    login_form + external_form_action together is the single strongest
    phishing indicator (~70 on its own). Other signals layer on top.
    """
    score = 0.0

    if has_login_form and external_form_action:
        score += 70  # credential harvesting pattern
    elif has_login_form:
        score += 20  # login forms alone are common on legit sites too
    elif external_form_action:
        score += 30  # external action without visible login is unusual

    if has_hidden_iframe:
        score += 15

    if has_js_redirect:
        score += 10

    if popup_detected:
        score += 5

    return round(min(score, 100.0), 1)


def analyze_behavior(url: str) -> dict:
    """
    Navigate to *url* in a headless Chromium browser, inspect the rendered
    page, and return behavioral risk indicators.

    Parameters
    ----------
    url : str
        The full URL to visit.

    Returns
    -------
    dict with keys:
        has_login_form, has_hidden_iframe, has_js_redirect,
        external_form_action, popup_detected, behavior_score,
        behavior_analysis_failed, behavior_failure_reason,
        blocked_private_requests
    """
    start = time.perf_counter()
    logger.info("[Behavior] Starting analysis for: {}", url)

    # ── SSRF guard: block private/internal targets ──
    try:
        resolve_and_guard(url)
    except PrivateTargetError:
        logger.warning("[Behavior] Blocked private target: {}", url)
        return _safe_result(failed=True, failure_reason="blocked_private_address")
    except Exception:
        pass  # DNS failure will be caught by Playwright later

    pw = None
    browser = None
    blocked_private_count = 0

    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        # Track popup/new-tab attempts
        popup_detected = False

        def _on_popup(_page):
            nonlocal popup_detected
            popup_detected = True

        page = context.new_page()
        page.on("popup", _on_popup)

        # ── Intercept every request (redirects, iframes, subresources) ──
        # Fail-closed: any exception during the check aborts the request.
        main_frame_blocked = False
        guard_cache: dict[str, BaseException | None] = {}

        def _handle_route(route):
            nonlocal blocked_private_count, main_frame_blocked
            req_url = route.request.url
            # Let data/blob/about/javascript through without checking
            if req_url.startswith(("data:", "blob:", "about:", "javascript:")):
                try:
                    route.continue_()
                except Exception:
                    pass
                return

            # 1. Guard check first (cached per hostname within this scan)
            host = urlparse(req_url).hostname or ""
            exc_to_raise: BaseException | None = None

            if host in guard_cache:
                cached = guard_cache[host]
                if isinstance(cached, BaseException):
                    exc_to_raise = cached
            else:
                try:
                    resolve_and_guard(req_url)
                    guard_cache[host] = None
                except BaseException as exc:
                    guard_cache[host] = exc
                    exc_to_raise = exc

            if exc_to_raise is not None:
                if isinstance(exc_to_raise, PrivateTargetError):
                    logger.warning("[Behavior] Aborting request to non-public address: {}", req_url)
                    blocked_private_count += 1
                    if route.request.is_navigation_request() and route.request.frame == page.main_frame:
                        main_frame_blocked = True
                    try:
                        route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return
                elif isinstance(exc_to_raise, (socket.gaierror, socket.herror)):
                    try:
                        route.abort("namenotresolved")
                    except Exception:
                        pass
                    return
                else:
                    # Fail closed: if we can't determine whether the target
                    # is safe, abort the request rather than allowing it.
                    logger.warning("[Behavior] Guard check failed for {}, aborting (fail-closed): {}", req_url, exc_to_raise)
                    blocked_private_count += 1
                    if route.request.is_navigation_request() and route.request.frame == page.main_frame:
                        main_frame_blocked = True
                    try:
                        route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return

            # 2. Guard passed. Abort heavy assets (images, media, fonts) to save bandwidth and execution time.
            resource_type = route.request.resource_type
            if resource_type in ("image", "media", "font"):
                try:
                    route.abort("blockedbyclient")
                except Exception:
                    pass
                return

            # 3. Allow other safe resources (scripts, styles, documents, xhr/fetch)
            try:
                route.continue_()
            except Exception:
                pass

        page.route("**/*", _handle_route)

        # Navigate with a 15-second timeout (accommodates 0.25 CPU container limits)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15_000)
        except Exception as nav_err:
            # If main-frame navigation was blocked by our guard, fail the engine
            if main_frame_blocked:
                logger.warning("[Behavior] Main-frame navigation to private address blocked for {}", url)
                return _safe_result(failed=True, failure_reason="blocked_private_address")
            # Re-raise so the outer handler classifies the error
            raise nav_err

        # Allow a short extra settle for late JS
        page.wait_for_timeout(1500)

        # If the main-frame navigation itself ended up blocked (via redirect)
        if main_frame_blocked:
            logger.warning("[Behavior] Main-frame redirected to private address for {}", url)
            return _safe_result(failed=True, failure_reason="blocked_private_address")

        final_url = page.url

        # ── SSRF guard: re-check after redirects ──
        try:
            check_url_after_redirect(final_url)
        except PrivateTargetError:
            logger.warning("[Behavior] Redirect to private target blocked: {}", final_url)
            return _safe_result(failed=True, failure_reason="blocked_private_address")

        # ── has_js_redirect ──
        has_js_redirect = not _same_domain(url, final_url)

        # ── has_login_form ──
        has_login_form = page.evaluate("""() => {
            const pwInputs = document.querySelectorAll('input[type="password"]');
            for (const inp of pwInputs) {
                const form = inp.closest('form');
                if (form) return true;
            }
            return false;
        }""")

        # ── external_form_action ──
        page_hostname = urlparse(final_url).hostname or ""
        external_form_action = page.evaluate("""(pageHost) => {
            const forms = document.querySelectorAll('form[action]');
            for (const f of forms) {
                const action = f.getAttribute('action');
                if (!action || action.startsWith('#') || action.startsWith('/') || action.startsWith('?')) continue;
                try {
                    const actionHost = new URL(action, document.location.href).hostname;
                    if (actionHost && actionHost !== pageHost) return true;
                } catch(e) {}
            }
            return false;
        }""", page_hostname)

        # ── has_hidden_iframe ──
        has_hidden_iframe = page.evaluate("""() => {
            const iframes = document.querySelectorAll('iframe');
            for (const ifr of iframes) {
                const style = window.getComputedStyle(ifr);
                const w = ifr.width || ifr.getAttribute('width') || '';
                const h = ifr.height || ifr.getAttribute('height') || '';
                if (style.display === 'none' || style.visibility === 'hidden') return true;
                if (w === '0' || h === '0') return true;
                if (parseInt(style.width) === 0 || parseInt(style.height) === 0) return true;
            }
            return false;
        }""")

        behavior_score = _compute_behavior_score(
            has_login_form=has_login_form,
            has_hidden_iframe=has_hidden_iframe,
            has_js_redirect=has_js_redirect,
            external_form_action=external_form_action,
            popup_detected=popup_detected,
        )

        # Bump score if sub-resources tried to reach private addresses
        if blocked_private_count > 0:
            behavior_score = round(min(behavior_score + _PRIVATE_SUBREQUEST_PENALTY, 100.0), 1)
            logger.warning(
                "[Behavior] {} sub-request(s) to private addresses blocked — "
                "score bumped by {} → {}",
                blocked_private_count, _PRIVATE_SUBREQUEST_PENALTY, behavior_score,
            )

        elapsed = time.perf_counter() - start
        logger.info("[Behavior] Completed in {:.1f}s — score: {}", elapsed, behavior_score)

        return {
            "has_login_form": bool(has_login_form),
            "has_hidden_iframe": bool(has_hidden_iframe),
            "has_js_redirect": bool(has_js_redirect),
            "external_form_action": bool(external_form_action),
            "popup_detected": bool(popup_detected),
            "behavior_score": behavior_score,
            "behavior_analysis_failed": False,
            "behavior_failure_reason": None,
            "blocked_private_requests": blocked_private_count,
        }

    except (PwTimeout, Exception) as e:
        elapsed = time.perf_counter() - start
        logger.warning("[Behavior] Failed after {:.1f}s — reason: {}", elapsed, e)
        try:
            if main_frame_blocked:
                return _safe_result(failed=True, failure_reason="blocked_private_address")
        except NameError:
            pass
        # Classify the specific failure reason
        err_msg = str(e).lower()
        if (
            "err_name_not_resolved" in err_msg
            or "err_name_resolution_failed" in err_msg
            or "err_connection_refused" in err_msg
            or "err_address_unreachable" in err_msg
            or "dns" in err_msg
        ):
            failure_reason = "dns_failure"
        elif isinstance(e, PwTimeout) or "timeout" in err_msg:
            failure_reason = "timeout"
        elif (
            "blocked" in err_msg
            or "access_denied" in err_msg
            or "403" in err_msg
            or "forbidden" in err_msg
        ):
            failure_reason = "blocked"
        else:
            failure_reason = None

        return _safe_result(failed=True, failure_reason=failure_reason)

    finally:
        # ALWAYS clean up browser resources, even on failure
        try:
            if browser:
                browser.close()
        except Exception:
            pass
        try:
            if pw:
                pw.stop()
        except Exception:
            pass
