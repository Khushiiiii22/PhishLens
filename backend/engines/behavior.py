"""
PhishLens — Website Behavior Analysis Engine

Uses Playwright (headless Chromium) to render a page and inspect it for
phishing-indicative behaviors: login forms, hidden iframes, JS redirects,
external form actions, and popup attempts.

Every operation is wrapped so that a failure (timeout, blocked, DNS error)
returns a safe default result instead of crashing.

No imports from database.py, models.py, or schemas.py.
"""

from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout


def _same_domain(url_a: str, url_b: str) -> bool:
    """Return True if two URLs share the same registered domain."""
    try:
        return urlparse(url_a).hostname == urlparse(url_b).hostname
    except Exception:
        return True  # can't parse → assume same


def _safe_result(failed: bool = True) -> dict:
    """Return a zeroed-out result when analysis could not be performed."""
    return {
        "has_login_form": False,
        "has_hidden_iframe": False,
        "has_js_redirect": False,
        "external_form_action": False,
        "popup_detected": False,
        "behavior_score": 0.0,
        "behavior_analysis_failed": failed,
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
        behavior_analysis_failed
    """
    pw = None
    browser = None

    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
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

        # Navigate with a 10-second timeout
        page.goto(url, wait_until="domcontentloaded", timeout=10_000)

        # Allow a short extra settle for late JS
        page.wait_for_timeout(1500)

        final_url = page.url

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

        return {
            "has_login_form": bool(has_login_form),
            "has_hidden_iframe": bool(has_hidden_iframe),
            "has_js_redirect": bool(has_js_redirect),
            "external_form_action": bool(external_form_action),
            "popup_detected": bool(popup_detected),
            "behavior_score": behavior_score,
            "behavior_analysis_failed": False,
        }

    except (PwTimeout, Exception):
        # Page timeout, DNS failure, connection refused, headless-block, etc.
        return _safe_result(failed=True)

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
