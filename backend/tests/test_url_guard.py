"""
Tests for url_guard — SSRF protection.

Monkeypatches socket.gethostbyname so no real DNS is needed.
"""

import socket
import pytest
import sys
import os

# Make sure we can import from the backend root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from url_guard import resolve_and_guard, check_url_after_redirect, PrivateTargetError


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _disable_allow_private(monkeypatch):
    """Ensure ALLOW_PRIVATE_TARGETS is unset for every test."""
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    # Reload the module-level flag
    import url_guard
    monkeypatch.setattr(url_guard, "_ALLOW_PRIVATE", False)


# ── resolve_and_guard ─────────────────────────────────────────────────


class TestResolveAndGuard:
    def test_public_ip_allowed(self, monkeypatch):
        """A hostname resolving to a public IP should pass."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "93.184.216.34")
        hostname, ip = resolve_and_guard("https://example.com/path")
        assert hostname == "example.com"
        assert ip == "93.184.216.34"

    def test_loopback_blocked(self, monkeypatch):
        """127.0.0.1 must be blocked."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "127.0.0.1")
        with pytest.raises(PrivateTargetError):
            resolve_and_guard("http://evil.com/")

    def test_private_10x_blocked(self, monkeypatch):
        """10.0.0.1 (RFC 1918) must be blocked."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "10.0.0.1")
        with pytest.raises(PrivateTargetError):
            resolve_and_guard("http://evil.com/")

    def test_private_172x_blocked(self, monkeypatch):
        """172.16.0.1 (RFC 1918) must be blocked."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "172.16.0.1")
        with pytest.raises(PrivateTargetError):
            resolve_and_guard("http://evil.com/")

    def test_private_192x_blocked(self, monkeypatch):
        """192.168.1.1 (RFC 1918) must be blocked."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "192.168.1.1")
        with pytest.raises(PrivateTargetError):
            resolve_and_guard("http://evil.com/")

    def test_link_local_blocked(self, monkeypatch):
        """169.254.x.x link-local addresses must be blocked."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "169.254.1.1")
        with pytest.raises(PrivateTargetError):
            resolve_and_guard("http://evil.com/")

    def test_cloud_metadata_blocked(self, monkeypatch):
        """AWS/GCP metadata endpoint 169.254.169.254 must be blocked."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "169.254.169.254")
        with pytest.raises(PrivateTargetError):
            resolve_and_guard("http://evil.com/")

    @pytest.mark.parametrize("blocked_ip", [
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
        "100.64.0.1",
    ])
    def test_non_global_ips_blocked(self, monkeypatch, blocked_ip):
        """::1, fe80::1, fc00::1, ::ffff:127.0.0.1, 0.0.0.0 and 100.64.0.1 must be blocked."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: blocked_ip)
        with pytest.raises(PrivateTargetError):
            resolve_and_guard("http://evil.com/")

    @pytest.mark.parametrize("blocked_ip", [
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
        "100.64.0.1",
    ])
    def test_direct_non_global_ip_urls_blocked(self, blocked_ip):
        """Direct IP target URLs must be blocked even without DNS."""
        target = f"http://[{blocked_ip}]/" if ":" in blocked_ip else f"http://{blocked_ip}/"
        with pytest.raises(PrivateTargetError):
            resolve_and_guard(target)

    def test_allow_private_override(self, monkeypatch):
        """When ALLOW_PRIVATE_TARGETS is set, private IPs pass through."""
        import url_guard
        monkeypatch.setattr(url_guard, "_ALLOW_PRIVATE", True)
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "127.0.0.1")
        hostname, ip = resolve_and_guard("http://localhost:8000/")
        assert ip == "127.0.0.1"

    def test_no_hostname_raises(self):
        """A URL without a hostname raises ValueError."""
        with pytest.raises(ValueError):
            resolve_and_guard("not-a-url")


# ── check_url_after_redirect ─────────────────────────────────────────


class TestCheckAfterRedirect:
    def test_public_redirect_ok(self, monkeypatch):
        """Redirect to a public IP passes silently."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "93.184.216.34")
        check_url_after_redirect("https://redirected.example.com/page")

    def test_redirect_to_private_blocked(self, monkeypatch):
        """Redirect landing on a private IP must raise."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "10.0.0.5")
        with pytest.raises(PrivateTargetError):
            check_url_after_redirect("http://internal-service/admin")


# ── Integration with behavior engine ─────────────────────────────────


class TestBehaviorSSRF:
    def test_behavior_returns_blocked_reason(self, monkeypatch):
        """analyze_behavior should return blocked_private_address for a loopback target."""
        monkeypatch.setattr(socket, "gethostbyname", lambda _: "127.0.0.1")
        from engines.behavior import analyze_behavior
        result = analyze_behavior("http://evil.com/steal-creds")
        assert result["behavior_analysis_failed"] is True
        assert result["behavior_failure_reason"] == "blocked_private_address"
        assert result["behavior_score"] == 0.0

    def test_behavior_prelaunch_listener_zero_hits(self):
        """Pre-launch check blocks private target before browser launch; listener gets 0 hits."""
        import threading
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from engines.behavior import analyze_behavior

        hits = [0]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits[0] += 1
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args): pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            result = analyze_behavior(f"http://127.0.0.1:{port}/direct")
            assert hits[0] == 0, f"Expected 0 hits on listener, got {hits[0]}"
            assert result["behavior_analysis_failed"] is True
            assert result["behavior_failure_reason"] == "blocked_private_address"
        finally:
            server.shutdown()

    def test_behavior_route_interception_listener_zero_hits(self):
        """Playwright page.route aborts subresource request to private address; listener gets 0 hits.
        The page analysis itself completes and counts the blocked request.
        """
        import threading
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from engines.behavior import analyze_behavior

        hits = [0]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits[0] += 1
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args): pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            # Page embeds an image pointing to the private listener
            target_url = f"data:text/html,<img src=\"http://127.0.0.1:{port}/subresource-leak\">"
            result = analyze_behavior(target_url)
            assert hits[0] == 0, f"Expected 0 hits on listener, got {hits[0]}"
            # Sub-request aborted, but page analysis completes successfully
            assert result["behavior_analysis_failed"] is False
            assert result["blocked_private_requests"] >= 1
            assert result["behavior_score"] >= 10.0
        finally:
            server.shutdown()

    def test_behavior_hidden_internal_image_with_login_form_detected(self):
        """A page with a hidden internal-address image AND a login form:
        - Image request to 127.0.0.1 is aborted (0 hits).
        - Page analysis succeeds.
        - The login form is still detected.
        - blocked_private_requests is recorded.
        - behavior_score includes the penalty (+10) on top of login form (+20) = 30.
        """
        import threading
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from engines.behavior import analyze_behavior

        hits = [0]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits[0] += 1
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args): pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            html = f"""
            <html>
                <body>
                    <img src="http://127.0.0.1:{port}/secret.png" style="display:none" width="0" height="0">
                    <form action="/login">
                        <input type="text" name="user">
                        <input type="password" name="pass">
                        <button type="submit">Log In</button>
                    </form>
                </body>
            </html>
            """
            target_url = f"data:text/html,{html}"
            result = analyze_behavior(target_url)

            # Request was aborted before reaching the listener
            assert hits[0] == 0, f"Expected 0 hits on listener, got {hits[0]}"
            # Page analysis completed
            assert result["behavior_analysis_failed"] is False
            assert result["has_login_form"] is True
            assert result["blocked_private_requests"] >= 1
            # 20 for login form + 10 for blocked private sub-request = 30
            assert result["behavior_score"] == 30.0
        finally:
            server.shutdown()

    def test_behavior_route_fail_closed_on_error(self, monkeypatch):
        """If resolve_and_guard raises an unexpected error during route check,
        the route handler must fail-closed (abort request) and increment blocked count.
        """
        import engines.behavior as behavior_mod

        def _boom(url):
            raise RuntimeError("Unexpected resolver failure")

        monkeypatch.setattr(behavior_mod, "resolve_and_guard", _boom)

        # When resolver throws an unexpected error on route check:
        # Route handler catches the error, increments blocked_private_count, and aborts
        result = behavior_mod.analyze_behavior("data:text/html,<img src='http://example.com/pic.jpg'>")
        assert result["blocked_private_requests"] >= 1

