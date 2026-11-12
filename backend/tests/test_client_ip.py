"""Tests for _get_client_ip — proxy-safe client IP extraction.

Covers:
  - True-Client-IP takes priority
  - X-Forwarded-For uses index -TRUSTED_PROXY_HOPS (never index 0)
  - Forged leftmost X-Forwarded-For entry is ignored
  - Falls back to request.client.host
  - Store eviction: entries older than 1 hour, max 10 000 keys
"""

import time
import pytest
from unittest.mock import MagicMock

from routers.scan import (
    _get_client_ip,
    _ip_scan_history,
    _evict_expired_entries,
    _check_rate_limit,
    _record_scan_for_ip,
    _reset_scan_limits,
    _RATE_LIMIT_MAX_KEYS,
    _RATE_LIMIT_WINDOW_SECONDS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_request(
    headers: dict[str, str] | None = None,
    client_host: str | None = "10.0.0.1",
) -> MagicMock:
    """Build a minimal mock ``Request`` with the given headers and peer IP."""
    req = MagicMock()
    req.headers = headers or {}
    if client_host:
        req.client = MagicMock()
        req.client.host = client_host
    else:
        req.client = None
    return req


@pytest.fixture(autouse=True)
def _clean():
    _reset_scan_limits()
    yield
    _reset_scan_limits()


# ---------------------------------------------------------------------------
# 1. True-Client-IP takes priority
# ---------------------------------------------------------------------------

class TestTrueClientIP:
    def test_true_client_ip_is_preferred(self):
        req = _fake_request(
            headers={
                "True-Client-IP": "93.184.216.34",
                "X-Forwarded-For": "1.2.3.4, 10.0.0.2, 10.0.0.1",
            },
        )
        assert _get_client_ip(req) == "93.184.216.34"

    def test_true_client_ip_strips_whitespace(self):
        req = _fake_request(headers={"True-Client-IP": "  93.184.216.34  "})
        assert _get_client_ip(req) == "93.184.216.34"


# ---------------------------------------------------------------------------
# 2. X-Forwarded-For at correct index — forgery resistance
# ---------------------------------------------------------------------------

class TestXForwardedFor:
    def test_xff_uses_negative_index(self, monkeypatch):
        """With TRUSTED_PROXY_HOPS=2, use XFF[-2]."""
        monkeypatch.setattr("routers.scan._TRUSTED_PROXY_HOPS", 2)
        req = _fake_request(
            headers={"X-Forwarded-For": "FORGED, 203.0.113.50, 10.0.0.2, 10.0.0.1"},
        )
        # 4 entries; index -2 → "10.0.0.2"
        assert _get_client_ip(req) == "10.0.0.2"

    def test_forged_first_entry_is_never_used(self, monkeypatch):
        """Attacker sets X-Forwarded-For: 8.8.8.8 — it must NOT become the IP."""
        monkeypatch.setattr("routers.scan._TRUSTED_PROXY_HOPS", 2)
        req = _fake_request(
            headers={"X-Forwarded-For": "8.8.8.8, 203.0.113.50, 10.0.0.1"},
        )
        ip = _get_client_ip(req)
        assert ip != "8.8.8.8", "Forged first entry must be ignored"
        assert ip == "203.0.113.50"

    def test_xff_single_entry_with_2_hops_falls_through(self, monkeypatch):
        """Only 1 entry but TRUSTED_PROXY_HOPS=2 → fall to client.host."""
        monkeypatch.setattr("routers.scan._TRUSTED_PROXY_HOPS", 2)
        req = _fake_request(
            headers={"X-Forwarded-For": "8.8.8.8"},
            client_host="172.16.0.5",
        )
        assert _get_client_ip(req) == "172.16.0.5"

    def test_xff_hops_1(self, monkeypatch):
        """TRUSTED_PROXY_HOPS=1 picks the last entry."""
        monkeypatch.setattr("routers.scan._TRUSTED_PROXY_HOPS", 1)
        req = _fake_request(
            headers={"X-Forwarded-For": "FORGED, 203.0.113.50"},
        )
        assert _get_client_ip(req) == "203.0.113.50"

    def test_xff_hops_3(self, monkeypatch):
        """TRUSTED_PROXY_HOPS=3 picks entry at index -3."""
        monkeypatch.setattr("routers.scan._TRUSTED_PROXY_HOPS", 3)
        req = _fake_request(
            headers={"X-Forwarded-For": "FORGED, 198.51.100.1, 10.0.0.3, 10.0.0.2, 10.0.0.1"},
        )
        assert _get_client_ip(req) == "10.0.0.3"


# ---------------------------------------------------------------------------
# 3. Fallback to request.client.host
# ---------------------------------------------------------------------------

class TestFallback:
    def test_no_headers_uses_client_host(self):
        req = _fake_request(headers={}, client_host="192.168.1.42")
        assert _get_client_ip(req) == "192.168.1.42"

    def test_no_headers_no_client_returns_loopback(self):
        req = _fake_request(headers={}, client_host=None)
        assert _get_client_ip(req) == "127.0.0.1"


# ---------------------------------------------------------------------------
# 4. Forged-header rate-limit bypass attempt
# ---------------------------------------------------------------------------

class TestForgedBypass:
    def test_attacker_cannot_rotate_xff_to_bypass_limit(self, monkeypatch):
        """Changing the forged first entry should not change the resolved IP."""
        monkeypatch.setattr("routers.scan._TRUSTED_PROXY_HOPS", 2)
        real_proxy = "10.0.0.1"
        real_client = "203.0.113.50"

        for forged in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            req = _fake_request(
                headers={"X-Forwarded-For": f"{forged}, {real_client}, {real_proxy}"},
            )
            assert _get_client_ip(req) == real_client


# ---------------------------------------------------------------------------
# 5. Store eviction
# ---------------------------------------------------------------------------

class TestStoreEviction:
    def test_expired_entries_are_removed(self):
        """Entries older than 1 hour are evicted."""
        old = time.time() - _RATE_LIMIT_WINDOW_SECONDS - 1
        _ip_scan_history["old_ip"] = [old, old]
        _ip_scan_history["fresh_ip"] = [time.time()]

        _evict_expired_entries()

        assert "old_ip" not in _ip_scan_history
        assert "fresh_ip" in _ip_scan_history

    def test_store_capped_at_max_keys(self):
        """Store is trimmed to _RATE_LIMIT_MAX_KEYS by evicting oldest."""
        now = time.time()
        # Fill store with MAX_KEYS + 500 entries
        for i in range(_RATE_LIMIT_MAX_KEYS + 500):
            # Stagger timestamps so older IPs have smaller timestamps
            _ip_scan_history[f"ip-{i}"] = [now - (_RATE_LIMIT_MAX_KEYS + 500 - i)]

        _evict_expired_entries()

        assert len(_ip_scan_history) <= _RATE_LIMIT_MAX_KEYS

    def test_eviction_triggered_on_check_rate_limit(self):
        """_check_rate_limit triggers eviction when store is >90% full."""
        now = time.time()
        # Fill to 91% with expired entries
        count = int(_RATE_LIMIT_MAX_KEYS * 0.91)
        old = now - _RATE_LIMIT_WINDOW_SECONDS - 10
        for i in range(count):
            _ip_scan_history[f"ip-{i}"] = [old]

        # This should trigger eviction and NOT raise 429
        _check_rate_limit("brand_new_ip")

        # All expired entries should be gone
        assert len(_ip_scan_history) < count
        assert "brand_new_ip" in _ip_scan_history
