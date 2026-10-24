import asyncio
import time
import pytest
from httpx import AsyncClient, ASGITransport
from main import app
from routers.scan import (
    _reset_scan_limits,
    _check_rate_limit,
    _record_scan_for_ip,
    _ip_scan_history,
    get_scan_semaphore,
    _RATE_LIMIT_MAX,
)
from database import get_db
from unittest.mock import MagicMock


@pytest.fixture(autouse=True)
def clean_limits():
    """Ensure clean limits and released semaphore before and after each test."""
    _reset_scan_limits()
    sem = get_scan_semaphore()
    while sem.locked():
        try:
            sem.release()
        except RuntimeError:
            break
    yield
    _reset_scan_limits()
    while sem.locked():
        try:
            sem.release()
        except RuntimeError:
            break


def _mock_db_session():
    mock_db = MagicMock()
    def _flush():
        for call in mock_db.add.call_args_list:
            obj = call[0][0]
            if hasattr(obj, "id") and getattr(obj, "id", None) is None:
                obj.id = 1
    mock_db.add = MagicMock()
    mock_db.flush = MagicMock(side_effect=_flush)
    mock_db.commit = MagicMock()
    mock_db.refresh = MagicMock(side_effect=lambda obj: None)
    return mock_db


class TestScanLimits:
    def test_per_ip_rate_limit_10_per_hour(self, monkeypatch):
        """A single IP can perform 10 scans per hour; the 11th scan gets HTTP 429."""
        client_ip = "198.51.100.42"

        # Record 10 scans
        for _ in range(10):
            _check_rate_limit(client_ip)
            _record_scan_for_ip(client_ip)

        # 11th check must raise HTTPException 429
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _check_rate_limit(client_ip)
        assert exc_info.value.status_code == 429
        assert "Rate limit exceeded" in exc_info.value.detail

    @pytest.mark.anyio
    async def test_per_ip_rate_limit_via_client(self, monkeypatch):
        """Test rate limit over AsyncClient with X-Forwarded-For."""
        app.dependency_overrides[get_db] = _mock_db_session

        import routers.scan as scan_mod
        monkeypatch.setattr(scan_mod, "analyze_lexical", lambda u: {
            "url_length": 10, "dot_count": 1, "hyphen_count": 0, "digit_count": 0,
            "special_char_count": 0, "entropy_score": 2.0, "has_suspicious_keywords": False,
            "has_punycode_or_homoglyph": False, "lexical_score": 0.0
        })
        monkeypatch.setattr(scan_mod, "predict_ml", lambda l: {
            "prediction": "legitimate", "confidence": 0.9, "model_version": "v1", "ml_score": 5.0
        })
        monkeypatch.setattr(scan_mod, "predict_deep", lambda u: {
            "prediction": "legitimate", "confidence": 0.9, "model_version": "v1", "ml_score": 5.0
        })
        monkeypatch.setattr(scan_mod, "analyze_domain", lambda u: {
            "domain_age_days": 100, "registrar": "test", "ssl_valid": True,
            "ssl_issuer": "test", "dnssec_enabled": False, "domain_score": 5.0
        })
        monkeypatch.setattr(scan_mod, "analyze_behavior", lambda u: {
            "has_login_form": False, "has_hidden_iframe": False, "has_js_redirect": False,
            "external_form_action": False, "popup_detected": False, "behavior_score": 0.0,
            "behavior_analysis_failed": False, "blocked_private_requests": 0
        })
        monkeypatch.setattr(scan_mod, "check_threat_intel", lambda u: {
            "total_engines_flagged": 0, "total_engines_checked": 0, "threat_score": 0.0,
            "threat_intel_failed": False, "never_seen_before": True, "rate_limited_incomplete": False
        })

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = {"X-Forwarded-For": "203.0.113.195, 10.0.0.1"}

            # 10 scans succeed
            for _ in range(10):
                resp = await client.post("/scan", json={"url": "https://example.com", "source": "email"}, headers=headers)
                assert resp.status_code == 200

            # 11th scan gets 429
            resp = await client.post("/scan", json={"url": "https://example.com", "source": "email"}, headers=headers)
            assert resp.status_code == 429
            assert "Rate limit exceeded" in resp.json()["detail"]

            # Different IP is not blocked
            other_headers = {"X-Forwarded-For": "198.51.100.99"}
            resp_other = await client.post("/scan", json={"url": "https://example.com", "source": "email"}, headers=other_headers)
            assert resp_other.status_code == 200

        app.dependency_overrides.clear()

    def test_rate_limit_expires_after_one_hour(self):
        """Scans older than 1 hour do not count towards the 10 scans limit."""
        client_ip = "198.51.100.55"
        old_time = time.time() - 3601.0  # 1 hour and 1 second ago

        # Populate 10 scans from > 1 hour ago
        _ip_scan_history[client_ip] = [old_time] * 10

        # Should not raise 429 because old timestamps expire
        _check_rate_limit(client_ip)
        assert len(_ip_scan_history[client_ip]) == 0

    @pytest.mark.anyio
    async def test_concurrency_semaphore_times_out_503(self, monkeypatch):
        """When scanner is locked for > 5 seconds, a second request gets HTTP 503 'Scanner busy, try again'."""
        app.dependency_overrides[get_db] = _mock_db_session

        import routers.scan as scan_mod
        # Set semaphore timeout to 0.3s
        monkeypatch.setattr(scan_mod, "_SEMAPHORE_TIMEOUT_SECONDS", 0.3)

        def _slow_domain(u):
            time.sleep(0.8)
            return {
                "domain_age_days": 100, "registrar": "test", "ssl_valid": True,
                "ssl_issuer": "test", "dnssec_enabled": False, "domain_score": 5.0
            }

        monkeypatch.setattr(scan_mod, "analyze_domain", _slow_domain)
        monkeypatch.setattr(scan_mod, "analyze_behavior", lambda u: {
            "has_login_form": False, "has_hidden_iframe": False, "has_js_redirect": False,
            "external_form_action": False, "popup_detected": False, "behavior_score": 0.0,
            "behavior_analysis_failed": False, "blocked_private_requests": 0
        })
        monkeypatch.setattr(scan_mod, "check_threat_intel", lambda u: {
            "total_engines_flagged": 0, "total_engines_checked": 0, "threat_score": 0.0,
            "threat_intel_failed": False, "never_seen_before": True, "rate_limited_incomplete": False
        })

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Start scan 1 in background task
            task1 = asyncio.create_task(
                client.post("/scan", json={"url": "https://example.com", "source": "email"}, headers={"X-Forwarded-For": "1.1.1.1"})
            )

            # Wait briefly to let task1 acquire semaphore
            await asyncio.sleep(0.05)

            # Scan 2 attempts while task1 is running; times out after 0.3s
            r2 = await client.post("/scan", json={"url": "https://example.com", "source": "email"}, headers={"X-Forwarded-For": "2.2.2.2"})
            assert r2.status_code == 503
            assert r2.json()["detail"] == "Scanner busy, try again"

            r1 = await task1
            assert r1.status_code == 200

        app.dependency_overrides.clear()

    @pytest.mark.anyio
    async def test_concurrency_semaphore_acquires_when_released(self, monkeypatch):
        """When scanner finishes within timeout, waiting request acquires semaphore and proceeds."""
        app.dependency_overrides[get_db] = _mock_db_session

        import routers.scan as scan_mod
        monkeypatch.setattr(scan_mod, "_SEMAPHORE_TIMEOUT_SECONDS", 2.0)

        def _short_lexical(u):
            time.sleep(0.1)
            return {
                "url_length": 10, "dot_count": 1, "hyphen_count": 0, "digit_count": 0,
                "special_char_count": 0, "entropy_score": 2.0, "has_suspicious_keywords": False,
                "has_punycode_or_homoglyph": False, "lexical_score": 0.0
            }

        monkeypatch.setattr(scan_mod, "analyze_lexical", _short_lexical)
        monkeypatch.setattr(scan_mod, "predict_ml", lambda l: {
            "prediction": "legitimate", "confidence": 0.9, "model_version": "v1", "ml_score": 5.0
        })
        monkeypatch.setattr(scan_mod, "predict_deep", lambda u: {
            "prediction": "legitimate", "confidence": 0.9, "model_version": "v1", "ml_score": 5.0
        })
        monkeypatch.setattr(scan_mod, "analyze_domain", lambda u: {
            "domain_age_days": 100, "registrar": "test", "ssl_valid": True,
            "ssl_issuer": "test", "dnssec_enabled": False, "domain_score": 5.0
        })
        monkeypatch.setattr(scan_mod, "analyze_behavior", lambda u: {
            "has_login_form": False, "has_hidden_iframe": False, "has_js_redirect": False,
            "external_form_action": False, "popup_detected": False, "behavior_score": 0.0,
            "behavior_analysis_failed": False, "blocked_private_requests": 0
        })
        monkeypatch.setattr(scan_mod, "check_threat_intel", lambda u: {
            "total_engines_flagged": 0, "total_engines_checked": 0, "threat_score": 0.0,
            "threat_intel_failed": False, "never_seen_before": True, "rate_limited_incomplete": False
        })

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            task1 = asyncio.create_task(
                client.post("/scan", json={"url": "https://example.com", "source": "email"}, headers={"X-Forwarded-For": "3.3.3.3"})
            )
            await asyncio.sleep(0.02)
            task2 = asyncio.create_task(
                client.post("/scan", json={"url": "https://example.com", "source": "email"}, headers={"X-Forwarded-For": "4.4.4.4"})
            )

            r1, r2 = await asyncio.gather(task1, task2)
            assert r1.status_code == 200
            assert r2.status_code == 200

        app.dependency_overrides.clear()
