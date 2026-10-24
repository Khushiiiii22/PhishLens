import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from main import app
import engines.threat_intel as ti

client = TestClient(app)

def test_threat_intel_monkeypatch_rate_limit(monkeypatch):
    """Monkeypatch requests.get to return 429 and verify check_threat_intel returns rate_limited_incomplete."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    monkeypatch.setattr(ti.requests, "get", lambda *args, **kwargs: mock_resp)
    monkeypatch.setattr(ti, "_wait_for_rate_limit", lambda: None)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy_key")

    res = ti.check_threat_intel("https://example.com/check")
    assert res["rate_limited_incomplete"] is True
    assert res["threat_intel_failed"] is False
    assert res["never_seen_before"] is False
    assert res["threat_score"] == 0.0

def test_scan_excludes_incomplete_threat_intel_from_fusion(monkeypatch):
    """Verify POST /scan excludes rate_limited_incomplete from fusion and lists in engines_incomplete."""
    def mock_check(url):
        return {
            "total_engines_flagged": 0,
            "total_engines_checked": 0,
            "threat_score": 0.0,
            "threat_intel_failed": False,
            "never_seen_before": False,
            "rate_limited_incomplete": True
        }
    monkeypatch.setattr("routers.scan.check_threat_intel", mock_check)

    # Mock behavior to avoid launching Playwright in unit test
    monkeypatch.setattr("routers.scan.analyze_behavior", lambda url: {
        "has_login_form": False,
        "has_hidden_iframe": False,
        "has_js_redirect": False,
        "external_form_action": False,
        "popup_detected": False,
        "behavior_score": 0.0,
        "behavior_analysis_failed": False,
        "behavior_failure_reason": None,
    })

    response = client.post("/scan", json={"url": "https://www.google.com", "source": "email"})
    assert response.status_code == 200
    data = response.json()

    # Assert engines_incomplete includes threat_intel
    assert "threat_intel" in data["engines_incomplete"]
    # Assert engines_used excludes threat_intel
    assert "threat_intel" not in data["engines_used"]
    # Assert fusion_method is always weighted
    assert data["fusion_method"] == "weighted"
    assert "threat_intel" not in data["final_weights"]
    assert data["final_weights"]["lexical"] == 0.21
    assert data["final_weights"]["domain"] == 0.28
    assert data["final_weights"]["behavior"] == 0.21
    assert data["final_weights"]["ml"] == 0.30
    assert data["threat_intelligence_analysis"]["rate_limited_incomplete"] is True

def test_weighted_fusion_with_real_threat_intel(monkeypatch):
    """Verify weighted fusion scales base weights by 0.85 and gives 15% to threat intel."""
    monkeypatch.setattr("routers.scan.check_threat_intel", lambda url: {
        "total_engines_flagged": 0,
        "total_engines_checked": 90,
        "threat_score": 0.0,
        "threat_intel_failed": False,
        "never_seen_before": False,
        "rate_limited_incomplete": False
    })
    monkeypatch.setattr("routers.scan.analyze_behavior", lambda url: {
        "has_login_form": False,
        "has_hidden_iframe": False,
        "has_js_redirect": False,
        "external_form_action": False,
        "popup_detected": False,
        "behavior_score": 0.0,
        "behavior_analysis_failed": False,
        "behavior_failure_reason": None,
    })

    response = client.post("/scan", json={"url": "https://www.google.com", "source": "email"})
    assert response.status_code == 200
    data = response.json()
    assert data["fusion_method"] == "weighted"
    assert "threat_intel" in data["engines_used"]
    assert data["final_weights"]["threat_intel"] == 0.15
    assert data["final_weights"]["lexical"] == round(0.21 * 0.85, 4)
    assert data["final_weights"]["domain"] == round(0.28 * 0.85, 4)
    assert data["final_weights"]["behavior"] == round(0.21 * 0.85, 4)
    assert data["final_weights"]["ml"] == round(0.30 * 0.85, 4)

def test_mock_rate_limit_url_is_processed_normally(monkeypatch):
    """Confirm a URL containing 'mock-rate-limit' is now processed through the standard VT path."""
    called = []
    def mock_get(url, *args, **kwargs):
        called.append(url)
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        return mock_resp

    monkeypatch.setattr(ti.requests, "get", mock_get)
    monkeypatch.setattr(ti, "_wait_for_rate_limit", lambda: None)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy_key")

    res = ti.check_threat_intel("https://mock-rate-limit.phishlens.test/account")
    # Verify requests.get was actually invoked (standard lookup path, no hook short-circuit)
    assert len(called) > 0
    # 404 returned by VT means never seen before, not rate limited
    assert res["never_seen_before"] is True
    assert res["rate_limited_incomplete"] is False
