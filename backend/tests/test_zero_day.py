"""Tests for the never-seen-before / zero-day path in threat intelligence.

Verifies that when VirusTotal returns 404 for a URL (meaning it has never
been scanned before), check_threat_intel correctly reports:
  - never_seen_before = True
  - threat_intel_failed = False
  - rate_limited_incomplete = False
  - threat_score = 0.0
"""

import pytest
from unittest.mock import MagicMock
import engines.threat_intel as ti


@pytest.fixture(autouse=True)
def _set_api_key(monkeypatch):
    """Ensure a dummy API key is set so check_threat_intel runs its normal path."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy_key_for_test")
    monkeypatch.setattr(ti, "_wait_for_rate_limit", lambda: None)


class TestNeverSeenBefore:
    def test_404_lookup_yields_never_seen(self, monkeypatch):
        """VT lookup returns 404 → never_seen_before=True, no failure."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        monkeypatch.setattr(ti.requests, "get", lambda *a, **kw: mock_resp)

        # Also stub POST (submission) to return 200 so the poll loop fires
        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.json.return_value = {
            "data": {"id": "fake-analysis-id"}
        }
        monkeypatch.setattr(ti.requests, "post", lambda *a, **kw: mock_post)

        result = ti.check_threat_intel("https://never-before-seen-domain.test/login")

        assert result["never_seen_before"] is True
        assert result["threat_intel_failed"] is False
        assert result["rate_limited_incomplete"] is False
        assert result["threat_score"] == 0.0
        assert result["total_engines_checked"] == 0
        assert result["total_engines_flagged"] == 0

    def test_never_seen_is_excluded_from_fusion(self):
        """The scan router must exclude never_seen results from weighted fusion."""
        from routers.scan import calculate_weighted_fusion

        engine_scores = {
            "lexical": 20.0,
            "domain": 30.0,
            "behavior": 10.0,
            "ml": 15.0,
            "threat_intel": 0.0,  # never seen → 0 score
        }

        # threat_intel goes into incomplete because never_seen_before
        final_score, used, failed, incomplete, weights = calculate_weighted_fusion(
            engine_scores=engine_scores,
            failed_engines=[],
            incomplete_engines=["threat_intel"],
            threat_intel_has_real_data=False,
        )

        # threat_intel must NOT appear in used or weights
        assert "threat_intel" not in used
        assert "threat_intel" not in weights
        assert "threat_intel" in incomplete

        # Weights must sum to ~1.0 without threat_intel
        assert abs(sum(weights.values()) - 1.0) < 0.01

    def test_cached_result_with_engines_is_not_never_seen(self, monkeypatch):
        """When VT returns a cached report with engines_checked > 0, never_seen is False."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 70,
                        "malicious": 2,
                        "suspicious": 1,
                        "undetected": 17,
                        "timeout": 0,
                    }
                }
            }
        }
        monkeypatch.setattr(ti.requests, "get", lambda *a, **kw: mock_resp)

        result = ti.check_threat_intel("https://well-known-site.com")

        assert result["never_seen_before"] is False
        assert result["total_engines_checked"] == 90
        assert result["total_engines_flagged"] == 3  # malicious + suspicious
        assert result["threat_score"] > 0
