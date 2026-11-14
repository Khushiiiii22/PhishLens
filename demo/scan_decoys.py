"""
PhishLens — Decoy Scanner Script

Executes the full PhishLens scanning pipeline across the three harmless demo pages:
1. http://127.0.0.1:9000/login-verify.html
2. http://127.0.0.1:9000/clean.html
3. http://127.0.0.1:9000/redirect.html

Uses ALLOW_PRIVATE_TARGETS=true for local inspection.
Applies the identical weighted fusion formula as the live FastAPI endpoint.
"""

import os
import sys
import json
from pathlib import Path

# Set local private targets allowlist before importing url_guard
os.environ["ALLOW_PRIVATE_TARGETS"] = "true"

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from engines.lexical import analyze_lexical
from engines.domain_intel import analyze_domain
from engines.behavior import analyze_behavior
from engines.ml_predict import predict_ml, predict_deep, ensemble_ml_predictions
from engines.threat_intel import check_threat_intel
from routers.scan import calculate_weighted_fusion

TARGET_URLS = [
    ("http://127.0.0.1:9000/login-verify.html", "Acme Test Portal (Credential Harvester Decoy)"),
    ("http://127.0.0.1:9000/clean.html", "Acme Documentation (Clean Static Page Decoy)"),
    ("http://127.0.0.1:9000/redirect.html", "Meta-Refresh Redirection Decoy"),
]


def scan_target(url: str, description: str) -> dict:
    print(f"\n{'='*75}")
    print(f"Scanning: {url}")
    print(f"Description: {description}")
    print(f"{'='*75}")

    # 1. Lexical Analysis
    lexical = analyze_lexical(url)

    # 2. Domain Intelligence
    domain = analyze_domain(url)

    # 3. Website Behavior
    behavior = analyze_behavior(url)

    # 4. Machine Learning
    rf = predict_ml(lexical)
    cnn = predict_deep(url)
    ml = ensemble_ml_predictions(rf, cnn)

    # 5. Threat Intelligence
    threat_intel = check_threat_intel(url)

    # 6. Weighted Fusion
    threat_intel_has_real_data = (
        threat_intel.get("total_engines_checked", 0) > 0
        and not threat_intel.get("threat_intel_failed", False)
        and not threat_intel.get("never_seen_before", False)
        and not threat_intel.get("rate_limited_incomplete", False)
    )

    failed_engines = []
    incomplete_engines = []

    if behavior.get("behavior_analysis_failed", False):
        failed_engines.append("behavior")

    if threat_intel.get("threat_intel_failed", False):
        failed_engines.append("threat_intel")
    elif threat_intel.get("never_seen_before", False) or threat_intel.get("rate_limited_incomplete", False):
        incomplete_engines.append("threat_intel")

    engine_scores = {
        "lexical": lexical.get("lexical_score", 0.0),
        "domain": domain.get("domain_score", 0.0),
        "behavior": behavior.get("behavior_score", 0.0),
        "ml": ml.get("ml_score", 0.0),
        "threat_intel": threat_intel.get("threat_score", 0.0),
    }

    final_risk_score, engines_used, failed, incomplete, final_weights = calculate_weighted_fusion(
        engine_scores=engine_scores,
        failed_engines=failed_engines,
        incomplete_engines=incomplete_engines,
        threat_intel_has_real_data=threat_intel_has_real_data,
    )

    result = {
        "url": url,
        "description": description,
        "final_risk_score": final_risk_score,
        "risk_band": "HIGH RISK" if final_risk_score >= 61 else ("MEDIUM RISK" if final_risk_score >= 31 else "LOW RISK"),
        "engines_used": engines_used,
        "engines_failed": failed,
        "engines_incomplete": incomplete,
        "final_weights": final_weights,
        "breakdown": {
            "lexical": {
                "score": lexical["lexical_score"],
                "suspicious_keywords": lexical["has_suspicious_keywords"],
                "entropy": lexical["entropy_score"],
                "length": lexical["url_length"],
            },
            "domain": {
                "score": domain["domain_score"],
                "age_days": domain["domain_age_days"],
                "ssl_valid": domain["ssl_valid"],
                "dnssec": domain["dnssec_enabled"],
            },
            "behavior": {
                "score": behavior["behavior_score"],
                "has_login_form": behavior["has_login_form"],
                "external_form_action": behavior["external_form_action"],
                "has_hidden_iframe": behavior["has_hidden_iframe"],
                "has_js_redirect": behavior["has_js_redirect"],
                "blocked_private_requests": behavior["blocked_private_requests"],
            },
            "ml": {
                "score": ml["ml_score"],
                "prediction": ml["prediction"],
                "rf_score": ml.get("rf_score"),
                "cnn_score": ml.get("cnn_score"),
                "models_agreed": ml["models_agreed"],
            },
            "threat_intel": {
                "score": threat_intel["threat_score"],
                "engines_flagged": threat_intel["total_engines_flagged"],
                "engines_checked": threat_intel["total_engines_checked"],
                "never_seen_before": threat_intel["never_seen_before"],
            },
        },
    }

    print(json.dumps(result, indent=2))
    return result


def main():
    results = []
    for url, desc in TARGET_URLS:
        res = scan_target(url, desc)
        results.append(res)

    out_file = Path(__file__).resolve().parent / "scan_results.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nAll results saved to {out_file}")


if __name__ == "__main__":
    main()

