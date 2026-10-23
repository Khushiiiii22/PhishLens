import asyncio
import time

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from loguru import logger
import os
import models
import schemas
from database import get_db
from engines.lexical import analyze_lexical
from engines.domain_intel import analyze_domain
from engines.behavior import analyze_behavior
from engines.ml_predict import predict_ml, predict_deep, ensemble_ml_predictions
from engines.threat_intel import check_threat_intel

router = APIRouter(
    prefix="/scan",
    tags=["Scan"]
)

def calculate_weighted_fusion(
    engine_scores: dict[str, float],
    failed_engines: list[str],
    incomplete_engines: list[str],
    threat_intel_has_real_data: bool
) -> tuple[float, list[str], list[str], list[str], dict[str, float]]:
    """
    Consistent, honest weighted fusion formula.
    - Base weights: lexical 0.21, domain 0.28, behavior 0.21, ml 0.30.
    - If threat intel has a real record (total_engines_checked > 0, not
      failed / never_seen / incomplete): scale base weights by 0.85 and
      give threat intel 0.15. Otherwise use the base weights.
    - Drop any engine in failed_engines or incomplete_engines and rescale
      the remaining weights to sum to 1.
    - final_risk_score = weighted sum of the engine scores.
    - fusion_method is always 'weighted'.
    """
    if threat_intel_has_real_data:
        raw_weights = {
            "lexical": 0.21 * 0.85,
            "domain": 0.28 * 0.85,
            "behavior": 0.21 * 0.85,
            "ml": 0.30 * 0.85,
            "threat_intel": 0.15,
        }
    else:
        raw_weights = {
            "lexical": 0.21,
            "domain": 0.28,
            "behavior": 0.21,
            "ml": 0.30,
        }

    excluded = set(failed_engines) | set(incomplete_engines)
    active_engines = [e for e in raw_weights if e not in excluded]

    total_weight = sum(raw_weights[e] for e in active_engines)
    if total_weight == 0.0:
        return 0.0, [], failed_engines, incomplete_engines, {}

    final_weights = {}
    final_score = 0.0
    for e in active_engines:
        eff_weight = raw_weights[e] / total_weight
        final_weights[e] = round(eff_weight, 4)
        score = engine_scores.get(e, 0.0)
        final_score += score * eff_weight

    return round(final_score, 2), active_engines, failed_engines, incomplete_engines, final_weights


@router.post("", response_model=schemas.ScanResponse)
async def create_scan(scan_request: schemas.ScanRequest, db: Session = Depends(get_db)):
    url_str = str(scan_request.url)
    total_start = time.perf_counter()
    logger.info("━━━ Scan started for: {} ━━━", url_str)

    # 1. Insert into url_scans with verdict "pending" initially
    new_scan = models.UrlScan(
        url=url_str,
        source=scan_request.source,
        verdict="pending"
    )
    db.add(new_scan)
    # Flush to get the auto-generated id without committing the transaction
    db.flush()

    # 2. Run the lexical analysis engine (instant — no network calls)
    lexical_data = analyze_lexical(url_str)

    # 3. Insert heuristic_results row
    heuristic_row = models.HeuristicResult(
        scan_id=new_scan.id,
        url_length=lexical_data["url_length"],
        dot_count=lexical_data["dot_count"],
        hyphen_count=lexical_data["hyphen_count"],
        digit_count=lexical_data["digit_count"],
        special_char_count=lexical_data["special_char_count"],
        entropy_score=lexical_data["entropy_score"],
        has_suspicious_keywords=lexical_data["has_suspicious_keywords"],
        has_punycode_or_homoglyph=lexical_data["has_punycode_or_homoglyph"],
        lexical_score=lexical_data["lexical_score"],
    )
    db.add(heuristic_row)

    # 4. Run BOTH ML models
    #    a) Classical Random Forest (uses lexical features)
    rf_data = predict_ml(lexical_data)
    #    b) Deep CNN (uses raw URL text — no hand-crafted features)
    cnn_data = predict_deep(url_str)

    # 5. Ensemble the two ML predictions into a single signal
    ml_data = ensemble_ml_predictions(rf_data, cnn_data)

    # 6. Insert BOTH ml_predictions rows (one per model)
    rf_row = models.MlPrediction(
        scan_id=new_scan.id,
        model_name="RandomForest",
        confidence=rf_data["confidence"],
        prediction=rf_data["prediction"],
        model_version=rf_data["model_version"],
    )
    cnn_row = models.MlPrediction(
        scan_id=new_scan.id,
        model_name="CharCNN",
        confidence=cnn_data["confidence"],
        prediction=cnn_data["prediction"],
        model_version=cnn_data["model_version"],
    )
    db.add(rf_row)
    db.add(cnn_row)

    # 7. Run domain intelligence + behavior + threat intel engines IN PARALLEL
    #    All are blocking I/O calls, so we offload them to threads
    #    using asyncio.to_thread and gather the results concurrently.
    #    Threat intel is hard-capped at 8 seconds — never blocks the scan.
    logger.info("[Scan] Launching Domain Intel + Behavior + Threat Intel in parallel…")
    parallel_start = time.perf_counter()

    async def _threat_intel_with_timeout(url: str) -> dict:
        """Run threat intel in a thread with an 8-second hard cap."""
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(check_threat_intel, url),
                timeout=8.0
            )
        except asyncio.TimeoutError:
            logger.warning("[Threat Intel] Hard timeout (8s) exceeded. Marking as incomplete.")
            return {
                "total_engines_flagged": 0,
                "total_engines_checked": 0,
                "threat_score": 0.0,
                "threat_intel_failed": False,
                "never_seen_before": False,
                "rate_limited_incomplete": True
            }

    domain_data, behavior_data, threat_intel_data = await asyncio.gather(
        asyncio.to_thread(analyze_domain, url_str),
        asyncio.to_thread(analyze_behavior, url_str),
        _threat_intel_with_timeout(url_str),
    )

    parallel_elapsed = time.perf_counter() - parallel_start
    logger.info("[Scan] Parallel engines finished in {:.1f}s", parallel_elapsed)

    # 8. Insert domain_intelligence_results row
    domain_row = models.DomainIntelligenceResult(
        scan_id=new_scan.id,
        domain_age_days=domain_data["domain_age_days"],
        registrar=domain_data["registrar"],
        ssl_valid=domain_data["ssl_valid"],
        ssl_issuer=domain_data["ssl_issuer"],
        dnssec_enabled=domain_data["dnssec_enabled"],
        domain_score=domain_data["domain_score"],
    )
    db.add(domain_row)

    # 9. Insert page_analysis row
    page_analysis_row = models.PageAnalysis(
        scan_id=new_scan.id,
        has_login_form=behavior_data["has_login_form"],
        has_hidden_iframe=behavior_data["has_hidden_iframe"],
        has_js_redirect=behavior_data["has_js_redirect"],
        external_form_action=behavior_data["external_form_action"],
        popup_detected=behavior_data["popup_detected"],
        behavior_score=behavior_data["behavior_score"],
        behavior_analysis_failed=behavior_data["behavior_analysis_failed"],
    )
    db.add(page_analysis_row)

    # 10. Insert threat_intelligence_results row (same atomic transaction)
    threat_intel_row = models.ThreatIntelligenceResult(
        scan_id=new_scan.id,
        total_engines_flagged=threat_intel_data["total_engines_flagged"],
        total_engines_checked=threat_intel_data["total_engines_checked"],
        threat_score=threat_intel_data["threat_score"],
        threat_intel_failed=threat_intel_data["threat_intel_failed"],
        never_seen_before=threat_intel_data["never_seen_before"],
        rate_limited_incomplete=threat_intel_data["rate_limited_incomplete"],
    )
    db.add(threat_intel_row)

    # 11. Calculate final risk score
    #
    # Fusion rule for threat_intel:
    #   - INCLUDE it in the score ONLY when it has a real record
    #     (total_engines_checked > 0 from a cached lookup or completed analysis).
    #   - If never_seen_before, rate_limited_incomplete, or threat_intel_failed,
    #     EXCLUDE it from fusion → list in engines_failed/engines_incomplete so
    #     the weighted_fallback logic redistributes correctly.
    #   - Never count it as a score of 0 when excluded.
    threat_intel_has_real_data = (
        threat_intel_data["total_engines_checked"] > 0
        and not threat_intel_data["threat_intel_failed"]
        and not threat_intel_data["never_seen_before"]
        and not threat_intel_data["rate_limited_incomplete"]
    )

    engines_failed = []
    engines_incomplete = []

    if behavior_data.get("behavior_analysis_failed", False):
        engines_failed.append("behavior")

    if threat_intel_data["threat_intel_failed"]:
        engines_failed.append("threat_intel")
    elif threat_intel_data["never_seen_before"] or threat_intel_data["rate_limited_incomplete"]:
        engines_incomplete.append("threat_intel")

    engine_scores = {
        "lexical": lexical_data.get("lexical_score", 0.0),
        "domain": domain_data.get("domain_score", 0.0),
        "behavior": behavior_data.get("behavior_score", 0.0),
        "ml": ml_data.get("ml_score", 0.0),
        "threat_intel": threat_intel_data.get("threat_score", 0.0),
    }

    final_risk_score, engines_used, engines_failed, engines_incomplete, final_weights = calculate_weighted_fusion(
        engine_scores=engine_scores,
        failed_engines=engines_failed,
        incomplete_engines=engines_incomplete,
        threat_intel_has_real_data=threat_intel_has_real_data,
    )

    fusion_method = "weighted"
    new_scan.final_risk_score = final_risk_score
    new_scan.fusion_method = fusion_method
    new_scan.verdict = "analyzed"

    # 12. Commit the ENTIRE transaction atomically
    #     (url_scans + heuristic_results + ml_predictions +
    #      domain_intelligence_results + page_analysis + threat_intelligence_results)
    db.commit()
    db.refresh(new_scan)

    total_elapsed = time.perf_counter() - total_start
    logger.info("━━━ Scan completed in {:.1f}s for: {} ━━━", total_elapsed, url_str)

    # 13. Build and return the response with all five analysis breakdowns
    return schemas.ScanResponse(
        id=new_scan.id,
        url=new_scan.url,
        source=new_scan.source.value,
        verdict=new_scan.verdict,
        final_risk_score=new_scan.final_risk_score,
        fusion_method=new_scan.fusion_method,
        final_weights=final_weights,
        engines_used=engines_used,
        engines_failed=engines_failed,
        engines_incomplete=engines_incomplete,
        lexical_analysis=schemas.LexicalAnalysisResponse(**lexical_data),
        domain_analysis=schemas.DomainAnalysisResponse(**domain_data),
        behavior_analysis=schemas.BehaviorAnalysisResponse(**behavior_data),
        ml_analysis=schemas.MLAnalysisResponse(**ml_data),
        threat_intelligence_analysis=schemas.ThreatIntelAnalysisResponse(**threat_intel_data),
    )
