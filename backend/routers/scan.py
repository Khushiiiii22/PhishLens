import asyncio
import time

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from loguru import logger

import models
import schemas
from database import get_db
from engines.lexical import analyze_lexical
from engines.domain_intel import analyze_domain
from engines.behavior import analyze_behavior
from engines.ml_predict import predict_ml

router = APIRouter(
    prefix="/scan",
    tags=["Scan"]
)

def calculate_final_score(engines_results: list[dict]) -> tuple[float, list[str], list[str]]:
    valid_engines = []
    failed_engines = []
    total_valid_weight = 0.0
    
    for r in engines_results:
        if r.get("failed", False):
            failed_engines.append(r["name"])
        else:
            valid_engines.append(r)
            total_valid_weight += r["weight"]
            
    if total_valid_weight == 0.0:
        return 0.0, [], failed_engines
        
    final_score = 0.0
    used_engine_names = []
    for r in valid_engines:
        # Redistribute weight proportionally
        adjusted_weight = r["weight"] / total_valid_weight
        final_score += r["score"] * adjusted_weight
        used_engine_names.append(r["name"])
        
    return final_score, used_engine_names, failed_engines


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

    # 4. Run ML prediction (instant — uses the lexical features already computed)
    ml_data = predict_ml(lexical_data)

    # 5. Insert ml_predictions row
    ml_row = models.MlPrediction(
        scan_id=new_scan.id,
        model_name=ml_data.get("model_version", "RandomForest"),
        confidence=ml_data["confidence"],
        prediction=ml_data["prediction"],
        model_version=ml_data["model_version"],
    )
    db.add(ml_row)

    # 6. Run domain intelligence + behavior engines IN PARALLEL
    #    Both are blocking I/O calls, so we offload them to threads
    #    using asyncio.to_thread and gather the results concurrently.
    logger.info("[Scan] Launching Domain Intel + Behavior in parallel…")
    parallel_start = time.perf_counter()

    domain_data, behavior_data = await asyncio.gather(
        asyncio.to_thread(analyze_domain, url_str),
        asyncio.to_thread(analyze_behavior, url_str),
    )

    parallel_elapsed = time.perf_counter() - parallel_start
    logger.info("[Scan] Parallel engines finished in {:.1f}s", parallel_elapsed)

    # 7. Insert domain_intelligence_results row
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

    # 8. Insert page_analysis row
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

    # 9. Calculate final risk score
    engines_results = [
        {"name": "lexical", "score": lexical_data.get("lexical_score", 0.0), "weight": 0.21, "failed": False},
        {"name": "domain", "score": domain_data.get("domain_score", 0.0), "weight": 0.28, "failed": False},
        {"name": "behavior", "score": behavior_data.get("behavior_score", 0.0), "weight": 0.21, "failed": behavior_data.get("behavior_analysis_failed", False)},
        {"name": "ml", "score": ml_data.get("ml_score", 0.0), "weight": 0.30, "failed": False},
    ]
    final_risk_score, engines_used, engines_failed = calculate_final_score(engines_results)
    
    new_scan.final_risk_score = final_risk_score
    new_scan.verdict = "analyzed"

    # 10. Commit the ENTIRE transaction atomically
    #     (url_scans + heuristic_results + ml_predictions +
    #      domain_intelligence_results + page_analysis)
    db.commit()
    db.refresh(new_scan)

    total_elapsed = time.perf_counter() - total_start
    logger.info("━━━ Scan completed in {:.1f}s for: {} ━━━", total_elapsed, url_str)

    # 11. Build and return the response with all four analysis breakdowns
    return schemas.ScanResponse(
        id=new_scan.id,
        url=new_scan.url,
        source=new_scan.source.value,
        verdict=new_scan.verdict,
        final_risk_score=new_scan.final_risk_score,
        engines_used=engines_used,
        engines_failed=engines_failed,
        lexical_analysis=schemas.LexicalAnalysisResponse(**lexical_data),
        domain_analysis=schemas.DomainAnalysisResponse(**domain_data),
        behavior_analysis=schemas.BehaviorAnalysisResponse(**behavior_data),
        ml_analysis=schemas.MLAnalysisResponse(**ml_data),
    )
