from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
import models
import schemas
from database import get_db
from engines.lexical import analyze_lexical
from engines.domain_intel import analyze_domain
from engines.behavior import analyze_behavior

router = APIRouter(
    prefix="/scan",
    tags=["Scan"]
)

@router.post("", response_model=schemas.ScanResponse)
def create_scan(scan_request: schemas.ScanRequest, db: Session = Depends(get_db)):
    url_str = str(scan_request.url)

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
        lexical_score=lexical_data["lexical_score"],
    )
    db.add(heuristic_row)

    # 4. Run the domain intelligence engine (WHOIS + SSL + DNS, ~5-10s worst case)
    domain_data = analyze_domain(url_str)

    # 5. Insert domain_intelligence_results row
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

    # 6. Run the website behavior engine (headless Chromium, ~10-15s)
    #    This can fail gracefully (site blocks headless, DNS error, timeout).
    #    A failure should NOT block the scan — we still return lexical + domain.
    behavior_data = analyze_behavior(url_str)

    # 7. Insert page_analysis row
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

    # 8. Update verdict to "analyzed"
    new_scan.verdict = "analyzed"

    # 9. Commit the ENTIRE transaction atomically
    #    (url_scans + heuristic_results + domain_intelligence_results + page_analysis)
    db.commit()
    db.refresh(new_scan)

    # 10. Build and return the response with all three analysis breakdowns
    return schemas.ScanResponse(
        id=new_scan.id,
        url=new_scan.url,
        source=new_scan.source.value,
        verdict=new_scan.verdict,
        lexical_analysis=schemas.LexicalAnalysisResponse(**lexical_data),
        domain_analysis=schemas.DomainAnalysisResponse(**domain_data),
        behavior_analysis=schemas.BehaviorAnalysisResponse(**behavior_data),
    )
