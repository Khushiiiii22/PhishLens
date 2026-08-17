from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
import models
import schemas
from database import get_db
from engines.lexical import analyze_lexical
from engines.domain_intel import analyze_domain

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

    # 6. Update verdict to "analyzed"
    new_scan.verdict = "analyzed"

    # 7. Commit the ENTIRE transaction atomically
    #    (url_scans + heuristic_results + domain_intelligence_results)
    db.commit()
    db.refresh(new_scan)

    # 8. Build and return the response with both analysis breakdowns
    return schemas.ScanResponse(
        id=new_scan.id,
        url=new_scan.url,
        source=new_scan.source.value,
        verdict=new_scan.verdict,
        lexical_analysis=schemas.LexicalAnalysisResponse(**lexical_data),
        domain_analysis=schemas.DomainAnalysisResponse(**domain_data),
    )
