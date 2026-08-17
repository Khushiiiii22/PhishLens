from pydantic import BaseModel, HttpUrl
from typing import Optional, Literal

class ScanRequest(BaseModel):
    url: HttpUrl
    source: Literal["email", "social_media", "message"]

class LexicalAnalysisResponse(BaseModel):
    url_length: int
    dot_count: int
    hyphen_count: int
    digit_count: int
    special_char_count: int
    entropy_score: float
    has_suspicious_keywords: bool
    lexical_score: float

    class Config:
        from_attributes = True

class DomainAnalysisResponse(BaseModel):
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    ssl_valid: bool
    ssl_issuer: Optional[str] = None
    dnssec_enabled: bool
    domain_score: float

    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: int
    url: str
    source: str
    verdict: str
    lexical_analysis: Optional[LexicalAnalysisResponse] = None
    domain_analysis: Optional[DomainAnalysisResponse] = None

    class Config:
        from_attributes = True

