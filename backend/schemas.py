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
    has_punycode_or_homoglyph: bool
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

class BehaviorAnalysisResponse(BaseModel):
    has_login_form: bool
    has_hidden_iframe: bool
    has_js_redirect: bool
    external_form_action: bool
    popup_detected: bool
    behavior_score: float
    behavior_analysis_failed: bool
    behavior_failure_reason: Optional[str] = None
    blocked_private_requests: int = 0

    class Config:
        from_attributes = True

class MLAnalysisResponse(BaseModel):
    prediction: str
    confidence: float
    model_version: str
    ml_score: float
    models_agreed: Optional[bool] = None
    rf_prediction: Optional[str] = None
    rf_confidence: Optional[float] = None
    rf_score: Optional[float] = None
    cnn_prediction: Optional[str] = None
    cnn_confidence: Optional[float] = None
    cnn_score: Optional[float] = None

    class Config:
        from_attributes = True

class ThreatIntelAnalysisResponse(BaseModel):
    total_engines_flagged: int = 0
    total_engines_checked: int = 0
    threat_score: float = 0.0
    threat_intel_failed: bool = False
    never_seen_before: bool = False
    rate_limited_incomplete: bool = False

    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: int
    url: str
    source: str
    verdict: str
    final_risk_score: Optional[float] = None
    fusion_method: Optional[str] = None
    final_weights: dict[str, float] = {}
    engines_used: list[str] = []
    engines_failed: list[str] = []
    engines_incomplete: list[str] = []
    lexical_analysis: Optional[LexicalAnalysisResponse] = None
    domain_analysis: Optional[DomainAnalysisResponse] = None
    behavior_analysis: Optional[BehaviorAnalysisResponse] = None
    ml_analysis: Optional[MLAnalysisResponse] = None
    threat_intelligence_analysis: Optional[ThreatIntelAnalysisResponse] = None

    class Config:
        from_attributes = True
