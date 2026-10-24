from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from database import Base

class SourceEnum(str, enum.Enum):
    email = "email"
    social_media = "social_media"
    message = "message"

class UrlScan(Base):
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, nullable=False, index=True)
    source = Column(Enum(SourceEnum, name="source_enum"), nullable=False)
    submitted_at = Column(DateTime(timezone=True), server_default=func.now())
    final_risk_score = Column(Float, nullable=True)
    verdict = Column(String, nullable=True)
    fusion_method = Column(String, nullable=True)

    # Relationships
    heuristic_results = relationship("HeuristicResult", back_populates="scan", cascade="all, delete-orphan", uselist=False)
    domain_intelligence_results = relationship("DomainIntelligenceResult", back_populates="scan", cascade="all, delete-orphan", uselist=False)
    page_analysis = relationship("PageAnalysis", back_populates="scan", cascade="all, delete-orphan", uselist=False)
    ml_predictions = relationship("MlPrediction", back_populates="scan", cascade="all, delete-orphan")
    threat_intelligence_results = relationship("ThreatIntelligenceResult", back_populates="scan", cascade="all, delete-orphan", uselist=False)
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class HeuristicResult(Base):
    __tablename__ = "heuristic_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    url_length = Column(Integer)
    dot_count = Column(Integer)
    hyphen_count = Column(Integer)
    digit_count = Column(Integer)
    special_char_count = Column(Integer)
    entropy_score = Column(Float)
    has_suspicious_keywords = Column(Boolean, default=False)
    has_punycode_or_homoglyph = Column(Boolean, default=False)
    lexical_score = Column(Float)

    scan = relationship("UrlScan", back_populates="heuristic_results")


class DomainIntelligenceResult(Base):
    __tablename__ = "domain_intelligence_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    domain_age_days = Column(Integer, nullable=True)
    registrar = Column(String, nullable=True)
    ssl_valid = Column(Boolean, nullable=True)
    ssl_issuer = Column(String, nullable=True)
    dnssec_enabled = Column(Boolean, nullable=True)
    domain_score = Column(Float, nullable=True)

    scan = relationship("UrlScan", back_populates="domain_intelligence_results")


class PageAnalysis(Base):
    __tablename__ = "page_analysis"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    has_login_form = Column(Boolean, default=False)
    has_hidden_iframe = Column(Boolean, default=False)
    has_js_redirect = Column(Boolean, default=False)
    external_form_action = Column(Boolean, default=False)
    popup_detected = Column(Boolean, default=False)
    behavior_score = Column(Float, nullable=True)
    behavior_analysis_failed = Column(Boolean, default=False)

    scan = relationship("UrlScan", back_populates="page_analysis")


class MlPrediction(Base):
    __tablename__ = "ml_predictions"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False)
    model_name = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    prediction = Column(String, nullable=False)
    model_version = Column(String, nullable=True)

    scan = relationship("UrlScan", back_populates="ml_predictions")


class ThreatIntelligenceResult(Base):
    __tablename__ = "threat_intelligence_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    total_engines_flagged = Column(Integer, default=0)
    total_engines_checked = Column(Integer, default=0)
    threat_score = Column(Float, default=0.0)
    threat_intel_failed = Column(Boolean, default=False)
    never_seen_before = Column(Boolean, default=False)
    rate_limited_incomplete = Column(Boolean, default=False)

    scan = relationship("UrlScan", back_populates="threat_intelligence_results")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    summary = Column(Text, nullable=False)

    scan = relationship("UrlScan", back_populates="reports")
