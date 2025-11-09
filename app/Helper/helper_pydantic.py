from pydantic import BaseModel, Field, EmailStr
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EmailContent(BaseModel):
    subject: str
    body: str
    sender: EmailStr
    recipients: List[EmailStr]
    date: datetime
    headers: Dict[str, str]

class EmailAnalysisInput(BaseModel):
    """Input schema for EmailContentAnalysisTool."""
    email_data: Dict[str, Any] = Field(..., description="Email content data including subject, body, sender, recipients, date, and headers")
    
class ThreatIndicator(BaseModel):
    type: str
    severity: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    evidence: List[str]
    
class AnalysisResult(BaseModel):
    threat_level: ThreatLevel
    confidence_score: float = Field(ge=0.0, le=1.0)
    indicators: List[ThreatIndicator]
    recommendations: List[str]
    metadata: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# Technical Validation Models (Lightweight)
class DomainValidation(BaseModel):
    """Lightweight domain validation result focusing on age"""
    domain: str
    age_days: Optional[int] = None
    registration_date: Optional[datetime] = None
    is_new_domain: bool = False  # < 30 days
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    whois_available: bool = True

class TechnicalValidationResult(BaseModel):
    """Lightweight technical validation result"""
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    domain_validation: DomainValidation
    url_count: int = 0
    has_external_links: bool = False
    processing_time_ms: int

class TechnicalValidationInput(BaseModel):
    """Input schema for Technical Validation Tool"""
    email_data: Dict[str, Any] = Field(
        ..., 
        description="Email data with sender and body for technical validation"
    )

# Threat Intelligence Models
class ThreatSource(BaseModel):
    """Individual threat intelligence source result"""
    source_name: str  # "Google Safe Browsing", "AbuseIPDB"
    is_malicious: bool
    threat_type: Optional[str] = None  # "MALWARE", "PHISHING", "SOCIAL_ENGINEERING"
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    details: Optional[str] = None

class URLThreatCheck(BaseModel):
    """Threat check result for a single URL"""
    url: str
    is_malicious: bool
    threat_sources: List[ThreatSource]
    risk_score: float = Field(ge=0.0, le=1.0)
    checked_at: datetime = Field(default_factory=datetime.utcnow)

class IPReputationCheck(BaseModel):
    """IP reputation check result"""
    ip_address: str
    is_malicious: bool
    abuse_confidence_score: int = Field(ge=0, le=100)  # AbuseIPDB score
    total_reports: int = 0
    country_code: Optional[str] = None
    usage_type: Optional[str] = None  # "Data Center", "ISP", etc.

class ThreatIntelligenceResult(BaseModel):
    """Complete threat intelligence analysis result"""
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    urls_checked: List[URLThreatCheck]
    ip_reputation: Optional[IPReputationCheck] = None
    malicious_count: int = 0
    total_checks: int = 0
    processing_time_ms: int

class ThreatIntelligenceInput(BaseModel):
    """Input schema for Threat Intelligence Tool"""
    email_data: Dict[str, Any] = Field(
        ..., 
        description="Email data with URLs and sender information for threat intelligence checking"
    )