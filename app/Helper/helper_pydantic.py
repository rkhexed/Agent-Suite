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

# Coordination Agent Models
class RecommendedAction(BaseModel):
    """Automated action recommendation from coordination agent"""
    action_type: str = Field(
        ..., 
        description="Type of action: QUARANTINE, BLOCK_SENDER, ALERT, TAG, LOG, NO_ACTION"
    )
    priority: str = Field(
        ..., 
        description="Priority level: CRITICAL, HIGH, MEDIUM, LOW"
    )
    confidence: float = Field(
        ge=0.0, 
        le=1.0,
        description="Confidence in this action recommendation"
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Action-specific parameters (e.g., quarantine folder, alert channels)"
    )
    requires_approval: bool = Field(
        default=False,
        description="Whether this action requires human approval before execution"
    )
    reasoning: str = Field(
        ...,
        description="Human-readable explanation of why this action is recommended"
    )

class AgentContribution(BaseModel):
    """Individual agent's contribution to final risk score"""
    agent_name: str = Field(..., description="Agent name: linguistic, technical_validation, threat_intelligence")
    risk_score: float = Field(ge=0.0, le=1.0, description="Agent's raw risk score")
    certainty_level: str = Field(..., description="Agent's certainty: DEFINITIVE, HIGH, MEDIUM, LOW, INCONCLUSIVE")
    analysis_reasoning: str = Field(..., description="Agent's reasoning for this assessment")
    weight: float = Field(ge=0.0, le=1.0, description="Agent's weight in final calculation (0.60, 0.20, 0.20)")
    weighted_contribution: float = Field(
        ge=0.0, 
        le=1.0,
        description="Final contribution to overall risk (risk * weight)"
    )
    key_findings: List[str] = Field(
        default_factory=list,
        description="Key findings from this agent"
    )

class ExplanationSummary(BaseModel):
    """Detailed explanation of the risk assessment"""
    summary: str = Field(..., description="Brief 1-2 sentence summary of the assessment")
    narrative: str = Field(..., description="Detailed LLM-generated explanation of the decision")
    key_findings: List[str] = Field(..., description="Bullet points of critical findings from all agents")
    risk_breakdown: Dict[str, str] = Field(
        ...,
        description="Risk level explanation for each agent (e.g., 'linguistic: HIGH (0.85) - ML model confirms phishing')"
    )
    top_indicators: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Top risk indicators across all agents, sorted by severity"
    )

class CoordinationResult(BaseModel):
    """Final coordinated result from all agents with cybersecurity analyst reasoning"""
    # Core assessment
    final_risk_score: float = Field(
        ge=0.0, 
        le=1.0,
        description="Final aggregated risk score (0.0-1.0)"
    )
    risk_level: str = Field(
        ...,
        description="Risk category: CRITICAL (≥0.90), HIGH (0.70-0.89), MEDIUM (0.40-0.69), LOW (<0.40)"
    )
    
    # New confidence structure (cybersecurity analyst approach)
    aggregated_certainty: str = Field(
        ...,
        description="Aggregated certainty level: DEFINITIVE, HIGH, MEDIUM, LOW, INCONCLUSIVE"
    )
    detailed_reasoning: str = Field(
        ...,
        description="Comprehensive reasoning explaining the final assessment based on all agent inputs"
    )
    
    uncertainty: float = Field(
        ge=0.0, 
        le=1.0,
        description="Uncertainty in the assessment based on agent disagreement and certainty levels"
    )
    
    # Agent contributions
    agent_contributions: List[AgentContribution] = Field(
        ...,
        description="Detailed breakdown of each agent's contribution"
    )
    
    # Explainability
    explanation: ExplanationSummary = Field(
        ...,
        description="Human-readable explanation of the decision"
    )
    
    # Actions
    recommended_actions: List[RecommendedAction] = Field(
        ...,
        description="Automated actions recommended based on risk level and certainty"
    )
    
    user_recommendations: List[str] = Field(
        default_factory=list,
        description="User-facing recommendations (what the user should do)"
    )
    
    # Metadata
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Analysis metadata (timestamp, processing time, models used, etc.)"
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    processing_time: float = Field(
        default=0.0,
        description="Time taken to process the coordination (in seconds)"
    )

class CoordinationInput(BaseModel):
    """Input schema for Coordination Agent (receives results from n8n)"""
    email_data: Dict[str, Any] = Field(
        ...,
        description="Original email data for context"
    )
    linguistic_result: Dict[str, Any] = Field(
        ...,
        description="Complete result from Linguistic Agent"
    )
    technical_result: Dict[str, Any] = Field(
        ...,
        description="Complete result from Technical Validation Agent"
    )
    threat_intel_result: Dict[str, Any] = Field(
        ...,
        description="Complete result from Threat Intelligence Agent"
    )