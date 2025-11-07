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