"""
Technical Validation Agent - Lightweight domain age validation specialist
"""
from typing import Dict, Any, List, Optional
from crewai import Agent, Task, Crew
from .basic_agent import BaseCybersecurityCrew, AgentRequest, AgentResponse
from datetime import datetime
import logging
import json

from app.Tools.technical_validation import TechnicalValidationTool
from app.LLM.llm import get_groq_llama_70b

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TechnicalValidationCrew(BaseCybersecurityCrew):
    """
    CrewAI crew for lightweight technical validation of emails.
    Focuses on domain age validation via WHOIS lookups.
    """
    
    def __init__(self):
        super().__init__("Technical Validation Crew", "1.0.0")
        self.technical_tool = TechnicalValidationTool()
    
    def create_agents(self) -> List[Agent]:
        """Create specialized agent for domain validation"""
        
        domain_validator = Agent(
            role="Email Domain Validation Specialist",
            goal="Validate sender domain authenticity and age to detect phishing attempts",
            backstory="""You are an expert in domain validation and WHOIS analysis.
            Your primary focus is checking if sender domains are suspiciously new 
            (registered less than 30 days ago), which is a strong indicator of 
            phishing attempts. You use WHOIS database lookups to determine domain 
            registration dates and calculate risk scores based on domain age.
            
            You understand that legitimate businesses use established domains, while 
            phishers frequently register new domains for their campaigns. You focus 
            on domain age as the primary technical signal for email authenticity.""",
            tools=[self.technical_tool],
            llm=get_groq_llama_70b(),
            verbose=True,
            allow_delegation=False
        )
        
        return [domain_validator]
    
    def create_tasks(self) -> List[Task]:
        """Create task for technical validation"""
        
        validation_task = Task(
            description="""Perform technical validation focusing on domain age analysis.
            Use the Technical Email Validation Tool to:
            
            1. Check sender domain age via WHOIS lookup
            2. Identify if domain is suspiciously new (< 30 days old)
            3. Calculate risk score based on domain age
            4. Count URLs and detect external links in email body
            
            Email Data: {email_data}
            Metadata: {metadata}
            
            Focus on domain age as the primary technical indicator.""",
            agent=self.agents[0],
            expected_output="""A structured validation report containing:
            - Domain age in days
            - Domain registration date
            - Is new domain flag (< 30 days)
            - Risk score based on domain age
            - URL count and external link detection
            - Confidence metrics"""
        )
        
        return [validation_task]
    
    async def _execute_crew(self, request: AgentRequest) -> Any:
        """Execute the technical validation crew"""
        return self.crew.kickoff(inputs={
            "email_data": request.email_data,
            "metadata": request.metadata
        })
    
    def _parse_crew_result(self, result: Any, request: AgentRequest, processing_time: float) -> AgentResponse:
        """Parse CrewAI result into standardized response"""
        
        findings = []
        recommendations = []
        confidence_score = 0.0
        
        try:
            validation_output = None
            
            # Extract JSON from CrewAI result
            if hasattr(result, 'raw') and result.raw:
                raw_str = str(result.raw)
                json_start = raw_str.find('{')
                json_end = raw_str.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    try:
                        potential_json = raw_str[json_start:json_end]
                        validation_output = json.loads(potential_json)
                        logger.info(f"Extracted validation output from raw (risk_score: {validation_output.get('risk_score', 'N/A')})")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON from raw output: {e}")
            
            # Process validation results
            if validation_output and isinstance(validation_output, dict):
                risk_score = validation_output.get('risk_score', 0.5)
                confidence_score = validation_output.get('confidence', 0.5)
                
                # Domain validation findings
                domain_val = validation_output.get('domain_validation', {})
                if domain_val:
                    is_new = domain_val.get('is_new_domain', False)
                    age_days = domain_val.get('age_in_days', 'Unknown')
                    domain_risk = domain_val.get('risk_score', 0.5)
                    
                    severity = "high" if domain_risk > 0.6 else "medium" if domain_risk > 0.3 else "low"
                    
                    findings.append({
                        "type": "domain_age",
                        "severity": severity,
                        "confidence": confidence_score,
                        "description": f"Domain age: {age_days} days {'(NEW DOMAIN - SUSPICIOUS)' if is_new else '(established)'}",
                        "evidence": [f"Registration date: {domain_val.get('registration_date', 'Unknown')}"]
                    })
                    
                    if is_new:
                        recommendations.append("⚠️ Sender domain is very new (< 30 days) - high phishing risk")
                
                # URL metrics findings
                url_count = validation_output.get('url_count', 0)
                has_external = validation_output.get('has_external_links', False)
                
                if url_count > 0:
                    findings.append({
                        "type": "url_analysis",
                        "severity": "medium" if has_external else "low",
                        "confidence": 0.8,
                        "description": f"Found {url_count} URL(s) in email",
                        "evidence": [f"Contains external links: {has_external}"]
                    })
                    
                    if has_external:
                        recommendations.append("Email contains external links - verify before clicking")
                
                logger.info(f"✅ Successfully parsed validation with {len(findings)} findings")
                
            else:
                # Fallback
                logger.warning("Could not extract validation output, using fallback")
                findings = [{
                    "type": "info",
                    "severity": "info",
                    "confidence": 0.5,
                    "description": "Validation completed - see output for details",
                    "evidence": [str(result)[:200]]
                }]
                confidence_score = 0.5
                recommendations = ["Review full validation output"]
            
        except Exception as e:
            logger.error(f"Error parsing validation results: {str(e)}", exc_info=True)
            findings = [{
                "type": "error",
                "severity": "high",
                "confidence": 1.0,
                "description": f"Failed to process validation output: {str(e)}"
            }]
            recommendations = ["Manual review required due to processing error"]
            confidence_score = 0.0
        
        return AgentResponse(
            agent_name=self.crew_name,
            request_id=request.request_id,
            status="success",
            confidence_score=confidence_score,
            findings=findings,
            recommendations=recommendations,
            processing_time=processing_time,
            timestamp=datetime.now()
        )
    
    def get_agent_info(self) -> Dict[str, Any]:
        """Return information about technical validation capabilities"""
        return {
            "crew_name": self.crew_name,
            "version": self.version,
            "capabilities": [
                "Domain age validation",
                "WHOIS lookup",
                "New domain detection (< 30 days)",
                "URL extraction and counting",
                "External link detection"
            ],
            "analysis_types": [
                "Domain authenticity",
                "Phishing infrastructure detection",
                "Domain age risk assessment"
            ],
            "output_format": "Structured validation assessment with confidence scores"
        }

