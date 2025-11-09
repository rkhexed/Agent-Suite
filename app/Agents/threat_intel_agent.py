"""
Threat Intelligence Agent - Threat intelligence analysis specialist
"""
from typing import Dict, Any, List, Optional
from crewai import Agent, Task, Crew
from .basic_agent import BaseCybersecurityCrew, AgentRequest, AgentResponse
from datetime import datetime
import logging
import json

from app.Tools.threat_intel_tool import ThreatIntelligenceTool
from app.LLM.llm import get_groq_llama_70b

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelligenceCrew(BaseCybersecurityCrew):
    """
    CrewAI crew for threat intelligence analysis of emails.
    Queries external threat databases (Google Safe Browsing, AbuseIPDB)
    to detect known malicious URLs and suspicious IPs.
    """
    
    def __init__(self):
        super().__init__("Threat Intelligence Crew", "1.0.0")
        self.threat_tool = ThreatIntelligenceTool()
    
    def create_agents(self) -> List[Agent]:
        """Create specialized agent for threat intelligence analysis"""
        
        threat_analyst = Agent(
            role="Threat Intelligence Analyst",
            goal="Check URLs and IPs against global threat intelligence databases to detect known threats",
            backstory="""You are an expert in threat intelligence and cyber threat hunting.
            Your specialty is querying external threat intelligence feeds like Google Safe Browsing
            and AbuseIPDB to identify known malicious URLs, phishing sites, malware distribution
            points, and suspicious IP addresses.
            
            You understand that threat intelligence provides critical context about known threats
            in the wild. When you find matches in threat databases, you know these are confirmed
            threats that should be taken seriously. You focus on actionable intelligence from
            reliable sources and provide clear recommendations based on threat feed data.
            
            You work alongside other security agents: the Linguistic Agent detects social engineering
            through content analysis, and the Technical Validation Agent checks infrastructure.
            Your unique contribution is cross-referencing against global threat intelligence to
            catch known bad actors and campaigns.""",
            tools=[self.threat_tool],
            llm=get_groq_llama_70b(),
            verbose=True,
            allow_delegation=False
        )
        
        return [threat_analyst]
    
    def create_tasks(self) -> List[Task]:
        """Create task for threat intelligence analysis"""
        
        threat_analysis_task = Task(
            description="""Perform threat intelligence analysis using external threat databases.
            Use the Threat Intelligence Tool to:
            
            1. Extract and check all URLs against Google Safe Browsing
            2. Check sender IP reputation via AbuseIPDB
            3. Identify known malicious sites, phishing campaigns, malware distributors
            4. Calculate threat scores based on database matches
            5. Provide actionable intelligence on detected threats
            
            Email Data: {email_data}
            Metadata: {metadata}
            
            Focus on confirmed threats from reliable intelligence sources.
            Cross-reference multiple databases for higher confidence.""",
            agent=self.agents[0],
            expected_output="""A structured threat intelligence report containing:
            - Threat database check results (Google Safe Browsing, AbuseIPDB)
            - Known malicious URLs with threat classifications
            - IP reputation scores and abuse history
            - Confirmed threat indicators with evidence
            - Risk assessment based on threat intelligence
            - Actionable recommendations for detected threats"""
        )
        
        return [threat_analysis_task]
    
    async def _execute_crew(self, request: AgentRequest) -> Any:
        """Execute the threat intelligence crew"""
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
            threat_output = None
            
            # Extract JSON from CrewAI result
            if hasattr(result, 'raw') and result.raw:
                raw_str = str(result.raw)
                json_start = raw_str.find('{')
                json_end = raw_str.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    try:
                        potential_json = raw_str[json_start:json_end]
                        threat_output = json.loads(potential_json)
                        logger.info(f"Extracted threat intelligence output (risk_score: {threat_output.get('risk_score', 'N/A')})")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON from raw output: {e}")
            
            # Process threat intelligence results
            if threat_output and isinstance(threat_output, dict):
                risk_score = threat_output.get('risk_score', 0.0)
                confidence_score = threat_output.get('confidence', 0.5)
                
                # URL threat findings
                urls_checked = threat_output.get('urls_checked', [])
                for url_check in urls_checked:
                    if url_check.get('is_malicious'):
                        threat_sources = url_check.get('threat_sources', [])
                        source_names = [s.get('source', 'Unknown') for s in threat_sources if s.get('malicious')]
                        threat_types = [s.get('threat_type', 'Unknown') for s in threat_sources if s.get('threat_type')]
                        
                        findings.append({
                            "type": "malicious_url",
                            "severity": "high",
                            "confidence": 0.95,
                            "description": f"URL flagged as malicious: {url_check.get('url')}",
                            "evidence": [
                                f"Threat databases: {', '.join(source_names)}",
                                f"Threat types: {', '.join(threat_types)}" if threat_types else "Classification: Malicious"
                            ]
                        })
                        
                        recommendations.append(f"⚠️ Block malicious URL: {url_check.get('url')}")
                
                # IP reputation findings
                ip_rep = threat_output.get('ip_reputation')
                if ip_rep and ip_rep.get('is_malicious'):
                    abuse_score = ip_rep.get('abuse_score', 0)
                    total_reports = ip_rep.get('total_reports', 0)
                    
                    findings.append({
                        "type": "malicious_ip",
                        "severity": "high" if abuse_score > 75 else "medium",
                        "confidence": 0.85,
                        "description": f"Sender IP has abuse history: {ip_rep.get('ip_address')}",
                        "evidence": [
                            f"Abuse confidence: {abuse_score}%",
                            f"Total reports: {total_reports}",
                            f"Country: {ip_rep.get('country', 'Unknown')}"
                        ]
                    })
                    
                    recommendations.append(f"🚨 Sender IP flagged by AbuseIPDB (abuse score: {abuse_score}%)")
                
                # Summary findings
                malicious_count = threat_output.get('malicious_count', 0)
                total_checks = threat_output.get('total_checks', 0)
                
                if malicious_count == 0 and total_checks > 0:
                    findings.append({
                        "type": "clean_scan",
                        "severity": "info",
                        "confidence": 0.80,
                        "description": f"No threats detected in {total_checks} threat intelligence checks",
                        "evidence": ["Google Safe Browsing: Clean", "AbuseIPDB: No abuse history"]
                    })
                    recommendations.append("✅ No known threats detected in threat intelligence databases")
                
                logger.info(f"✅ Successfully parsed threat intelligence with {len(findings)} findings")
                
            else:
                # Fallback
                logger.warning("Could not extract threat intelligence output, using fallback")
                findings = [{
                    "type": "info",
                    "severity": "info",
                    "confidence": 0.5,
                    "description": "Threat intelligence check completed - see output for details",
                    "evidence": [str(result)[:200]]
                }]
                confidence_score = 0.5
                recommendations = ["Review full threat intelligence output"]
            
        except Exception as e:
            logger.error(f"Error parsing threat intelligence results: {str(e)}", exc_info=True)
            findings = [{
                "type": "error",
                "severity": "high",
                "confidence": 1.0,
                "description": f"Failed to process threat intelligence output: {str(e)}"
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
        """Return information about threat intelligence capabilities"""
        return {
            "crew_name": self.crew_name,
            "version": self.version,
            "capabilities": [
                "URL threat intelligence (Google Safe Browsing)",
                "IP reputation checking (AbuseIPDB)",
                "Known malware/phishing detection",
                "Threat database cross-referencing",
                "Abuse history analysis"
            ],
            "threat_sources": [
                "Google Safe Browsing (10,000 req/day)",
                "AbuseIPDB (1,000 req/day)"
            ],
            "analysis_types": [
                "Malicious URL detection",
                "Phishing site identification",
                "Malware distribution detection",
                "IP reputation analysis",
                "Abuse history correlation"
            ],
            "output_format": "Structured threat intelligence assessment with database evidence"
        }
