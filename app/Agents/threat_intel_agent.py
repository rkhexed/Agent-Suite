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
from app.LLM.llm import get_mistral_small

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
            role="Threat Intelligence Correlation Analyst",
            goal="Correlate email indicators against authoritative threat intelligence databases to identify known malicious infrastructure",
            backstory="""You are a cybersecurity analyst specializing in threat intelligence correlation.
            You analyze emails like an experienced threat hunter would:
            
            1. KNOWN THREAT CORRELATION: You check indicators against authoritative sources
               - Google Safe Browsing: Definitive malware/phishing detections (100% reliable when matched)
               - AbuseIPDB: Community-reported IP abuse (reliability scales with report count)
               - You understand that a match in these databases means confirmed malicious activity
            
            2. AUTHORITATIVE SOURCE CITATIONS: You document exactly which databases flagged what
               - Google Safe Browsing match = DEFINITIVE threat (no false positives)
               - AbuseIPDB abuse confidence 100% = DEFINITIVE malicious IP
               - AbuseIPDB abuse confidence 50-99% = HIGH confidence malicious IP
               - AbuseIPDB abuse confidence <50% = MEDIUM confidence suspicious IP
            
            3. CERTAINTY BASED ON SOURCE QUALITY: Your confidence comes from database authority
               - DEFINITIVE: Google Safe Browsing malware/phishing match, AbuseIPDB 100% confidence
               - HIGH: AbuseIPDB 50-99% confidence with many reports
               - MEDIUM: AbuseIPDB <50% confidence or few reports
               - LOW: Database available but no matches found
               - INCONCLUSIVE: Database unavailable or API error
            
            Your assessments include:
            - CERTAINTY LEVEL based on database match quality and source authority
            - ANALYSIS REASONING explaining which databases flagged which indicators and why that matters
            - EVIDENCE QUALITY citing specific threat categories (malware, phishing, spam, botnet) and confidence scores
            - LIMITATIONS noting you cannot analyze content, domain age, or social engineering - only known threat matches
            
            CRITICAL: Call the Threat Intelligence Tool ONLY ONCE. The tool's output is authoritative and complete.
            Do NOT re-run the tool or second-guess its results. Database matches are definitive - trust them and provide your analysis immediately.
            
            CRITICAL: If Google Safe Browsing flags a URL as malware/phishing, this is a DEFINITIVE threat.
            If AbuseIPDB shows 100% abuse confidence, this is a DEFINITIVE malicious IP.
            These are not "maybe suspicious" - they are confirmed threats in global databases.
            
            You DO NOT analyze email content or domain infrastructure - that's for other agents.
            You focus purely on known threat correlation.""",
            tools=[self.threat_tool],
            llm=get_mistral_small(),
            verbose=True,
            allow_delegation=False,
            max_iter=3  # Limit iterations to prevent redundant tool calls
        )
        
        return [threat_analyst]
    
    def create_tasks(self) -> List[Task]:
        """Create task for threat intelligence analysis"""
        
        threat_analysis_task = Task(
            description="""Perform threat intelligence correlation analysis with cybersecurity analyst expertise.
            Use the Threat Intelligence Tool to check indicators, then provide detailed threat hunter reasoning:
            
            ANALYSIS APPROACH (think like a threat hunter):
            1. **Google Safe Browsing Check**: Query URLs against Google's threat database
               - MALWARE match = DEFINITIVE threat (confirmed malware distribution)
               - SOCIAL_ENGINEERING match = DEFINITIVE threat (confirmed phishing site)
               - UNWANTED_SOFTWARE match = HIGH threat (potentially unwanted programs)
               - No match = Low risk (not in Google's known threat database)
               - Note: Google Safe Browsing has extremely low false positive rate
            
            2. **AbuseIPDB Reputation Check**: Query sender IP against abuse database
               - Abuse confidence 100% = DEFINITIVE malicious (many reports, high certainty)
               - Abuse confidence 75-99% = HIGH confidence malicious
               - Abuse confidence 50-74% = MEDIUM confidence suspicious
               - Abuse confidence 25-49% = LOW confidence (few reports)
               - Abuse confidence 0-24% or 0 reports = No significant abuse history
               - Note: Confidence score based on report volume and recency
            
            3. **Threat Correlation Reasoning**: Explain significance of database matches
               - WHY Google match is critical (authoritative source, confirmed threat)
               - HOW AbuseIPDB confidence scores work (community validation)
               - WHAT threat categories mean (malware vs phishing vs spam vs botnet)
            
            Email Data: {email_data}
            Metadata: {metadata}
            
            REQUIRED OUTPUT FORMAT (provide ALL fields):
            - risk_score: Float 0.0-1.0 (1.0 for Google malware match OR AbuseIPDB 100%, scale down from there)
            - certainty_level: DEFINITIVE (Google match OR AbuseIPDB 100%) / HIGH (AbuseIPDB 75-99%) / MEDIUM (AbuseIPDB 50-74%) / LOW (AbuseIPDB <50% or no matches) / INCONCLUSIVE (API error)
            - analysis_reasoning: "Google Safe Browsing: [RESULT]. AbuseIPDB: [SCORE]% abuse confidence with [COUNT] reports. [Explain threat significance]"
            - evidence_quality: "Google Safe Browsing API (authoritative, 10K req/day limit). AbuseIPDB API (community-driven, confidence based on report volume). Threat categories: [LIST]."
            - limitations: "Cannot assess: email content, domain age, social engineering tactics, attachment safety. Only checks known threat databases."
            - findings: List of specific database matches (URL flags, IP abuse reports, threat categories)
            - recommendations: Actionable advice based on threat intelligence (QUARANTINE for DEFINITIVE threats, BLOCK for HIGH threats)""",
            agent=self.agents[0],
            expected_output="""JSON object with complete threat intelligence correlation assessment:
            {
                "risk_score": 0.X,
                "certainty_level": "DEFINITIVE/HIGH/MEDIUM/LOW/INCONCLUSIVE",
                "analysis_reasoning": "Detailed explanation of database matches and threat significance",
                "evidence_quality": "Database sources, reliability assessment, and threat categories",
                "limitations": "Clear statement of what this agent cannot assess",
                "findings": [list of specific threat database matches],
                "recommendations": [actionable security recommendations based on threat severity]
            }"""
        )
        
        return [threat_analysis_task]
    
    async def _execute_crew(self, request: AgentRequest) -> Any:
        """Execute the threat intelligence crew"""
        return self.crew.kickoff(inputs={
            "email_data": request.email_data,
            "metadata": request.metadata
        })
    
    def _parse_crew_result(self, result: Any, request: AgentRequest, processing_time: float) -> AgentResponse:
        """Parse CrewAI result into standardized response with threat hunter reasoning"""
        
        findings = []
        recommendations = []
        risk_score = 0.0
        certainty_level = "INCONCLUSIVE"
        analysis_reasoning = "Threat intelligence analysis failed to produce structured output"
        evidence_quality = "No threat database queries performed"
        limitations = "Unable to perform threat correlation"
        
        try:
            import json
            threat_output = None
            
            # Strategy 1: Extract JSON from agent output
            if hasattr(result, 'raw') and result.raw:
                raw_str = str(result.raw)
                
                # Remove markdown code fences if present
                if '```json' in raw_str:
                    json_start = raw_str.find('```json') + 7
                    json_end = raw_str.find('```', json_start)
                    if json_end > json_start:
                        raw_str = raw_str[json_start:json_end].strip()
                elif '```' in raw_str:
                    json_start = raw_str.find('```') + 3
                    json_end = raw_str.find('```', json_start)
                    if json_end > json_start:
                        raw_str = raw_str[json_start:json_end].strip()
                
                json_start = raw_str.find('{')
                json_end = raw_str.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    try:
                        potential_json = raw_str[json_start:json_end]
                        threat_output = json.loads(potential_json)
                        logger.info(f"✅ Extracted JSON output from agent")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON: {e}")
            
            # Strategy 2: Try tasks_output
            if not threat_output and hasattr(result, 'tasks_output') and result.tasks_output:
                for task_output in result.tasks_output:
                    if hasattr(task_output, 'raw') and task_output.raw:
                        try:
                            raw_str = str(task_output.raw)
                            # Remove markdown fences
                            if '```json' in raw_str:
                                json_start = raw_str.find('```json') + 7
                                json_end = raw_str.find('```', json_start)
                                raw_str = raw_str[json_start:json_end].strip() if json_end > json_start else raw_str
                            
                            json_start = raw_str.find('{')
                            json_end = raw_str.rfind('}') + 1
                            if json_start >= 0 and json_end > json_start:
                                threat_output = json.loads(raw_str[json_start:json_end])
                                logger.info(f"✅ Extracted from tasks_output")
                                break
                        except Exception as e:
                            continue
            
            # If we got structured output, extract all fields
            if threat_output and isinstance(threat_output, dict):
                # Extract new confidence structure
                certainty_level = threat_output.get("certainty_level", "MEDIUM")
                analysis_reasoning = threat_output.get("analysis_reasoning", "No reasoning provided")
                evidence_quality = threat_output.get("evidence_quality", "Evidence quality not documented")
                limitations = threat_output.get("limitations", "Limitations not specified")
                
                # Extract risk score using robust extraction
                risk_score = self._extract_risk_score(threat_output)
                
                # Extract findings
                if "findings" in threat_output:
                    raw_findings = threat_output["findings"]
                    # Convert to list of dicts if they're strings
                    if isinstance(raw_findings, list):
                        findings = []
                        for f in raw_findings:
                            if isinstance(f, str):
                                findings.append({"description": f})
                            elif isinstance(f, dict):
                                findings.append(f)
                            else:
                                findings.append({"description": str(f)})
                    else:
                        findings = [{"description": str(raw_findings)}]
                else:
                    # Fallback to old format - extract from tool output
                    urls_checked = self._extract_url_findings(threat_output)
                    for url_check in urls_checked:
                        if url_check.get('is_malicious'):
                            threat_sources = url_check.get('threat_sources', [])
                            source_names = [s.get('source', 'Unknown') for s in threat_sources if s.get('malicious')]
                            threat_types = [s.get('threat_type', 'Unknown') for s in threat_sources if s.get('threat_type')]
                            
                            findings.append({
                                "type": "malicious_url",
                                "description": f"URL flagged as malicious by {', '.join(source_names)}: {url_check.get('url')}",
                                "evidence": f"Threat types: {', '.join(threat_types)}" if threat_types else "Classification: Malicious"
                            })
                    
                    ip_rep = self._extract_ip_reputation(threat_output)
                    if ip_rep and ip_rep.get('is_malicious'):
                        abuse_score = ip_rep.get('abuse_score', 0)
                        findings.append({
                            "type": "malicious_ip",
                            "description": f"IP flagged by AbuseIPDB: {ip_rep.get('ip_address')} ({abuse_score}% abuse confidence)",
                            "evidence": f"{ip_rep.get('total_reports', 0)} reports"
                        })
                
                # Extract recommendations
                if "recommendations" in threat_output:
                    recommendations = threat_output["recommendations"] if isinstance(threat_output["recommendations"], list) else [str(threat_output["recommendations"])]
                
                logger.info(f"✅ Parsed threat intelligence: {certainty_level} certainty, {risk_score:.2f} risk, {len(findings)} findings")
                
            else:
                # Fallback
                logger.warning("Could not extract structured output, using fallback")
                findings = [{
                    "type": "info",
                    "description": "Threat intelligence check completed - structured output not available"
                }]
                risk_score = 0.5
                certainty_level = "LOW"
                analysis_reasoning = "Agent did not produce expected structured output"
                evidence_quality = "Unable to extract threat database results from agent output"
                limitations = "Analysis produced narrative instead of structured data"
                recommendations = ["Retry threat correlation with explicit JSON formatting"]
            
        except Exception as e:
            logger.error(f"Error parsing threat intelligence: {str(e)}", exc_info=True)
            findings = [{
                "type": "error",
                "description": f"Failed to process threat intelligence output: {str(e)}"
            }]
            recommendations = ["Manual review required due to processing error"]
            risk_score = 0.0
            certainty_level = "INCONCLUSIVE"
            analysis_reasoning = f"Parser error: {str(e)}"
            evidence_quality = "No evidence - parsing failed"
            limitations = "Complete analysis failure"
        
        return AgentResponse(
            agent_name=self.crew_name,
            request_id=request.request_id,
            status="success",
            risk_score=risk_score,
            certainty_level=certainty_level,
            analysis_reasoning=analysis_reasoning,
            evidence_quality=evidence_quality,
            limitations=limitations,
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
    
    def _extract_risk_score(self, threat_output: Dict[str, Any]) -> float:
        """
        Robustly extract risk_score from various JSON structures
        
        Handles formats:
        1. Direct: {"risk_score": 0.96}
        2. Nested lowercase: {"risk_assessment": {"risk_score": 0.96}}
        3. Nested capitalized: {"Risk Assessment": {"risk_score": 0.96}}
        4. Nested with suffix: {"Risk Assessment based on Threat Intelligence": {"risk_score": 0.96}}
        5. Threat Report wrapper: {"Threat Intelligence Report": {"Risk Assessment": {...}}}
        6. Gemini format: {"threat_intelligence_report": {"risk_assessment": {"risk_score": 0.96}}}
        """
        # Try direct access first
        risk_score = threat_output.get('risk_score', 0.0)
        if risk_score > 0.0:
            return float(risk_score)
        
        # Try all possible nested paths
        possible_paths = [
            ['threat_intelligence_report', 'risk_assessment', 'risk_score'],
            ['threat_intelligence_report', 'Risk Assessment', 'risk_score'],
            ['risk_assessment', 'risk_score'],
            ['Risk Assessment', 'risk_score'],
            ['Risk Assessment based on Threat Intelligence', 'risk_score'],
            ['Threat Intelligence Report', 'Risk Assessment', 'risk_score'],
            ['Threat Intelligence Report', 'risk_assessment', 'risk_score'],
            ['threat_report', 'risk_assessment', 'risk_score'],
        ]
        
        for path in possible_paths:
            current = threat_output
            for key in path:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    break
            else:
                # Successfully traversed the entire path
                if isinstance(current, (int, float)):
                    return float(current)
        
        return 0.0
    
    def _extract_confidence(self, threat_output: Dict[str, Any]) -> float:
        """Extract confidence score from various JSON structures"""
        # Try direct access first
        confidence = threat_output.get('confidence', 0.5)
        if confidence != 0.5:
            return float(confidence)
        
        # Try nested paths
        possible_paths = [
            ['risk_assessment', 'confidence'],
            ['Risk Assessment', 'confidence'],
            ['Risk Assessment based on Threat Intelligence', 'confidence'],
            ['Threat Intelligence Report', 'Risk Assessment', 'confidence'],
        ]
        
        for path in possible_paths:
            current = threat_output
            for key in path:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    break
            else:
                if isinstance(current, (int, float)):
                    return float(current)
        
        return 0.5
    
    def _extract_url_findings(self, threat_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract URL findings from various JSON structures"""
        # Try direct tool output format
        urls_checked = threat_output.get('urls_checked', [])
        if urls_checked:
            return urls_checked
        
        # Try capitalized nested format
        known_urls = threat_output.get('Known Malicious URLs', [])
        if known_urls:
            # Convert to expected format
            return [{
                'url': url_info.get('url', ''),
                'is_malicious': True,
                'threat_sources': [{
                    'source': 'Google Safe Browsing',
                    'threat_type': url_info.get('threat_classification', 'UNKNOWN'),
                    'malicious': True
                }]
            } for url_info in known_urls]
        
        # Try report wrapper format
        if 'Threat Intelligence Report' in threat_output:
            report = threat_output['Threat Intelligence Report']
            known_urls = report.get('Known Malicious URLs', [])
            if known_urls:
                return [{
                    'url': url_info.get('url', ''),
                    'is_malicious': True,
                    'threat_sources': [{
                        'source': 'Google Safe Browsing',
                        'threat_type': url_info.get('threat_classification', 'UNKNOWN'),
                        'malicious': True
                    }]
                } for url_info in known_urls]
        
        # Try lowercase format
        known_malicious_urls = threat_output.get('known_malicious_urls', [])
        if known_malicious_urls:
            return [{
                'url': url if isinstance(url, str) else url.get('url', ''),
                'is_malicious': True,
                'threat_sources': [{'source': 'Threat Database', 'malicious': True}]
            } for url in known_malicious_urls]
        
        return []
    
    def _extract_ip_reputation(self, threat_output: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IP reputation from various JSON structures"""
        # Try direct tool output format
        ip_rep = threat_output.get('ip_reputation')
        if ip_rep:
            return ip_rep
        
        # Try capitalized nested format
        ip_scores = threat_output.get('IP Reputation Scores and Abuse History', {})
        if ip_scores:
            return {
                'ip_address': ip_scores.get('ip_address', ''),
                'is_malicious': ip_scores.get('abuse_score', 0) > 0,
                'abuse_score': ip_scores.get('abuse_score', 0),
                'total_reports': ip_scores.get('total_reports', 0),
                'country': ip_scores.get('country', 'Unknown')
            }
        
        # Try report wrapper format
        if 'Threat Intelligence Report' in threat_output:
            report = threat_output['Threat Intelligence Report']
            ip_scores = report.get('IP Reputation Scores and Abuse History', {})
            if ip_scores:
                return {
                    'ip_address': ip_scores.get('ip_address', ''),
                    'is_malicious': ip_scores.get('abuse_score', 0) > 0,
                    'abuse_score': ip_scores.get('abuse_score', 0),
                    'total_reports': ip_scores.get('total_reports', 0),
                    'country': ip_scores.get('country', 'Unknown')
                }
        
        # Try lowercase snake_case format
        ip_reputation_scores = threat_output.get('ip_reputation_scores', {})
        if ip_reputation_scores:
            return {
                'ip_address': ip_reputation_scores.get('ip', ''),
                'is_malicious': ip_reputation_scores.get('reputation_score', 0) > 0,
                'abuse_score': ip_reputation_scores.get('reputation_score', 0),
                'total_reports': len(ip_reputation_scores.get('abuse_history', [])),
                'country': ip_reputation_scores.get('country', 'Unknown')
            }
        
        return None
