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
from app.LLM.llm import get_mistral_small

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
            role="Infrastructure Security Analyst",
            goal="Assess email sender infrastructure for signs of phishing campaigns using domain age analysis",
            backstory="""You are a cybersecurity analyst specializing in email infrastructure analysis.
            You analyze sender domains like an experienced SOC analyst would:
            
            1. DOMAIN AGE ASSESSMENT: You check WHOIS records to determine domain registration date
               - Phishing campaigns often use newly registered domains (< 30 days old)
               - Legitimate businesses use established domains (typically years old)
               - You understand that domain age alone isn't conclusive but is a strong signal
            
            2. DATA QUALITY INDICATORS: You document WHOIS lookup reliability
               - WHOIS data availability (some registrars protect privacy)
               - Registration date accuracy (some shows last update, not creation)
               - Domain registrar reputation
            
            3. CONTEXTUAL REASONING: You explain infrastructure risk patterns
               - WHY new domains indicate phishing risk
               - How domain age correlates with attack campaigns
               - When established domains might still be compromised
            
            Your assessments include:
            - CERTAINTY LEVEL based on WHOIS data quality (DEFINITIVE for clear WHOIS, HIGH for partial data, LOW for protected/unavailable)
            - ANALYSIS REASONING explaining domain age significance and risk patterns
            - EVIDENCE QUALITY documenting WHOIS source, data completeness, lookup success/failure
            - LIMITATIONS noting you cannot assess: content safety, sender authenticity, IP reputation, link destinations
            
            CRITICAL: Call the Technical Email Validation Tool ONLY ONCE. The tool's output is authoritative and complete.
            Do NOT re-run the tool or second-guess its results. Trust the WHOIS data and provide your analysis immediately.
            
            You DO NOT analyze email content, URLs, or IPs - that's for other specialized agents.
            You focus purely on sender domain infrastructure.""",
            tools=[self.technical_tool],
            llm=get_mistral_small(),
            verbose=True,
            allow_delegation=False,
            max_iter=3  # Limit iterations to prevent redundant tool calls
        )
        
        return [domain_validator]
    
    def create_tasks(self) -> List[Task]:
        """Create task for technical validation"""
        
        validation_task = Task(
            description="""Perform infrastructure security analysis of sender domain with cybersecurity analyst expertise.
            Use the Technical Email Validation Tool to analyze domain infrastructure, then provide detailed reasoning:
            
            ANALYSIS APPROACH (think like a SOC analyst):
            1. **WHOIS Domain Age Check**: Retrieve domain registration date
               - Calculate domain age in days
               - Flag if < 30 days old (high phishing risk)
               - Flag if < 90 days old (moderate phishing risk)
               - Note: Established domains (> 1 year) are generally lower risk
            
            2. **Data Quality Assessment**: Document WHOIS lookup reliability
               - Was WHOIS data available? (Some registrars use privacy protection)
               - Is registration date accurate? (Some show update date, not creation)
               - What registrar was used? (Some are known for phishing abuse)
            
            3. **Infrastructure Risk Patterns**: Explain phishing campaign indicators
               - New domains: Phishers register fresh domains for each campaign
               - Domain parking: Recently registered but not yet configured properly
               - Bulk registration: Multiple similar domains registered together
            
            Email Data: {email_data}
            Metadata: {metadata}
            
            REQUIRED OUTPUT FORMAT (provide ALL fields):
            - risk_score: Float 0.0-1.0 (1.0 for <7 days, 0.8 for <30 days, 0.5 for <90 days, 0.2 for >1 year)
            - certainty_level: DEFINITIVE (clear WHOIS with registration date) / HIGH (WHOIS available, some ambiguity) / MEDIUM (partial WHOIS) / LOW (privacy protected) / INCONCLUSIVE (WHOIS unavailable)
            - analysis_reasoning: "Domain is X days old, registered on DATE. [Explain risk pattern and significance]"
            - evidence_quality: "WHOIS lookup via [source]. Registration date: [DATE]. Data completeness: [FULL/PARTIAL/PROTECTED]. Registrar: [NAME]."
            - limitations: "Cannot assess: email content safety, sender IP reputation, link/attachment threats, whether domain is compromised. Infrastructure analysis only."
            - findings: List of infrastructure indicators (domain age, WHOIS availability, registration patterns)
            - recommendations: Actionable advice based on infrastructure risk""",
            agent=self.agents[0],
            expected_output="""JSON object with complete infrastructure security assessment:
            {
                "risk_score": 0.X,
                "certainty_level": "DEFINITIVE/HIGH/MEDIUM/LOW/INCONCLUSIVE",
                "analysis_reasoning": "Detailed explanation of domain age significance and infrastructure risk patterns",
                "evidence_quality": "WHOIS data source, completeness, and reliability assessment",
                "limitations": "Clear statement of what this agent cannot assess",
                "findings": [list of specific infrastructure indicators],
                "recommendations": [actionable security recommendations]
            }"""
        )
        
        return [validation_task]
    
    async def _execute_crew(self, request: AgentRequest) -> Any:
        """Execute the technical validation crew"""
        return self.crew.kickoff(inputs={
            "email_data": request.email_data,
            "metadata": request.metadata
        })
    
    def _parse_crew_result(self, result: Any, request: AgentRequest, processing_time: float) -> AgentResponse:
        """Parse CrewAI result into standardized response with infrastructure analyst reasoning"""
        
        findings = []
        recommendations = []
        risk_score = 0.0
        certainty_level = "INCONCLUSIVE"
        analysis_reasoning = "Infrastructure analysis failed to produce structured output"
        evidence_quality = "No WHOIS data collected"
        limitations = "Unable to perform infrastructure analysis"
        
        try:
            import json
            validation_output = None
            
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
                        validation_output = json.loads(potential_json)
                        logger.info(f"✅ Extracted JSON output from agent")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON: {e}")
            
            # Strategy 2: Try tasks_output
            if not validation_output and hasattr(result, 'tasks_output') and result.tasks_output:
                for task_output in result.tasks_output:
                    if hasattr(task_output, 'raw') and task_output.raw:
                        try:
                            raw_str = str(task_output.raw)
                            json_start = raw_str.find('{')
                            json_end = raw_str.rfind('}') + 1
                            if json_start >= 0 and json_end > json_start:
                                validation_output = json.loads(raw_str[json_start:json_end])
                                logger.info(f"✅ Extracted from tasks_output")
                                break
                        except Exception as e:
                            continue
            
            # If we got structured output, extract all fields
            if validation_output and isinstance(validation_output, dict):
                # Extract new confidence structure
                certainty_level = validation_output.get("certainty_level", "MEDIUM")
                analysis_reasoning = validation_output.get("analysis_reasoning", "No reasoning provided")
                evidence_quality = validation_output.get("evidence_quality", "Evidence quality not documented")
                limitations = validation_output.get("limitations", "Limitations not specified")
                
                # Extract risk score
                risk_score = validation_output.get("risk_score", 0.5)
                
                # Extract findings
                if "findings" in validation_output:
                    raw_findings = validation_output["findings"]
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
                    # Fallback to old format parsing
                    domain_val = validation_output.get('domain_validation', {})
                    if domain_val:
                        is_new = domain_val.get('is_new_domain', False)
                        age_days = domain_val.get('age_in_days', 'Unknown')
                        findings.append({
                            "type": "domain_age",
                            "description": f"Domain age: {age_days} days {'(NEW DOMAIN - SUSPICIOUS)' if is_new else '(established)'}",
                            "evidence": f"Registration date: {domain_val.get('registration_date', 'Unknown')}"
                        })
                
                # Extract recommendations
                if "recommendations" in validation_output:
                    recommendations = validation_output["recommendations"] if isinstance(validation_output["recommendations"], list) else [str(validation_output["recommendations"])]
                
                logger.info(f"✅ Parsed technical validation: {certainty_level} certainty, {risk_score:.2f} risk, {len(findings)} findings")
                
            else:
                # Fallback
                logger.warning("Could not extract structured output, using fallback")
                findings = [{
                    "type": "info",
                    "description": "Validation completed - structured output not available"
                }]
                risk_score = 0.5
                certainty_level = "LOW"
                analysis_reasoning = "Agent did not produce expected structured output"
                evidence_quality = "Unable to extract WHOIS data from agent output"
                limitations = "Analysis produced narrative instead of structured data"
                recommendations = ["Retry validation with explicit JSON formatting"]
            
        except Exception as e:
            logger.error(f"Error parsing technical validation: {str(e)}", exc_info=True)
            findings = [{
                "type": "error",
                "description": f"Failed to process validation output: {str(e)}"
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

