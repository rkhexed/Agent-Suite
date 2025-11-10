from typing import Dict, Any, List, Optional
from crewai import Agent, Task, Crew
from .basic_agent import BaseCybersecurityCrew, AgentRequest, AgentResponse
from datetime import datetime
import logging

from app.Tools.email_analysis import EmailContentAnalysisTool
from app.ML.semantic_analysis import SemanticAnalyzer
from app.LLM.llm import get_gemini_flash  # Using Gemini Flash (1500 req/day FREE)
from app.Helper.helper_pydantic import ThreatLevel, ThreatIndicator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LinguisticAnalysisCrew(BaseCybersecurityCrew):
    """
    CrewAI crew for ML-powered linguistic analysis of emails.
    Utilizes advanced NLP models for pattern detection and threat analysis.
    """
    
    def __init__(self):
        super().__init__("Linguistic Analysis Crew", "2.0.0")
        self.email_tool = EmailContentAnalysisTool()
        self.semantic_analyzer = SemanticAnalyzer()
    
    def create_agents(self) -> List[Agent]:
        """Create specialized agent for ML-powered linguistic analysis"""
        
        linguistic_expert = Agent(
            role="ML-Enhanced Linguistic Analyst",
            goal="Perform comprehensive behavioral analysis of email content using ML models with cybersecurity analyst expertise",
            backstory="""You are a cybersecurity analyst specializing in social engineering and phishing detection. 
            You analyze email content like an experienced SOC analyst would:
            
            1. BEHAVIORAL ANALYSIS: You examine psychological manipulation tactics (urgency, fear, authority, scarcity)
            2. ML MODEL INTERPRETATION: You interpret BERT phishing model predictions with understanding of model strengths/limitations
            3. SOCIAL ENGINEERING TACTICS: You identify specific techniques (pretexting, baiting, quid pro quo, tailgating)
            4. CONTEXTUAL REASONING: You explain WHY something is suspicious, not just that it is
            
            Your assessments include:
            - CERTAINTY LEVEL based on evidence strength (DEFINITIVE for ML confidence >0.95, HIGH for >0.80, MEDIUM for >0.60, LOW for <0.60)
            - ANALYSIS REASONING explaining specific tactics and behavioral indicators observed
            - EVIDENCE QUALITY documenting BERT model performance and which features triggered detection
            - LIMITATIONS noting what you cannot assess (sender authenticity, technical infrastructure, etc.)
            
            You DO NOT make claims about technical aspects (DNS, IP reputation, etc.) - that's for other agents.
            You focus purely on content analysis and behavioral patterns.""",
            tools=[self.email_tool],
            llm=get_gemini_flash(),
            verbose=True,
            allow_delegation=False
        )
        
        return [linguistic_expert]
    
    def create_tasks(self) -> List[Task]:
        """Create task for ML-powered linguistic analysis"""
        
        linguistic_analysis_task = Task(
            description="""Perform cybersecurity analyst-level behavioral analysis of email content.
            Use the EmailContentAnalysisTool to analyze the email, then provide detailed reasoning:
            
            ANALYSIS APPROACH (think like a SOC analyst):
            1. **BERT Model Assessment**: Run the phishing detection model and interpret results
               - What's the model prediction and confidence?
               - Note: dima806/phishing-email-detection has 99.98% accuracy on test set
               - Predictions >0.95 are highly reliable, 0.80-0.95 are strong, 0.60-0.80 need context
            
            2. **Social Engineering Tactics**: Identify specific manipulation techniques
               - Urgency/time pressure ("within 24 hours", "immediately", "expires soon")
               - Authority impersonation (claims to be from IT, bank, executive)
               - Fear/consequences ("account suspended", "security breach", "legal action")
               - Reward/scarcity ("limited offer", "exclusive access")
            
            3. **Behavioral Indicators**: Document psychological patterns
               - Unusual requests (credentials, payments, downloads)
               - Inconsistent tone (formal subject, informal body)
               - Generic greetings vs. personalized content
               - Suspicious language patterns
            
            Email Data: {email_data}
            Metadata: {metadata}
            
            REQUIRED OUTPUT FORMAT (provide ALL fields):
            - risk_score: Float 0.0-1.0 (use BERT model confidence as primary signal)
            - certainty_level: DEFINITIVE (BERT >0.95) / HIGH (>0.80) / MEDIUM (>0.60) / LOW (<0.60) / INCONCLUSIVE (error)
            - analysis_reasoning: Detailed explanation of WHY this assessment - cite specific tactics observed
            - evidence_quality: "BERT phishing model (99.98% accuracy) confidence: X.XX. Features detected: [list]. Model limitations: [note]"
            - limitations: "Cannot assess: sender IP reputation, domain authenticity, link destinations, attachment safety. Content analysis only."
            - findings: List of specific indicators found (urgency, authority claims, suspicious requests)
            - recommendations: Actionable advice based on behavioral analysis""",
            agent=self.agents[0],
            expected_output="""JSON object with complete cybersecurity analyst assessment:
            {
                "risk_score": 0.X,
                "certainty_level": "DEFINITIVE/HIGH/MEDIUM/LOW/INCONCLUSIVE",
                "analysis_reasoning": "Detailed explanation citing specific social engineering tactics and BERT results",
                "evidence_quality": "BERT model performance metrics and feature analysis",
                "limitations": "Clear statement of what this agent cannot assess",
                "findings": [list of specific behavioral indicators],
                "recommendations": [actionable security recommendations]
            }"""
        )
        
        return [linguistic_analysis_task]
    
    async def _execute_crew(self, request: AgentRequest) -> Any:
        """Execute the linguistic analysis crew"""
        return self.crew.kickoff(inputs={
            "email_data": request.email_data,
            "metadata": request.metadata
        })
    
    def _parse_crew_result(self, result: Any, request: AgentRequest, processing_time: float) -> AgentResponse:
        """Parse CrewAI result into standardized response with cybersecurity analyst reasoning"""
        
        findings = []
        recommendations = []
        risk_score = 0.0
        certainty_level = "INCONCLUSIVE"
        analysis_reasoning = "Analysis failed to produce structured output"
        evidence_quality = "No evidence collected"
        limitations = "Unable to perform analysis"
        
        try:
            import json
            
            model_output = None
            
            # Strategy 1: Try to extract JSON from agent output
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
                
                # Try to find JSON object
                json_start = raw_str.find('{')
                json_end = raw_str.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    try:
                        potential_json = raw_str[json_start:json_end]
                        model_output = json.loads(potential_json)
                        logger.info(f"✅ Extracted JSON output from agent")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON: {e}")
            
            # Strategy 2: Try to get tool output directly
            if not model_output and hasattr(result, 'tasks_output') and result.tasks_output:
                for task_output in result.tasks_output:
                    if hasattr(task_output, 'raw') and task_output.raw:
                        try:
                            raw_str = str(task_output.raw)
                            json_start = raw_str.find('{')
                            json_end = raw_str.rfind('}') + 1
                            if json_start >= 0 and json_end > json_start:
                                model_output = json.loads(raw_str[json_start:json_end])
                                logger.info(f"✅ Extracted from tasks_output")
                                break
                        except Exception as e:
                            continue
            
            # If we got structured output, extract all fields
            if model_output and isinstance(model_output, dict):
                # Extract new confidence structure
                certainty_level = model_output.get("certainty_level", "MEDIUM")
                analysis_reasoning = model_output.get("analysis_reasoning", "No reasoning provided")
                evidence_quality = model_output.get("evidence_quality", "Evidence quality not documented")
                limitations = model_output.get("limitations", "Limitations not specified")
                
                # Extract risk score
                risk_score = model_output.get("risk_score", 0.5)
                
                # Extract findings
                if "findings" in model_output:
                    raw_findings = model_output["findings"]
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
                elif "indicators" in model_output:
                    # Fallback to old format
                    for indicator in model_output["indicators"]:
                        findings.append({
                            "type": indicator.get("type", "unknown"),
                            "severity": str(indicator.get("severity", "low")).replace("ThreatLevel.", ""),
                            "confidence": indicator.get("confidence", 0.5),
                            "description": indicator.get("description", "No description"),
                            "evidence": indicator.get("evidence", [])
                        })
                
                # Extract recommendations
                if "recommendations" in model_output:
                    recommendations = model_output["recommendations"] if isinstance(model_output["recommendations"], list) else [str(model_output["recommendations"])]
                
                logger.info(f"✅ Parsed linguistic analysis: {certainty_level} certainty, {risk_score:.2f} risk, {len(findings)} findings")
                
            else:
                # Fallback: couldn't extract structured output
                logger.warning("Could not extract structured output, using fallback")
                findings = [{
                    "type": "info",
                    "description": "Analysis completed - structured output not available"
                }]
                risk_score = 0.5
                certainty_level = "LOW"
                analysis_reasoning = "Agent did not produce expected structured output"
                evidence_quality = "Unable to extract evidence from agent output"
                limitations = "Analysis produced narrative instead of structured data"
                recommendations = ["Retry analysis with explicit JSON formatting"]
            
        except Exception as e:
            logger.error(f"Error parsing linguistic analysis: {str(e)}", exc_info=True)
            findings = [{
                "type": "error",
                "description": f"Failed to process analysis output: {str(e)}"
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
        """Return information about linguistic analysis capabilities"""
        return {
            "crew_name": self.crew_name,
            "version": self.version,
            "capabilities": [
                "Email content analysis",
                "Social engineering detection",
                "Sentiment analysis",
                "Linguistic pattern detection",
                "Urgency indicator identification",
                "Psychological manipulation detection"
            ],
            "analysis_types": [
                "Phishing detection",
                "Social engineering analysis",
                "Urgency pressure tactics",
                "Language anomaly detection",
                "Emotional manipulation identification"
            ],
            "output_format": "Structured threat assessment with confidence scores"
        }


# Example usage
if __name__ == "__main__":
    # Create and test the linguistic analysis crew
    crew = LinguisticAnalysisCrew()
    
    # Example email data
    test_request = {
        "email_data": {
            "subject": "URGENT: Verify Your Account Immediately",
            "content": "Your account will be suspended in 24 hours. Click here to verify: bit.ly/suspicious-link",
            "sender": "security@fake-bank.com"
        },
        "metadata": {"source": "test"},
        "request_id": "test_001"
    }
    
    # Process the request
    import asyncio
    async def test_crew():
        response = await crew.process_request(test_request)
        print(f"Analysis Result: {response}")
    
    asyncio.run(test_crew())
