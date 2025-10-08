from typing import Dict, Any, List, Optional
from crewai import Agent, Task, Crew
from .basic_agent import BaseCybersecurityCrew, AgentRequest, AgentResponse
from datetime import datetime
import logging

from app.Tools.email_analysis import EmailContentAnalysisTool
from app.ML.semantic_analysis import SemanticAnalyzer
from app.LLM.llm import get_gemini_pro
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
            goal="Perform comprehensive linguistic analysis using advanced ML models",
            backstory="""You are an expert in email security analysis, combining ML model insights 
            with deep knowledge of social engineering and phishing tactics. You leverage transformer 
            models and semantic analysis to detect subtle patterns and anomalies in email content. 
            Your analysis is data-driven and based on model outputs rather than static rules.""",
            tools=[self.email_tool],
            llm=get_gemini_pro(),
            verbose=True,
            allow_delegation=False
        )
        
        return [linguistic_expert]
    
    def create_tasks(self) -> List[Task]:
        """Create task for ML-powered linguistic analysis"""
        
        linguistic_analysis_task = Task(
            description="""Perform comprehensive linguistic analysis using ML models and semantic analysis.
            Use the EmailContentAnalysisTool to:
            
            1. Process email content through transformer models
            2. Analyze semantic patterns and anomalies
            3. Detect social engineering indicators
            4. Identify manipulation tactics
            5. Calculate threat metrics
            
            Email Data: {email_data}
            Metadata: {metadata}
            
            Focus on ML model outputs and confidence scores.""",
            agent=self.agents[0],
            expected_output="""A structured analysis report containing:
            - ML model predictions and confidence scores
            - Semantic analysis results
            - Threat indicators with severity levels
            - Evidence-based recommendations
            - Threat level assessment with confidence metrics"""
        )
        
        return [linguistic_analysis_task]
    
    async def _execute_crew(self, request: AgentRequest) -> Any:
        """Execute the linguistic analysis crew"""
        return self.crew.kickoff(inputs={
            "email_data": request.email_data,
            "metadata": request.metadata
        })
    
    def _parse_crew_result(self, result: Any, request: AgentRequest, processing_time: float) -> AgentResponse:
        """Parse CrewAI result into standardized response, handling ML model outputs"""
        
        findings = []
        recommendations = []
        confidence_score = 0.0
        
        try:
            # Extract structured data from ML analysis result
            if isinstance(result, dict):
                model_output = result
            elif hasattr(result, 'raw'):
                model_output = result.raw
            else:
                model_output = {"raw_text": str(result)}
            
            # Process threat indicators
            if "indicators" in model_output:
                findings.extend([
                    ThreatIndicator(
                        type=indicator.get("type", "unknown"),
                        severity=ThreatLevel[indicator.get("severity", "LOW").upper()],
                        confidence=indicator.get("confidence", 0.5),
                        description=indicator.get("description", "No description provided")
                    ).dict()
                    for indicator in model_output["indicators"]
                ])
                
            # Calculate overall confidence from ML model scores
            if findings:
                confidence_score = sum(f["confidence"] for f in findings) / len(findings)
            
            # Extract ML-based recommendations
            if "recommendations" in model_output:
                recommendations = model_output["recommendations"]
            
            # Add model-specific metadata
            findings.append({
                "type": "model_metadata",
                "severity": "info",
                "confidence": 1.0,
                "description": "Analysis performed using transformer models and semantic analysis"
            })
            
        except Exception as e:
            logger.error(f"Error parsing ML model results: {str(e)}", exc_info=True)
            findings = [{
                "type": "error",
                "severity": "high",
                "confidence": 1.0,
                "description": f"Failed to process ML model output: {str(e)}"
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
