from typing import Dict, Any, List
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
from .basic_agent import BaseCybersecurityCrew, AgentRequest, AgentResponse
from datetime import datetime
import json
import re


class EmailContentTool(BaseTool):
    """Custom tool for analyzing email content"""
    
    name: str = "email_content_analyzer"
    description: str = "Analyzes email content for linguistic patterns, sentiment, and suspicious indicators"
    
    def _run(self, email_content: str, email_subject: str = "") -> Dict[str, Any]:
        """Analyze email content for linguistic patterns"""
        
        analysis = {
            "suspicious_patterns": [],
            "sentiment_score": 0.0,
            "urgency_indicators": [],
            "social_engineering_indicators": [],
            "language_anomalies": []
        }
        
        # Check for urgency indicators
        urgency_words = ["urgent", "immediate", "asap", "critical", "emergency", "expires", "limited time"]
        for word in urgency_words:
            if word.lower() in email_content.lower():
                analysis["urgency_indicators"].append(word)
        
        # Check for social engineering patterns
        social_engineering_patterns = [
            r"click here",
            r"verify your account",
            r"suspended",
            r"unauthorized access",
            r"update your information",
            r"confirm your identity"
        ]
        
        for pattern in social_engineering_patterns:
            if re.search(pattern, email_content.lower()):
                analysis["social_engineering_indicators"].append(pattern)
        
        # Simple sentiment analysis (can be enhanced with proper NLP)
        positive_words = ["good", "great", "excellent", "wonderful", "amazing"]
        negative_words = ["bad", "terrible", "urgent", "problem", "issue", "suspended"]
        
        positive_count = sum(1 for word in positive_words if word in email_content.lower())
        negative_count = sum(1 for word in negative_words if word in email_content.lower())
        
        if positive_count + negative_count > 0:
            analysis["sentiment_score"] = (positive_count - negative_count) / (positive_count + negative_count)
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r"bit\.ly|tinyurl|short\.link",  # URL shorteners
            r"\$[0-9,]+",  # Money amounts
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Multiple email addresses
            r"password|login|credentials"  # Credential requests
        ]
        
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, email_content, re.IGNORECASE)
            if matches:
                analysis["suspicious_patterns"].extend(matches)
        
        return analysis


class LinguisticAnalysisCrew(BaseCybersecurityCrew):
    """
    CrewAI crew for linguistic analysis of emails.
    Focuses on NLP patterns, sentiment, and social engineering detection.
    """
    
    def __init__(self):
        super().__init__("Linguistic Analysis Crew", "1.0.0")
        self.email_tool = EmailContentTool()
    
    def create_agents(self) -> List[Agent]:
        """Create specialized agents for linguistic analysis"""
        
        # Content Analysis Agent
        content_analyst = Agent(
            role="Email Content Analyst",
            goal="Analyze email content for linguistic patterns and suspicious indicators",
            backstory="""You are an expert in email content analysis with deep knowledge of 
            social engineering tactics, phishing patterns, and linguistic indicators of malicious intent. 
            You excel at identifying subtle manipulation techniques and suspicious language patterns.""",
            tools=[self.email_tool],
            verbose=True,
            allow_delegation=False
        )
        
        # Sentiment Analysis Agent
        sentiment_analyst = Agent(
            role="Sentiment and Tone Analyst",
            goal="Analyze emotional tone, urgency, and psychological manipulation in emails",
            backstory="""You are a psychologist and linguistics expert specializing in detecting 
            emotional manipulation, urgency tactics, and psychological pressure techniques used in 
            malicious emails. You understand how attackers use language to create urgency and bypass 
            critical thinking.""",
            verbose=True,
            allow_delegation=False
        )
        
        # Pattern Detection Agent
        pattern_detector = Agent(
            role="Linguistic Pattern Detective",
            goal="Identify suspicious linguistic patterns, anomalies, and red flags in email content",
            backstory="""You are a cybersecurity expert with expertise in identifying malicious 
            linguistic patterns. You have extensive experience analyzing phishing emails, social 
            engineering attempts, and other malicious communications. You can spot subtle indicators 
            that others might miss.""",
            verbose=True,
            allow_delegation=False
        )
        
        return [content_analyst, sentiment_analyst, pattern_detector]
    
    def create_tasks(self) -> List[Task]:
        """Create tasks for linguistic analysis workflow"""
        
        # Task 1: Content Analysis
        content_analysis_task = Task(
            description="""Analyze the email content for suspicious linguistic patterns, 
            social engineering indicators, and potential security threats. Focus on:
            1. Suspicious URLs, domains, or links
            2. Requests for sensitive information
            3. Urgency indicators and pressure tactics
            4. Language inconsistencies or anomalies
            5. Social engineering patterns
            
            Email Data: {email_data}
            Metadata: {metadata}
            
            Provide detailed findings with confidence scores.""",
            agent=self.agents[0],  # Content analyst
            expected_output="""A detailed analysis report containing:
            - List of suspicious patterns found
            - Confidence scores for each finding
            - Specific examples from the email
            - Risk assessment level"""
        )
        
        # Task 2: Sentiment and Psychological Analysis
        sentiment_analysis_task = Task(
            description="""Analyze the emotional tone, psychological manipulation tactics, 
            and urgency indicators in the email. Focus on:
            1. Emotional manipulation techniques
            2. Urgency and pressure tactics
            3. Fear-based appeals
            4. Authority impersonation
            5. Reciprocity or social proof tactics
            
            Use the content analysis results from the previous task.
            
            Provide psychological analysis with manipulation indicators.""",
            agent=self.agents[1],  # Sentiment analyst
            expected_output="""A psychological analysis report containing:
            - Emotional manipulation techniques identified
            - Urgency indicators and pressure tactics
            - Psychological risk assessment
            - Recommendations for user awareness"""
        )
        
        # Task 3: Pattern Synthesis and Final Assessment
        pattern_synthesis_task = Task(
            description="""Synthesize all linguistic analysis results and provide a comprehensive 
            assessment. Combine insights from content analysis and sentiment analysis to:
            1. Determine overall threat level
            2. Identify the most critical indicators
            3. Provide actionable recommendations
            4. Calculate confidence score for the assessment
            
            Consider the cumulative evidence from all analysis components.""",
            agent=self.agents[2],  # Pattern detector
            expected_output="""A comprehensive linguistic threat assessment containing:
            - Overall threat level (Low/Medium/High/Critical)
            - Key findings summary
            - Confidence score (0.0-1.0)
            - Specific recommendations
            - User guidance for handling similar emails"""
        )
        
        return [content_analysis_task, sentiment_analysis_task, pattern_synthesis_task]
    
    async def _execute_crew(self, request: AgentRequest) -> Any:
        """Execute the linguistic analysis crew"""
        return self.crew.kickoff(inputs={
            "email_data": request.email_data,
            "metadata": request.metadata
        })
    
    def _parse_crew_result(self, result: Any, request: AgentRequest, processing_time: float) -> AgentResponse:
        """Parse CrewAI result into standardized response"""
        
        # Extract findings from crew result
        findings = []
        recommendations = []
        confidence_score = 0.7  # Default confidence
        
        try:
            # Parse the result (this will depend on actual crew output format)
            if hasattr(result, 'raw'):
                # If result has raw attribute, parse it
                result_text = str(result.raw)
            else:
                result_text = str(result)
            
            # Extract structured information from the result
            # This is a simplified parser - in practice, you'd want more sophisticated parsing
            
            # Look for threat level indicators
            if "critical" in result_text.lower() or "high" in result_text.lower():
                confidence_score = 0.9
                findings.append({
                    "type": "threat_level",
                    "severity": "high",
                    "confidence": 0.9,
                    "description": "High threat indicators detected"
                })
            elif "medium" in result_text.lower():
                confidence_score = 0.7
                findings.append({
                    "type": "threat_level",
                    "severity": "medium",
                    "confidence": 0.7,
                    "description": "Medium threat indicators detected"
                })
            else:
                confidence_score = 0.5
                findings.append({
                    "type": "threat_level",
                    "severity": "low",
                    "confidence": 0.5,
                    "description": "Low threat indicators detected"
                })
            
            # Extract recommendations
            recommendations = [
                "Review email content carefully",
                "Verify sender identity through alternative channels",
                "Do not click on suspicious links",
                "Report suspicious emails to security team"
            ]
            
        except Exception as e:
            self.logger.error(f"Error parsing crew result: {str(e)}")
            findings = [{"error": "Failed to parse analysis results"}]
            recommendations = ["Manual review recommended"]
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
