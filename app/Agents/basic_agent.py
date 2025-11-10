from typing import Dict, Any, Optional, List, Literal
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
import logging
from datetime import datetime
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AgentRequest(BaseModel):
    """Base request model for all cybersecurity agents"""
    email_data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = {}
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None


class AgentResponse(BaseModel):
    """
    Base response model for all cybersecurity agents.
    
    New Confidence Mechanism (Cybersecurity Analyst Approach):
    - certainty_level: DEFINITIVE (authoritative sources, 100% confirmed) / HIGH (strong indicators, multiple corroborating signals) / MEDIUM (some evidence, needs context) / LOW (weak signals, inconclusive) / INCONCLUSIVE (insufficient data)
    - analysis_reasoning: WHY this assessment was made - specific evidence and logic
    - evidence_quality: Which sources were used, how trustworthy they are, data completeness
    - limitations: What couldn't be determined, missing context, caveats
    """
    agent_name: str
    request_id: str
    status: str  # "success", "error", "warning"
    
    # Risk assessment
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Quantitative risk score from 0.0 to 1.0")
    
    # New confidence structure (cybersecurity analyst perspective)
    certainty_level: Literal["DEFINITIVE", "HIGH", "MEDIUM", "LOW", "INCONCLUSIVE"] = Field(
        description="Assessment certainty based on evidence quality and source authority"
    )
    analysis_reasoning: str = Field(
        description="Detailed reasoning for this assessment - WHY this conclusion was reached"
    )
    evidence_quality: str = Field(
        description="Quality and sources of evidence - which tools/models were used, how trustworthy"
    )
    limitations: str = Field(
        description="What couldn't be determined, missing context, analysis caveats"
    )
    
    # Results
    findings: List[Dict[str, Any]]
    recommendations: List[str]
    processing_time: float
    timestamp: datetime


class BaseCybersecurityCrew:
    """
    Base CrewAI crew class for cybersecurity agents.
    Each specific agent will inherit from this and define their own agents, tasks, and crew.
    """
    
    def __init__(self, crew_name: str, version: str = "1.0.0"):
        self.crew_name = crew_name
        self.version = version
        self.logger = logging.getLogger(f"{__name__}.{crew_name}")
        self.crew = None
        self.agents = []
        self.tasks = []
        
    def create_agents(self) -> List[Agent]:
        """
        Create the agents for this crew. Must be implemented by subclasses.
        
        Returns:
            List of CrewAI Agent objects
        """
        raise NotImplementedError("Subclasses must implement create_agents()")
    
    def create_tasks(self) -> List[Task]:
        """
        Create the tasks for this crew. Must be implemented by subclasses.
        
        Returns:
            List of CrewAI Task objects
        """
        raise NotImplementedError("Subclasses must implement create_tasks()")
    
    def setup_crew(self) -> Crew:
        """
        Set up the CrewAI crew with agents and tasks.
        
        Returns:
            Configured CrewAI Crew object
        """
        self.agents = self.create_agents()
        self.tasks = self.create_tasks()
        
        self.crew = Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,  # Can be overridden in subclasses
            verbose=True
        )
        
        return self.crew
    
    def get_agent_info(self) -> Dict[str, Any]:
        """
        Return information about this crew's capabilities.
        Override in subclasses for specific capability information.
        
        Returns:
            Dictionary containing crew metadata
        """
        return {
            "crew_name": self.crew_name,
            "version": self.version,
            "agent_count": len(self.agents) if self.agents else 0,
            "task_count": len(self.tasks) if self.tasks else 0
        }
    
    def validate_request(self, request: AgentRequest) -> bool:
        """
        Validate the incoming request.
        Override in subclasses for specific validation requirements.
        
        Args:
            request: AgentRequest to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not request.email_data:
            self.logger.error("No email data provided in request")
            return False
        
        if not request.request_id:
            self.logger.warning("No request_id provided, generating one")
            request.request_id = f"{self.crew_name}_{datetime.now().isoformat()}"
            
        if not request.timestamp:
            request.timestamp = datetime.now()
            
        return True
    
    async def process_request(self, request_data: Dict[str, Any]) -> AgentResponse:
        """
        Main entry point for processing requests with CrewAI.
        Handles validation, crew execution, and response formatting.
        
        Args:
            request_data: Raw request data from HTTP call
            
        Returns:
            AgentResponse with analysis results
        """
        start_time = datetime.now()
        
        try:
            # Parse and validate request
            request = AgentRequest(**request_data)
            
            if not self.validate_request(request):
                raise ValueError("Invalid request data")
            
            self.logger.info(f"Processing request {request.request_id}")
            
            # Ensure crew is set up
            if not self.crew:
                self.setup_crew()
            
            # Execute the crew
            result = await self._execute_crew(request)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Parse crew result into standardized response
            response = self._parse_crew_result(result, request, processing_time)
            
            self.logger.info(f"Request {request.request_id} processed in {processing_time:.2f}s")
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error processing request: {str(e)}")
            
            # Return error response
            return AgentResponse(
                agent_name=self.crew_name,
                request_id=request_data.get('request_id', 'unknown'),
                status="error",
                risk_score=0.0,
                certainty_level="INCONCLUSIVE",
                analysis_reasoning=f"Crew execution failed: {str(e)}",
                evidence_quality="No analysis performed due to error",
                limitations="Agent error prevented analysis",
                findings=[],
                recommendations=[f"Crew error: {str(e)}"],
                processing_time=(datetime.now() - start_time).total_seconds(),
                timestamp=datetime.now()
            )
    
    async def _execute_crew(self, request: AgentRequest) -> Any:
        """
        Execute the CrewAI crew with the given request.
        Override in subclasses for specific execution logic.
        
        Args:
            request: Validated AgentRequest
            
        Returns:
            CrewAI execution result
        """
        # Default execution - can be overridden
        return self.crew.kickoff(inputs={
            "email_data": request.email_data,
            "metadata": request.metadata
        })
    
    def _parse_crew_result(self, result: Any, request: AgentRequest, processing_time: float) -> AgentResponse:
        """
        Parse CrewAI result into standardized AgentResponse.
        Override in subclasses for specific parsing logic.
        
        Args:
            result: CrewAI execution result
            request: Original request
            processing_time: Time taken to process
            
        Returns:
            Standardized AgentResponse
        """
        # Default parsing - can be overridden
        return AgentResponse(
            agent_name=self.crew_name,
            request_id=request.request_id,
            status="success",
            risk_score=0.5,
            certainty_level="MEDIUM",
            analysis_reasoning="Default analysis - override in subclass",
            evidence_quality="No specific evidence sources configured",
            limitations="Default implementation - specific agent should provide details",
            findings=[{"result": str(result)}],
            recommendations=["Review analysis results"],
            processing_time=processing_time,
            timestamp=datetime.now()
        )
    
    def health_check(self) -> Dict[str, Any]:
        """
        Health check endpoint for the crew.
        
        Returns:
            Dictionary with crew health status
        """
        return {
            "crew_name": self.crew_name,
            "version": self.version,
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "capabilities": self.get_agent_info(),
            "crew_configured": self.crew is not None
        }
