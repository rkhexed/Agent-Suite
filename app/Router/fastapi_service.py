from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any
import uvicorn
import asyncio
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FastAPICybersecurityService:
    """
    FastAPI service wrapper for CrewAI cybersecurity agents.
    Provides HTTP endpoints that n8n can call.
    """
    
    def __init__(self, crew_instance, service_name: str, port: int = 8000):
        self.crew = crew_instance
        self.service_name = service_name
        self.port = port
        self.app = FastAPI(
            title=f"{service_name} API",
            description=f"Cybersecurity agent service for {service_name}",
            version="1.0.0"
        )
        
        # Add CORS middleware for n8n integration
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Set up FastAPI routes for the service"""
        
        @self.app.get("/")
        async def root():
            return {
                "service": self.service_name,
                "status": "running",
                "timestamp": datetime.now().isoformat()
            }
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint for monitoring"""
            try:
                health_info = self.crew.health_check()
                return health_info
            except Exception as e:
                logger.error(f"Health check failed: {str(e)}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/info")
        async def get_agent_info():
            """Get agent capabilities and information"""
            try:
                return self.crew.get_agent_info()
            except Exception as e:
                logger.error(f"Failed to get agent info: {str(e)}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/analyze")
        async def analyze_email(request_data: Dict[str, Any]):
            """
            Main analysis endpoint that n8n will call.
            Accepts email data and returns analysis results.
            """
            try:
                logger.info(f"Received analysis request for {self.service_name}")
                
                # Process the request using the crew
                response = await self.crew.process_request(request_data)
                
                # Convert Pydantic model to dict for JSON response
                return response.dict()
                
            except Exception as e:
                logger.error(f"Analysis failed: {str(e)}")
                raise HTTPException(
                    status_code=500, 
                    detail={
                        "error": str(e),
                        "service": self.service_name,
                        "timestamp": datetime.now().isoformat()
                    }
                )
        
        @self.app.post("/process")
        async def process_request(request_data: Dict[str, Any]):
            """
            Alternative endpoint name for compatibility with different n8n workflows.
            Same functionality as /analyze.
            """
            return await analyze_email(request_data)
    
    def run(self, host: str = "0.0.0.0", reload: bool = False):
        """
        Run the FastAPI service.
        
        Args:
            host: Host to bind to
            reload: Enable auto-reload for development
        """
        logger.info(f"Starting {self.service_name} service on {host}:{self.port}")
        
        if reload:
            # For development with reload, use import string
            uvicorn.run(
                "app.Agents.fastapi_service:app",
                host=host,
                port=self.port,
                reload=True,
                log_level="info"
            )
        else:
            # For production, use app instance directly
            uvicorn.run(
                self.app,
                host=host,
                port=self.port,
                log_level="info"
            )
    
    def get_app(self) -> FastAPI:
        """Get the FastAPI app instance for testing or external ASGI server"""
        return self.app


# Example usage and service factory functions
def create_linguistic_service(port: int = 8001) -> FastAPICybersecurityService:
    """Create linguistic analysis service"""
    # This would import and instantiate the actual linguistic crew
    # from .linguistic_agent import LinguisticAnalysisCrew
    # crew = LinguisticAnalysisCrew()
    # return FastAPICybersecurityService(crew, "Linguistic Analysis", port)
    
    # Placeholder for now
    class MockCrew:
        async def process_request(self, data):
            return {"status": "mock", "service": "linguistic"}
        
        def health_check(self):
            return {"status": "healthy", "service": "linguistic"}
        
        def get_agent_info(self):
            return {"capabilities": ["NLP analysis", "Sentiment detection"]}
    
    mock_crew = MockCrew()
    return FastAPICybersecurityService(mock_crew, "Linguistic Analysis", port)


def create_technical_service(port: int = 8002) -> FastAPICybersecurityService:
    """Create technical analysis service"""
    # Placeholder for now
    class MockCrew:
        async def process_request(self, data):
            return {"status": "mock", "service": "technical"}
        
        def health_check(self):
            return {"status": "healthy", "service": "technical"}
        
        def get_agent_info(self):
            return {"capabilities": ["Email header analysis", "Forensics"]}
    
    mock_crew = MockCrew()
    return FastAPICybersecurityService(mock_crew, "Technical Analysis", port)


if __name__ == "__main__":
    # Example: Run a mock service for testing
    service = create_linguistic_service()
    service.run(reload=True)
