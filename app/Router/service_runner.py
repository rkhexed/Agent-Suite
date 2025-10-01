#!/usr/bin/env python3
"""
Service runner for cybersecurity agents.
Each agent runs as a separate FastAPI service that n8n can call via HTTP.
"""

import sys
import argparse
import asyncio
from typing import Dict, Any
from .fastapi_service import FastAPICybersecurityService


def create_linguistic_service(port: int = 8001) -> FastAPICybersecurityService:
    """Create and configure the linguistic analysis service"""
    try:
        from .linguistic_agent import LinguisticAnalysisCrew
        
        crew = LinguisticAnalysisCrew()
        return FastAPICybersecurityService(crew, "Linguistic Analysis", port)
    except ImportError as e:
        print(f"Error importing linguistic agent: {e}")
        # Fallback to mock service
        return create_mock_service("Linguistic Analysis", port)


def create_technical_service(port: int = 8002) -> FastAPICybersecurityService:
    """Create and configure the technical analysis service"""
    try:
        # from technical_agent import TechnicalAnalysisCrew
        # crew = TechnicalAnalysisCrew()
        # return FastAPICybersecurityService(crew, "Technical Analysis", port)
        
        # Placeholder until technical_agent.py is implemented
        return create_mock_service("Technical Analysis", port)
    except ImportError as e:
        print(f"Error importing technical agent: {e}")
        return create_mock_service("Technical Analysis", port)


def create_behavioral_service(port: int = 8003) -> FastAPICybersecurityService:
    """Create and configure the behavioral analysis service"""
    try:
        # from behavioral_agent import BehavioralAnalysisCrew
        # crew = BehavioralAnalysisCrew()
        # return FastAPICybersecurityService(crew, "Behavioral Analysis", port)
        
        # Placeholder until behavioral_agent.py is implemented
        return create_mock_service("Behavioral Analysis", port)
    except ImportError as e:
        print(f"Error importing behavioral agent: {e}")
        return create_mock_service("Behavioral Analysis", port)


def create_threat_intel_service(port: int = 8004) -> FastAPICybersecurityService:
    """Create and configure the threat intelligence service"""
    try:
        # from threat_intel_agent import ThreatIntelCrew
        # crew = ThreatIntelCrew()
        # return FastAPICybersecurityService(crew, "Threat Intelligence", port)
        
        # Placeholder until threat_intel_agent.py is implemented
        return create_mock_service("Threat Intelligence", port)
    except ImportError as e:
        print(f"Error importing threat intel agent: {e}")
        return create_mock_service("Threat Intelligence", port)


def create_coordination_service(port: int = 8005) -> FastAPICybersecurityService:
    """Create and configure the coordination service"""
    try:
        # from coordination_agent import CoordinationCrew
        # crew = CoordinationCrew()
        # return FastAPICybersecurityService(crew, "Coordination", port)
        
        # Placeholder until coordination_agent.py is implemented
        return create_mock_service("Coordination", port)
    except ImportError as e:
        print(f"Error importing coordination agent: {e}")
        return create_mock_service("Coordination", port)


def create_chatbot_service(port: int = 8006) -> FastAPICybersecurityService:
    """Create and configure the chatbot service"""
    try:
        # from chatbot_agent import ChatbotCrew
        # crew = ChatbotCrew()
        # return FastAPICybersecurityService(crew, "Chatbot", port)
        
        # Placeholder until chatbot_agent.py is implemented
        return create_mock_service("Chatbot", port)
    except ImportError as e:
        print(f"Error importing chatbot agent: {e}")
        return create_mock_service("Chatbot", port)


def create_mock_service(service_name: str, port: int) -> FastAPICybersecurityService:
    """Create a mock service for testing or when real agents aren't available"""
    
    class MockCrew:
        def __init__(self, name: str):
            self.crew_name = name
        
        async def process_request(self, data: Dict[str, Any]):
            return {
                "status": "mock_response",
                "service": self.crew_name,
                "message": f"This is a mock response from {self.crew_name}",
                "timestamp": "2024-01-01T00:00:00"
            }
        
        def health_check(self):
            return {
                "agent_name": self.crew_name,
                "version": "1.0.0",
                "status": "healthy",
                "timestamp": "2024-01-01T00:00:00",
                "capabilities": ["mock_analysis"],
                "crew_configured": True
            }
        
        def get_agent_info(self):
            return {
                "crew_name": self.crew_name,
                "version": "1.0.0",
                "capabilities": ["mock_analysis"],
                "note": "This is a mock service for testing"
            }
    
    mock_crew = MockCrew(service_name)
    return FastAPICybersecurityService(mock_crew, service_name, port)


def main():
    """Main entry point for running agent services"""
    
    parser = argparse.ArgumentParser(description="Run cybersecurity agent services")
    parser.add_argument(
        "agent_type",
        choices=[
            "linguistic", "technical", "behavioral", 
            "threat-intel", "coordination", "chatbot", "all"
        ],
        help="Type of agent to run"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to run the service on (defaults vary by agent type)"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development"
    )
    
    args = parser.parse_args()
    
    # Default ports for each agent type
    default_ports = {
        "linguistic": 8001,
        "technical": 8002,
        "behavioral": 8003,
        "threat-intel": 8004,
        "coordination": 8005,
        "chatbot": 8006
    }
    
    port = args.port or default_ports.get(args.agent_type, 8000)
    
    # Create and run the appropriate service
    service_creators = {
        "linguistic": create_linguistic_service,
        "technical": create_technical_service,
        "behavioral": create_behavioral_service,
        "threat-intel": create_threat_intel_service,
        "coordination": create_coordination_service,
        "chatbot": create_chatbot_service
    }
    
    if args.agent_type == "all":
        print("Starting all agent services...")
        print("Note: This will start multiple services. Use separate terminals for each agent.")
        for agent_type, creator in service_creators.items():
            default_port = default_ports[agent_type]
            print(f"To start {agent_type} agent: python service_runner.py {agent_type} --port {default_port}")
    else:
        print(f"Starting {args.agent_type} agent service on {args.host}:{port}")
        
        try:
            service = service_creators[args.agent_type](port)
            service.run(host=args.host, reload=args.reload)
        except KeyboardInterrupt:
            print(f"\n{args.agent_type} agent service stopped.")
        except Exception as e:
            print(f"Error starting {args.agent_type} agent service: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
