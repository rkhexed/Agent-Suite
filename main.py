
#!/usr/bin/env python3
"""
Main entry point for the Agent Suite.
This can be used to run individual agents or start the entire system.
"""

import sys
import os
import asyncio
from typing import Dict, Any

# Add the app directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.Agents.service_runner import (
    create_linguistic_service,
    create_technical_service,
    create_behavioral_service,
    create_threat_intel_service,
    create_coordination_service,
    create_chatbot_service
)


async def test_linguistic_agent():
    """Test the linguistic analysis agent with sample data"""
    print("Testing Linguistic Analysis Agent...")
    
    # Create the service
    service = create_linguistic_service(port=8001)
    
    # Sample email data for testing
    test_request = {
        "email_data": {
            "subject": "URGENT: Verify Your Account Immediately",
            "content": """
            Dear Customer,
            
            We have detected suspicious activity on your account. To prevent suspension, 
            please verify your identity by clicking the link below within 24 hours:
            
            https://bit.ly/verify-account-now
            
            If you do not verify your account, it will be permanently suspended.
            
            Best regards,
            Security Team
            """,
            "sender": "security@fake-bank.com",
            "recipient": "user@example.com"
        },
        "metadata": {
            "source": "test_suite",
            "priority": "high"
        },
        "request_id": "test_001"
    }
    
    try:
        # Test the crew directly
        crew = service.crew.crew
        response = await crew.process_request(test_request)
        print(f"Analysis Result: {response}")
        
    except Exception as e:
        print(f"Error testing linguistic agent: {e}")


def show_service_endpoints():
    """Display available service endpoints for n8n integration"""
    print("\n" + "="*60)
    print("CYBERSECURITY AGENT SERVICES - N8N INTEGRATION")
    print("="*60)
    print("\nEach agent runs as a separate FastAPI service that n8n can call via HTTP:")
    print("\n1. LINGUISTIC ANALYSIS SERVICE (Port 8001)")
    print("   - Endpoint: http://localhost:8001/analyze")
    print("   - Purpose: NLP analysis, sentiment detection, social engineering")
    print("   - Start: python main.py linguistic")
    
    print("\n2. TECHNICAL ANALYSIS SERVICE (Port 8002)")
    print("   - Endpoint: http://localhost:8002/analyze")
    print("   - Purpose: Email header analysis, forensics, technical indicators")
    print("   - Start: python main.py technical")
    
    print("\n3. BEHAVIORAL ANALYSIS SERVICE (Port 8003)")
    print("   - Endpoint: http://localhost:8003/analyze")
    print("   - Purpose: Pattern analysis, behavioral indicators")
    print("   - Start: python main.py behavioral")
    
    print("\n4. THREAT INTELLIGENCE SERVICE (Port 8004)")
    print("   - Endpoint: http://localhost:8004/analyze")
    print("   - Purpose: Threat feed integration, IOCs, reputation analysis")
    print("   - Start: python main.py threat-intel")
    
    print("\n5. COORDINATION SERVICE (Port 8005)")
    print("   - Endpoint: http://localhost:8005/analyze")
    print("   - Purpose: Decision fusion, result aggregation")
    print("   - Start: python main.py coordination")
    
    print("\n6. CHATBOT SERVICE (Port 8006)")
    print("   - Endpoint: http://localhost:8006/analyze")
    print("   - Purpose: General purpose interface, email drafting, action reversal")
    print("   - Start: python main.py chatbot")
    
    print("\n" + "="*60)
    print("COMMON ENDPOINTS FOR ALL SERVICES:")
    print("="*60)
    print("POST /analyze     - Main analysis endpoint (n8n will call this)")
    print("POST /process     - Alternative endpoint name")
    print("GET  /health      - Health check for monitoring")
    print("GET  /info        - Agent capabilities and information")
    print("GET  /            - Service status")
    
    print("\n" + "="*60)
    print("N8N WORKFLOW INTEGRATION:")
    print("="*60)
    print("1. Use HTTP Request nodes in n8n to call each agent")
    print("2. Send POST requests to /analyze endpoint with email data")
    print("3. Each agent returns standardized JSON response")
    print("4. Use n8n's conditional logic to route based on results")
    print("5. Aggregate results from multiple agents in coordination service")
    
    print("\n" + "="*60)
    print("SAMPLE REQUEST FORMAT:")
    print("="*60)
    sample_request = {
        "email_data": {
            "subject": "Email subject here",
            "content": "Email body content here",
            "sender": "sender@example.com",
            "recipient": "recipient@example.com",
            "headers": {},
            "attachments": []
        },
        "metadata": {
            "source": "n8n_workflow",
            "priority": "normal"
        },
        "request_id": "n8n_request_001"
    }
    print(f"Request Body: {sample_request}")
    
    print("\n" + "="*60)
    print("SAMPLE RESPONSE FORMAT:")
    print("="*60)
    sample_response = {
        "agent_name": "Linguistic Analysis Crew",
        "request_id": "n8n_request_001",
        "status": "success",
        "confidence_score": 0.85,
        "findings": [
            {
                "type": "suspicious_pattern",
                "severity": "medium",
                "confidence": 0.8,
                "description": "Urgency indicators detected"
            }
        ],
        "recommendations": [
            "Review email content carefully",
            "Verify sender identity"
        ],
        "processing_time": 2.5,
        "timestamp": "2024-01-01T12:00:00"
    }
    print(f"Response: {sample_response}")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        show_service_endpoints()
        print("\nUsage examples:")
        print("  python main.py test-all         # Run comprehensive tests")
        print("  python main.py test-linguistic  # Test linguistic agent")
        print("  python main.py show-endpoints   # Show this help")
        print("  python main.py linguistic       # Start linguistic service")
        print("  python main.py technical        # Start technical service")
        print("  python main.py all-services     # Show all service commands")
        return
    
    command = sys.argv[1].lower()
    
    if command == "test-linguistic":
        asyncio.run(test_linguistic_agent())
    
    elif command == "test-all":
        print("Running simple tests...")
        import subprocess
        result = subprocess.run([sys.executable, "simple_test.py"], capture_output=False)
        return
    
    elif command == "show-endpoints":
        show_service_endpoints()
    
    elif command == "all-services":
        print("To start all services, run each in separate terminals:")
        print("  python main.py linguistic")
        print("  python main.py technical")
        print("  python main.py behavioral")
        print("  python main.py threat-intel")
        print("  python main.py coordination")
        print("  python main.py chatbot")
    
    elif command == "linguistic":
        service = create_linguistic_service(port=8001)
        print("Starting Linguistic Analysis Service on port 8001...")
        service.run(host="0.0.0.0", reload=True)
    
    elif command == "technical":
        service = create_technical_service(port=8002)
        print("Starting Technical Analysis Service on port 8002...")
        service.run(host="0.0.0.0", reload=True)
    
    elif command == "behavioral":
        service = create_behavioral_service(port=8003)
        print("Starting Behavioral Analysis Service on port 8003...")
        service.run(host="0.0.0.0", reload=True)
    
    elif command == "threat-intel":
        service = create_threat_intel_service(port=8004)
        print("Starting Threat Intelligence Service on port 8004...")
        service.run(host="0.0.0.0", reload=True)
    
    elif command == "coordination":
        service = create_coordination_service(port=8005)
        print("Starting Coordination Service on port 8005...")
        service.run(host="0.0.0.0", reload=True)
    
    elif command == "chatbot":
        service = create_chatbot_service(port=8006)
        print("Starting Chatbot Service on port 8006...")
        service.run(host="0.0.0.0", reload=True)
    
    else:
        print(f"Unknown command: {command}")
        print("Available commands: test-linguistic, show-endpoints, all-services")
        print("Service commands: linguistic, technical, behavioral, threat-intel, coordination, chatbot")


if __name__ == "__main__":
    main()