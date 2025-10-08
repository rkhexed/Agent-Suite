import asyncio
import json
from app.Agents.linguistic_agent import LinguisticAnalysisCrew
from datetime import datetime

def test_linguistic_analysis():
    # Initialize the linguistic analysis crew
    crew = LinguisticAnalysisCrew()
    
    # Test cases with different types of emails
    test_cases = [
        {
            "name": "Phishing Attempt",
            "email_data": {
                "subject": "URGENT: Your Account Will Be Suspended",
                "body": """
                Dear Valued Customer,
                
                We have detected unusual activity in your account. Your account will be suspended 
                within 24 hours unless you verify your information immediately.
                
                Click here to verify: https://suspicious-looking-link.com/verify
                
                Note: Failure to verify will result in permanent account suspension.
                
                Best regards,
                Security Team
                """,
                "sender": "security@suspicious-bank.com",
                "recipients": ["user@example.com"],
                "date": datetime.now().isoformat(),
                "headers": {
                    "Return-Path": "<bounce@suspicious-bank.com>",
                    "X-Originating-IP": "192.168.1.1"
                }
            }
        },
        {
            "name": "Legitimate Email",
            "email_data": {
                "subject": "Team Meeting Next Week",
                "body": """
                Hi team,
                
                Just a reminder about our weekly team meeting next Tuesday at 10 AM.
                
                Agenda:
                1. Project updates
                2. Sprint planning
                3. Open discussion
                
                Please prepare your updates beforehand.
                
                Best regards,
                John
                """,
                "sender": "john@company.com",
                "recipients": ["team@company.com"],
                "date": datetime.now().isoformat(),
                "headers": {
                    "Return-Path": "<john@company.com>",
                    "X-Originating-IP": "10.0.0.1"
                }
            }
        }
    ]
    
    # Process each test case
    for test_case in test_cases:
        print(f"\nAnalyzing: {test_case['name']}")
        print("-" * 50)
        
        request = {
            "email_data": test_case["email_data"],
            "metadata": {"test_case": test_case["name"]},
            "request_id": f"test_{datetime.now().timestamp()}"
        }
        
        try:
            # Process the email
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            result = loop.run_until_complete(crew.process_request(request))
            
            # Print results in a readable format
            print("\nAnalysis Results:")
            if isinstance(result, dict):
                print(f"Threat Level: {result.get('threat_level')}")
                print(f"Confidence Score: {result.get('confidence_score', 0.0):.2f}")
                
                print("\nFindings:")
                for finding in result.get('findings', []):
                    print(f"- Type: {finding.get('type')}")
                    print(f"  Severity: {finding.get('severity')}")
                    print(f"  Confidence: {finding.get('confidence', 0.0):.2f}")
                    print(f"  Description: {finding.get('description')}")
                
                print("\nRecommendations:")
                for rec in result.get('recommendations', []):
                    print(f"- {rec}")
            else:
                print(f"Analysis completed with result type: {type(result)}")
                print(f"Result: {result}")
            
        except Exception as e:
            print(f"Error processing test case: {str(e)}")

if __name__ == "__main__":
    # Run the test
    test_linguistic_analysis()