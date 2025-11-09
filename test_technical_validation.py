import asyncio
import json
from app.Agents.technical_validation_agent import TechnicalValidationCrew
from datetime import datetime

def test_technical_validation():
    # Initialize the technical validation crew
    crew = TechnicalValidationCrew()
    
    # Test cases with different types of emails
    test_cases = [
        {
            "name": "Phishing Email (New Domain)",
            "email_data": {
                "subject": "URGENT: Account Suspended - Verify Now",
                "body": """
                URGENT: Your account has been suspended!
                
                Click here to verify immediately: http://bit.ly/verify-now
                
                Failure to verify within 24 hours will result in permanent suspension.
                """,
                "sender": "security@suspicious-newsite.com",
                "recipients": ["user@example.com"],
                "date": datetime.now().isoformat(),
                "headers": {
                    "Return-Path": "<security@suspicious-newsite.com>",
                    "X-Originating-IP": "192.168.1.1"
                }
            }
        },
        {
            "name": "Legitimate Email (Established Domain)",
            "email_data": {
                "subject": "Team Meeting Next Week",
                "body": """
                Hi team,
                
                Just a reminder about our weekly team meeting next Tuesday at 10 AM.
                
                Agenda:
                1. Project updates
                2. Sprint planning
                3. Open discussion
                
                Best regards,
                John
                """,
                "sender": "john@google.com",
                "recipients": ["team@company.com"],
                "date": datetime.now().isoformat(),
                "headers": {
                    "Return-Path": "<john@google.com>",
                    "X-Originating-IP": "10.0.0.1"
                }
            }
        },
        {
            "name": "Email with Multiple External URLs",
            "email_data": {
                "subject": "Special Offers",
                "body": """
                Check out these links:
                - https://example.com/promo
                - https://bit.ly/special-offer
                - https://another-site.com/deals
                """,
                "sender": "marketing@company.com",
                "recipients": ["user@example.com"],
                "date": datetime.now().isoformat(),
                "headers": {
                    "Return-Path": "<marketing@company.com>",
                    "X-Originating-IP": "10.0.0.2"
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
            print("\nValidation Results:")
            if isinstance(result, dict):
                print(f"Status: {result.get('status')}")
                print(f"Confidence Score: {result.get('confidence_score', 0.0):.2f}")
                
                print("\nFindings:")
                for finding in result.get('findings', []):
                    print(f"- Type: {finding.get('type')}")
                    print(f"  Severity: {finding.get('severity')}")
                    print(f"  Confidence: {finding.get('confidence', 0.0):.2f}")
                    print(f"  Description: {finding.get('description')}")
                    if finding.get('evidence'):
                        print(f"  Evidence: {finding.get('evidence')}")
                
                print("\nRecommendations:")
                for rec in result.get('recommendations', []):
                    print(f"- {rec}")
                    
                print(f"\nProcessing Time: {result.get('processing_time', 0.0):.2f}s")
            else:
                print(f"Validation completed with result type: {type(result)}")
                print(f"Result: {result}")
            
        except Exception as e:
            print(f"Error processing test case: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    # Run the test
    test_technical_validation()

