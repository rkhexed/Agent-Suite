import asyncio
import json
import os
from dotenv import load_dotenv
from app.Agents.threat_intel_agent import ThreatIntelligenceCrew
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

def test_threat_intelligence():
    # Initialize the threat intelligence crew
    crew = ThreatIntelligenceCrew()
    
    # Test cases with different types of emails
    test_cases = [
        {
            "name": "Phishing Email with Suspicious URL",
            "email_data": {
                "subject": "URGENT: Verify Your Account",
                "body": """
                Dear Customer,
                
                Your account will be suspended unless you verify immediately.
                
                Click here: http://malware.testing.google.test/testing/malware/
                
                This is urgent! Act now to avoid account closure.
                """,
                "sender": "security@suspicious-bank.com",
                "recipients": ["user@example.com"],
                "date": datetime.now().isoformat(),
                "headers": {
                    "Return-Path": "<security@suspicious-bank.com>",
                    "X-Originating-IP": "185.220.101.50"  # Known malicious IP for testing
                }
            }
        },
        {
            "name": "Legitimate Email from Trusted Domain",
            "email_data": {
                "subject": "Weekly Team Update",
                "body": """
                Hi team,
                
                Here's our weekly update. Check out the latest metrics:
                https://google.com/analytics
                
                Great work everyone!
                """,
                "sender": "manager@company.com",
                "recipients": ["team@company.com"],
                "date": datetime.now().isoformat(),
                "headers": {
                    "Return-Path": "<manager@company.com>",
                    "X-Originating-IP": "8.8.8.8"  # Google DNS - safe IP
                }
            }
        },
        {
            "name": "Email with Multiple URLs",
            "email_data": {
                "subject": "Check out these offers!",
                "body": """
                Amazing deals:
                - https://amazon.com/deals
                - https://ebay.com/specials  
                - http://bit.ly/random-link
                
                Don't miss out!
                """,
                "sender": "promotions@marketing.com",
                "recipients": ["user@example.com"],
                "date": datetime.now().isoformat(),
                "headers": {
                    "Return-Path": "<promotions@marketing.com>",
                    "X-Originating-IP": "192.168.1.100"
                }
            }
        },
        {
            "name": "Email with No URLs (Text Only)",
            "email_data": {
                "subject": "Meeting Tomorrow",
                "body": """
                Hi everyone,
                
                Just a reminder about tomorrow's meeting at 2 PM.
                Please bring your reports.
                
                Thanks,
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
            print("\nThreat Intelligence Results:")
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
                        print(f"  Evidence:")
                        for evidence in finding.get('evidence'):
                            print(f"    • {evidence}")
                
                print("\nRecommendations:")
                for rec in result.get('recommendations', []):
                    print(f"- {rec}")
                    
                print(f"\nProcessing Time: {result.get('processing_time', 0.0):.2f}s")
            else:
                print(f"Analysis completed with result type: {type(result)}")
                print(f"Result: {result}")
            
        except Exception as e:
            print(f"Error processing test case: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    print("=" * 50)
    print("Threat Intelligence Agent Test Suite")
    print("=" * 50)
    print("\nNOTE: This test requires API keys:")
    print("- GOOGLE_SAFE_BROWSING_API_KEY")
    print("- ABUSEIPDB_API_KEY")
    print("\nSet them in your .env file before running.")
    print("=" * 50)
    
    # Run the test
    test_threat_intelligence()
