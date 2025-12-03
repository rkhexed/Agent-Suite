#!/usr/bin/env python3
"""
Test script for Multi-Agent Email Security API
Tests all 4 agent endpoints with sample phishing email
"""

import requests
import json
import time

# API base URL
BASE_URL = "http://localhost:8000"

# Sample phishing email for testing
PHISHING_EMAIL = {
    "email_id": "test_001",
    "subject": "URGENT: Verify Your Account Immediately",
    "sender": "security@paypa1-verify.com",
    "recipient": "user@example.com",
    "body": """
    Dear Valued Customer,
    
    We have detected suspicious activity on your PayPal account. 
    Your account will be SUSPENDED within 24 hours if you do not verify your identity immediately.
    
    Click here to verify: http://bit.ly/paypal-verify-now
    
    Failure to comply will result in permanent account closure and loss of funds.
    
    Urgent Action Required - Do Not Delay!
    
    Security Department
    PayPal Inc.
    """,
    "headers": {
        "From": "security@paypa1-verify.com",
        "To": "user@example.com",
        "Subject": "URGENT: Verify Your Account Immediately"
    },
    "metadata": {
        "source": "test_script"
    }
}


def test_health_check():
    """Test health check endpoint"""
    print("\n" + "="*60)
    print("1. TESTING HEALTH CHECK ENDPOINT")
    print("="*60)
    
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False


def test_linguistic_agent():
    """Test linguistic analysis endpoint"""
    print("\n" + "="*60)
    print("2. TESTING LINGUISTIC ANALYSIS AGENT")
    print("="*60)
    
    try:
        print("Sending phishing email for analysis...")
        start = time.time()
        
        response = requests.post(
            f"{BASE_URL}/api/linguistic/analyze",
            json=PHISHING_EMAIL,
            timeout=60
        )
        
        elapsed = time.time() - start
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {elapsed:.2f}s")
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Analysis Complete!")
            print(f"  Agent: {result.get('agent')}")
            print(f"  Risk Score: {result.get('risk_score')}")
            print(f"  Threat Level: {result.get('threat_level')}")
            print(f"  Confidence: {result.get('confidence')}")
            print(f"  Indicators: {result.get('indicators', [])[:3]}")  # First 3
            print(f"  Analysis: {result.get('analysis', '')[:200]}...")  # First 200 chars
            return True
        else:
            print(f"❌ Failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Linguistic analysis failed: {e}")
        return False


def test_technical_agent():
    """Test technical validation endpoint"""
    print("\n" + "="*60)
    print("3. TESTING TECHNICAL VALIDATION AGENT")
    print("="*60)
    
    try:
        print("Sending email for technical analysis...")
        start = time.time()
        
        response = requests.post(
            f"{BASE_URL}/api/technical/analyze",
            json=PHISHING_EMAIL,
            timeout=60
        )
        
        elapsed = time.time() - start
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {elapsed:.2f}s")
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Analysis Complete!")
            print(f"  Agent: {result.get('agent')}")
            print(f"  Risk Score: {result.get('risk_score')}")
            print(f"  Threat Level: {result.get('threat_level')}")
            print(f"  Confidence: {result.get('confidence')}")
            print(f"  Indicators: {result.get('indicators', [])[:3]}")
            return True
        else:
            print(f"❌ Failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Technical analysis failed: {e}")
        return False


def test_threat_intel_agent():
    """Test threat intelligence endpoint"""
    print("\n" + "="*60)
    print("4. TESTING THREAT INTELLIGENCE AGENT")
    print("="*60)
    
    try:
        print("Sending email for threat intel analysis...")
        start = time.time()
        
        response = requests.post(
            f"{BASE_URL}/api/threat-intel/analyze",
            json=PHISHING_EMAIL,
            timeout=60
        )
        
        elapsed = time.time() - start
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {elapsed:.2f}s")
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Analysis Complete!")
            print(f"  Agent: {result.get('agent')}")
            print(f"  Risk Score: {result.get('risk_score')}")
            print(f"  Threat Level: {result.get('threat_level')}")
            print(f"  Confidence: {result.get('confidence')}")
            print(f"  Indicators: {result.get('indicators', [])[:3]}")
            return True
        else:
            print(f"❌ Failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Threat intel analysis failed: {e}")
        return False


def test_coordination_agent(ling_result, tech_result, threat_result):
    """Test coordination endpoint with real agent results"""
    print("\n" + "="*60)
    print("5. TESTING COORDINATION AGENT")
    print("="*60)
    
    try:
        print("Sending aggregated results to coordination agent...")
        start = time.time()
        
        coordination_request = {
            "email_id": "test_001",
            "linguistic_result": ling_result,
            "technical_result": tech_result,
            "threat_intel_result": threat_result,
            "email_data": {
                "subject": PHISHING_EMAIL["subject"],
                "sender": PHISHING_EMAIL["sender"],
                "body": PHISHING_EMAIL["body"]
            }
        }
        
        response = requests.post(
            f"{BASE_URL}/api/coordination/analyze",
            json=coordination_request,
            timeout=60
        )
        
        elapsed = time.time() - start
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {elapsed:.2f}s")
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ Coordination Complete!")
            print(f"  Agent: {result.get('agent')}")
            print(f"  Final Risk Score: {result.get('risk_score')}")
            print(f"  Final Threat Level: {result.get('threat_level')}")
            print(f"  Confidence: {result.get('confidence')}")
            print(f"  Analysis: {result.get('analysis', '')[:200]}...")
            return True
        else:
            print(f"❌ Failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Coordination failed: {e}")
        return False


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("MULTI-AGENT EMAIL SECURITY API - TEST SUITE")
    print("="*60)
    print(f"API URL: {BASE_URL}")
    print(f"Test Email: Simulated PayPal phishing attempt")
    
    results = []
    
    # Test 1: Health Check
    results.append(("Health Check", test_health_check()))
    time.sleep(1)
    
    # Test 2: Linguistic Agent
    ling_success = False
    ling_result = None
    try:
        response = requests.post(f"{BASE_URL}/api/linguistic/analyze", json=PHISHING_EMAIL, timeout=60)
        if response.status_code == 200:
            ling_result = response.json()
            ling_success = True
    except:
        pass
    results.append(("Linguistic Agent", ling_success))
    time.sleep(1)
    
    # Test 3: Technical Agent
    tech_success = False
    tech_result = None
    try:
        response = requests.post(f"{BASE_URL}/api/technical/analyze", json=PHISHING_EMAIL, timeout=60)
        if response.status_code == 200:
            tech_result = response.json()
            tech_success = True
    except:
        pass
    results.append(("Technical Agent", tech_success))
    time.sleep(1)
    
    # Test 4: Threat Intel Agent
    threat_success = False
    threat_result = None
    try:
        response = requests.post(f"{BASE_URL}/api/threat-intel/analyze", json=PHISHING_EMAIL, timeout=60)
        if response.status_code == 200:
            threat_result = response.json()
            threat_success = True
    except:
        pass
    results.append(("Threat Intel Agent", threat_success))
    time.sleep(1)
    
    # Test 5: Coordination Agent (only if we have all 3 results)
    if ling_result and tech_result and threat_result:
        coord_success = test_coordination_agent(ling_result, tech_result, threat_result)
        results.append(("Coordination Agent", coord_success))
    else:
        print("\n⚠️  Skipping coordination test - missing agent results")
        results.append(("Coordination Agent", False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    total = len(results)
    passed = sum(1 for _, success in results if success)
    print(f"\nTotal: {passed}/{total} tests passed ({(passed/total)*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 All tests passed! API is working correctly.")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Check logs for details.")


if __name__ == "__main__":
    main()
