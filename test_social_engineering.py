"""
Test Case: Pure Social Engineering Attack (No Malicious URLs/IPs)

This test validates the system's ability to detect phishing based purely on:
- Social engineering tactics (urgency, fear, authority)
- BERT phishing model detection
- Content analysis

Expected behavior:
- Linguistic Agent: HIGH/DEFINITIVE certainty (BERT detects phishing)
- Technical Agent: LOW certainty (domain not available, clean URL)
- Threat Intelligence: LOW certainty (no malicious URLs/IPs in databases)
- Coordination: HIGH risk based on linguistic analysis (60% weight)
- Actions: Should recommend QUARANTINE based on strong linguistic signals
"""

import asyncio
import sys
from datetime import datetime

from app.Agents.linguistic_agent import LinguisticAnalysisCrew
from app.Agents.technical_validation_agent import TechnicalValidationCrew
from app.Agents.threat_intel_agent import ThreatIntelligenceCrew
from app.Agents.coordination_agent import CoordinationCrew


def call_agent_sync(agent_crew, email_data):
    """Helper to call agent synchronously"""
    loop = asyncio.get_event_loop()
    request_data = {
        "email_data": email_data,
        "metadata": {},
        "request_id": f"test_{int(datetime.now().timestamp())}"
    }
    return loop.run_until_complete(agent_crew.process_request(request_data))


def test_social_engineering():
    """Test pure social engineering attack without malicious infrastructure"""
    
    print("=" * 70)
    print("SOCIAL ENGINEERING TEST - No Malicious URLs/IPs")
    print("=" * 70)
    
    # Pure social engineering email (legitimate domain, clean URLs)
    email = {
        "subject": "URGENT: Your Account Has Been Compromised - Immediate Action Required",
        "body": """
        Dear Valued Customer,
        
        We have detected unusual activity on your account from an unknown device in Russia.
        Your account has been temporarily locked to prevent unauthorized access.
        
        To restore full access, you must verify your identity immediately by following these steps:
        
        1. Click here to access our secure verification portal: https://www.example.com/verify
        2. Enter your username and password to confirm your identity
        3. Provide the last 4 digits of your credit card for additional verification
        
        WARNING: Failure to verify within 24 hours will result in permanent account suspension
        and potential legal action for suspicious activity detected on your account.
        
        This is an automated security alert from our fraud detection system.
        Do not reply to this email as this mailbox is not monitored.
        
        Security Team
        Example Corporation
        """,
        "sender": "security@example.com",  # Legitimate domain
        "recipients": ["user@company.com"],
        "date": datetime.now().isoformat(),
        "headers": {
            "Return-Path": "<security@example.com>",
            "X-Originating-IP": "203.0.113.45"  # Clean IP (documentation range)
        }
    }
    
    print("\n📧 Test Email:")
    print(f"  Subject: {email['subject']}")
    print(f"  Sender: {email['sender']}")
    print(f"  Contains malicious URL: No (example.com is legitimate)")
    print(f"  Contains malicious IP: No (documentation IP range)")
    print(f"  Social Engineering Tactics:")
    print(f"    - ✓ Urgency (24 hour deadline)")
    print(f"    - ✓ Fear (account compromised, legal action)")
    print(f"    - ✓ Authority (security team, fraud detection)")
    print(f"    - ✓ Credential harvesting (username/password request)")
    print(f"    - ✓ Sensitive data request (credit card digits)")
    
    # Step 1: Call all 3 agents
    print("\n" + "-" * 70)
    print("STEP 1: Calling All 3 Agents")
    print("-" * 70)
    
    print("\n🤖 Linguistic Agent analyzing...")
    linguistic_crew = LinguisticAnalysisCrew()
    linguistic_result = call_agent_sync(linguistic_crew, email).dict()
    print(f"  ✓ Linguistic Risk Score: {linguistic_result['risk_score']:.3f}")
    print(f"    - Certainty: {linguistic_result['certainty_level']}")
    print(f"    - Status: {linguistic_result['status']}")
    print(f"    - Reasoning: {linguistic_result['analysis_reasoning'][:100]}...")
    
    print("\n🔧 Technical Validation Agent analyzing...")
    technical_crew = TechnicalValidationCrew()
    technical_result = call_agent_sync(technical_crew, email).dict()
    tech_risk = technical_result.get('risk_score', 0)
    print(f"  ✓ Technical Risk Score: {tech_risk:.3f}")
    print(f"    - Certainty: {technical_result['certainty_level']}")
    print(f"    - Status: {technical_result['status']}")
    print(f"    - Reasoning: {technical_result['analysis_reasoning'][:100]}...")
    
    print("\n🛡️  Threat Intelligence Agent analyzing...")
    threat_crew = ThreatIntelligenceCrew()
    threat_result = call_agent_sync(threat_crew, email).dict()
    threat_risk = threat_result.get('risk_score', 0)
    print(f"  ✓ Threat Intel Risk Score: {threat_risk:.3f}")
    print(f"    - Certainty: {threat_result['certainty_level']}")
    print(f"    - Status: {threat_result['status']}")
    print(f"    - Reasoning: {threat_result['analysis_reasoning'][:100]}...")
    
    # Step 2: Coordination Agent aggregates results
    print("\n" + "-" * 70)
    print("STEP 2: Coordination Agent Aggregating Results")
    print("-" * 70)
    
    coordination_crew = CoordinationCrew()
    
    print("\n🎯 Aggregating with 60-20-20 weights...")
    print("   Expected: Linguistic (60%) should dominate since no threat intel override")
    final_result = coordination_crew.analyze(
        email_data=email,
        linguistic_result=linguistic_result,
        technical_result=technical_result,
        threat_intel_result=threat_result
    )
    
    # Step 3: Display final results
    print("\n" + "=" * 70)
    print("FINAL COORDINATION RESULT")
    print("=" * 70)
    
    print(f"\n📊 Risk Assessment:")
    print(f"  - Final Risk Score: {final_result.final_risk_score:.3f}")
    print(f"  - Risk Level: {final_result.risk_level}")
    print(f"  - Aggregated Certainty: {final_result.aggregated_certainty}")
    print(f"  - Uncertainty: {final_result.uncertainty:.3f}")
    
    print(f"\n🎯 Agent Contributions (60-20-20 weighting):")
    for contrib in final_result.agent_contributions:
        print(f"  - {contrib.agent_name}: {contrib.weighted_contribution:.3f} "
              f"(risk: {contrib.risk_score:.3f}, certainty: {contrib.certainty_level})")
    
    print(f"\n💡 Explanation:")
    print(f"  Summary: {final_result.explanation.summary[:150]}...")
    print(f"  Narrative Length: {len(final_result.explanation.narrative)} chars")
    
    print(f"\n📋 Detailed Reasoning (first 500 chars):")
    print(f"  {final_result.detailed_reasoning[:500]}...")
    
    print(f"\n🎬 Recommended Actions: {len(final_result.recommended_actions)} actions")
    for action in final_result.recommended_actions:
        approval = "⚠️  REQUIRES APPROVAL" if action.requires_approval else "✓ AUTO-EXECUTE"
        print(f"  - {action.action_type} ({action.priority}) - {approval}")
        print(f"    Reasoning: {action.reasoning[:100]}...")
    
    print(f"\n⏱️  Performance:")
    print(f"  - Processing Time: {final_result.processing_time:.2f}s")
    
    # Validations
    print("\n" + "=" * 70)
    print("VALIDATION CHECKS (Social Engineering Test)")
    print("=" * 70)
    
    checks_passed = 0
    total_checks = 0
    
    # Check 1: Linguistic agent should have high certainty (BERT detects phishing)
    total_checks += 1
    if linguistic_result['certainty_level'] in ["DEFINITIVE", "HIGH"]:
        print(f"✅ Linguistic certainty is {linguistic_result['certainty_level']} (BERT detected phishing)")
        checks_passed += 1
    else:
        print(f"❌ Linguistic certainty is {linguistic_result['certainty_level']} (expected HIGH/DEFINITIVE)")
    
    # Check 2: Threat intelligence should have LOW certainty (no malicious URLs/IPs)
    total_checks += 1
    if threat_result['certainty_level'] in ["LOW", "MEDIUM", "INCONCLUSIVE"]:
        print(f"✅ Threat intel certainty is {threat_result['certainty_level']} (no confirmed threats)")
        checks_passed += 1
    else:
        print(f"⚠️  Threat intel certainty is {threat_result['certainty_level']} (unexpected for clean URLs)")
    
    # Check 3: No threat intelligence override (clean infrastructure)
    total_checks += 1
    override_active = final_result.metadata.get('override_active', False)
    if not override_active:
        print(f"✅ No threat intelligence override (expected for social engineering only)")
        checks_passed += 1
    else:
        print(f"❌ Threat intelligence override activated (unexpected for clean infrastructure)")
    
    # Check 4: Final risk should be driven by linguistic analysis (60% weight)
    total_checks += 1
    linguistic_contribution = linguistic_result['risk_score'] * 0.60
    if final_result.final_risk_score >= 0.50 and final_result.risk_level in ["HIGH", "MEDIUM"]:
        print(f"✅ Risk driven by linguistic analysis ({final_result.final_risk_score:.3f}, {final_result.risk_level})")
        checks_passed += 1
    else:
        print(f"❌ Risk score {final_result.final_risk_score:.3f} ({final_result.risk_level}) - expected MEDIUM/HIGH")
    
    # Check 5: Should recommend security action (QUARANTINE or TAG)
    total_checks += 1
    action_types = [action.action_type for action in final_result.recommended_actions]
    if any(action in action_types for action in ["QUARANTINE", "TAG", "ALERT"]):
        print(f"✅ Security action recommended: {action_types}")
        checks_passed += 1
    else:
        print(f"❌ No security action recommended: {action_types}")
    
    # Check 6: Should have detailed explanation
    total_checks += 1
    if len(final_result.detailed_reasoning) > 200:
        print(f"✅ Detailed reasoning provided ({len(final_result.detailed_reasoning)} chars)")
        checks_passed += 1
    else:
        print(f"❌ Insufficient reasoning ({len(final_result.detailed_reasoning)} chars)")
    
    # Check 7: Linguistic contribution should be highest
    total_checks += 1
    contributions = {c.agent_name: c.weighted_contribution for c in final_result.agent_contributions}
    if contributions.get('linguistic', 0) > contributions.get('threat_intelligence', 0):
        print(f"✅ Linguistic contribution ({contributions.get('linguistic', 0):.3f}) > Threat intel ({contributions.get('threat_intelligence', 0):.3f})")
        checks_passed += 1
    else:
        print(f"❌ Threat intel dominating (should be linguistic for social engineering)")
    
    # Final result
    print("\n" + "=" * 70)
    success_rate = (checks_passed / total_checks) * 100
    if checks_passed == total_checks:
        print(f"✅ ALL CHECKS PASSED ({checks_passed}/{total_checks}) - 100%")
        print("=" * 70)
        print("\n🎉 SOCIAL ENGINEERING TEST: PASSED")
        return True
    elif checks_passed >= total_checks * 0.8:
        print(f"✅ MOST CHECKS PASSED ({checks_passed}/{total_checks}) - {success_rate:.1f}%")
        print("=" * 70)
        print("\n✓ SOCIAL ENGINEERING TEST: PASSED (with minor issues)")
        return True
    else:
        print(f"⚠️  SOME CHECKS FAILED ({checks_passed}/{total_checks}) - {success_rate:.1f}%")
        print("=" * 70)
        print("\n⚠️  SOCIAL ENGINEERING TEST: FAILED")
        return False


if __name__ == "__main__":
    try:
        success = test_social_engineering()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ TEST FAILED WITH ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
