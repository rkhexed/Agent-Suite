"""
Simplified Coordination Agent Test - Single comprehensive test
Avoids Groq rate limits by running just 1 test case
"""
import sys
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Load environment variables
load_dotenv()

from app.Agents.linguistic_agent import LinguisticAnalysisCrew
from app.Agents.technical_validation_agent import TechnicalValidationCrew
from app.Agents.threat_intel_agent import ThreatIntelligenceCrew
from app.Agents.coordination_agent import CoordinationCrew


def call_agent_sync(agent_crew, email_data):
    """Helper to call agent synchronously"""
    import asyncio
    loop = asyncio.get_event_loop()
    request = {"email_data": email_data, "metadata": {}}
    result = loop.run_until_complete(agent_crew.process_request(request))
    return result


def test_coordination_end_to_end():
    """
    Single comprehensive test: HIGH risk phishing email
    Tests complete workflow: n8n → 3 agents → coordination → actions
    """
    print("\n" + "=" * 70)
    print("COORDINATION AGENT - END-TO-END TEST")
    print("=" * 70)
    
    # High-risk phishing email with multiple indicators
    email = {
        "subject": "URGENT: Verify Your Account NOW",
        "body": """
        Dear Customer,
        
        Your account will be suspended unless you verify immediately.
        Click here: http://malware.testing.google.test/testing/malware/
        
        This is urgent! Act now to avoid account closure.
        """,
        "sender": "security@suspicious-newsite.com",
        "recipients": ["user@example.com"],
        "date": datetime.now().isoformat(),
        "headers": {
            "Return-Path": "<security@suspicious-newsite.com>",
            "X-Originating-IP": "185.220.101.50"  # Known malicious IP
        }
    }
    
    print("\n📧 Test Email:")
    print(f"  Subject: {email['subject']}")
    print(f"  Sender: {email['sender']}")
    print(f"  Has malware URL: Yes")
    print(f"  Suspicious IP: {email['headers']['X-Originating-IP']}")
    
    # Step 1: Call all 3 agents (simulating n8n parallel calls)
    print("\n" + "-" * 70)
    print("STEP 1: Calling All 3 Agents (n8n Parallel Workflow)")
    print("-" * 70)
    
    print("\n🤖 Linguistic Agent analyzing...")
    linguistic_crew = LinguisticAnalysisCrew()
    linguistic_result = call_agent_sync(linguistic_crew, email).dict()
    print(f"  ✓ Linguistic Risk Score: {linguistic_result['risk_score']:.3f}")
    print(f"    - Certainty: {linguistic_result['certainty_level']}")
    print(f"    - Status: {linguistic_result['status']}")
    print(f"    - Findings: {len(linguistic_result.get('findings', []))}")
    
    print("\n🔧 Technical Validation Agent analyzing...")
    technical_crew = TechnicalValidationCrew()
    technical_result = call_agent_sync(technical_crew, email).dict()
    tech_risk = technical_result.get('risk_score', 0)
    print(f"  ✓ Technical Risk Score: {tech_risk:.3f}")
    print(f"    - Certainty: {technical_result['certainty_level']}")
    print(f"    - Status: {technical_result['status']}")
    print(f"    - Findings: {len(technical_result.get('findings', []))}")
    
    print("\n🛡️  Threat Intelligence Agent analyzing...")
    threat_crew = ThreatIntelligenceCrew()
    threat_result = call_agent_sync(threat_crew, email).dict()
    threat_risk = threat_result.get('risk_score', 0)
    print(f"  ✓ Threat Intel Risk Score: {threat_risk:.3f}")
    print(f"    - Certainty: {threat_result['certainty_level']}")
    print(f"    - Status: {threat_result['status']}")
    print(f"    - Findings: {len(threat_result.get('findings', []))}")
    
    # Step 2: Coordination Agent aggregates results
    print("\n" + "-" * 70)
    print("STEP 2: Coordination Agent Aggregating Results")
    print("-" * 70)
    
    coordination_crew = CoordinationCrew()
    
    print("\n🎯 Aggregating with 60-20-20 weights...")
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
    print(f"  Key Findings: {len(final_result.explanation.key_findings)} findings")
    print(f"  Top Indicators: {len(final_result.explanation.top_indicators)} indicators")
    
    if final_result.explanation.key_findings:
        print(f"\n  📋 Top 3 Findings:")
        for finding in final_result.explanation.key_findings[:3]:
            print(f"    {finding}")
    
    print(f"\n🎬 Recommended Actions: {len(final_result.recommended_actions)} actions")
    for action in final_result.recommended_actions:
        approval = "⚠️  REQUIRES APPROVAL" if action.requires_approval else "✓ AUTO-EXECUTE"
        print(f"  - {action.action_type} ({action.priority}) - {approval}")
        print(f"    Reasoning: {action.reasoning[:80]}...")
    
    print(f"\n⏱️  Performance:")
    print(f"  - Processing Time: {final_result.processing_time:.2f}s")
    print(f"  - Timestamp: {final_result.timestamp}")
    
    # Validations
    print("\n" + "=" * 70)
    print("VALIDATION CHECKS")
    print("=" * 70)
    
    checks_passed = 0
    total_checks = 0
    
    # Check 1: Risk score should be HIGH
    total_checks += 1
    if final_result.final_risk_score >= 0.70:
        print("✅ Risk score >= 0.70 (HIGH/CRITICAL)")
        checks_passed += 1
    else:
        print(f"❌ Risk score {final_result.final_risk_score:.3f} < 0.70")
    
    # Check 2: Risk level should be HIGH or CRITICAL
    total_checks += 1
    if final_result.risk_level in ["HIGH", "CRITICAL"]:
        print(f"✅ Risk level is {final_result.risk_level}")
        checks_passed += 1
    else:
        print(f"❌ Risk level is {final_result.risk_level} (expected HIGH/CRITICAL)")
    
    # Check 3: Should have high certainty
    total_checks += 1
    certainty_score_map = {"DEFINITIVE": 1.0, "HIGH": 0.85, "MEDIUM": 0.7, "LOW": 0.5, "INCONCLUSIVE": 0.3}
    certainty_score = certainty_score_map.get(final_result.aggregated_certainty, 0.5)
    if certainty_score > 0.6:
        print(f"✅ Certainty {final_result.aggregated_certainty} ({certainty_score:.3f}) > 0.6")
        checks_passed += 1
    else:
        print(f"❌ Certainty {final_result.aggregated_certainty} ({certainty_score:.3f}) <= 0.6")
    
    # Check 4: Should have 3 agent contributions
    total_checks += 1
    if len(final_result.agent_contributions) == 3:
        print(f"✅ All 3 agents contributed")
        checks_passed += 1
    else:
        print(f"❌ Only {len(final_result.agent_contributions)} agents contributed")
    
    # Check 5: Should recommend QUARANTINE
    total_checks += 1
    action_types = [action.action_type for action in final_result.recommended_actions]
    if "QUARANTINE" in action_types:
        print(f"✅ QUARANTINE action recommended")
        checks_passed += 1
    else:
        print(f"❌ QUARANTINE not recommended (actions: {action_types})")
    
    # Check 6: Should recommend ALERT or BLOCK_SENDER
    total_checks += 1
    if "ALERT" in action_types or "BLOCK_SENDER" in action_types:
        print(f"✅ Critical action recommended (ALERT or BLOCK_SENDER)")
        checks_passed += 1
    else:
        print(f"❌ No critical action recommended")
    
    # Check 7: Explanation should exist
    total_checks += 1
    if len(final_result.explanation.narrative) > 100:
        print(f"✅ Detailed explanation generated ({len(final_result.explanation.narrative)} chars)")
        checks_passed += 1
    else:
        print(f"❌ Explanation too short")
    
    # Check 8: Should have key findings
    total_checks += 1
    if len(final_result.explanation.key_findings) > 0:
        print(f"✅ {len(final_result.explanation.key_findings)} key findings identified")
        checks_passed += 1
    else:
        print(f"❌ No key findings")
    
    # Check 9: Processing time should be reasonable
    total_checks += 1
    if final_result.processing_time < 10.0:
        print(f"✅ Processing time {final_result.processing_time:.2f}s < 10s")
        checks_passed += 1
    else:
        print(f"❌ Processing time {final_result.processing_time:.2f}s >= 10s")
    
    # Final result
    print("\n" + "=" * 70)
    success_rate = (checks_passed / total_checks) * 100
    if checks_passed == total_checks:
        print(f"✅ ALL CHECKS PASSED ({checks_passed}/{total_checks}) - 100%")
        print("=" * 70)
        print("\n🎉 COORDINATION AGENT TEST: PASSED")
        return True
    else:
        print(f"⚠️  SOME CHECKS FAILED ({checks_passed}/{total_checks}) - {success_rate:.1f}%")
        print("=" * 70)
        print("\n⚠️  COORDINATION AGENT TEST: PARTIAL SUCCESS")
        return False


if __name__ == "__main__":
    try:
        success = test_coordination_end_to_end()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ TEST FAILED WITH ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
