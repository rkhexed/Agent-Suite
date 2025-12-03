#!/usr/bin/env python3
"""Test retrieval endpoints"""
import requests
import json

BASE_URL = "http://localhost:8000"

print("=" * 80)
print("Testing Retrieval Endpoints")
print("=" * 80)

# Test 1: List emails
print("\n1. GET /api/emails - List all emails")
print("-" * 80)
response = requests.get(f"{BASE_URL}/api/emails")
print(f"Status: {response.status_code}")
if response.status_code == 200:
    data = response.json()
    print(f"Found {data['count']} emails")
    for email in data['emails']:
        print(f"  - {email['subject']} | Risk: {email.get('final_risk_score', 'N/A')} | Action: {email.get('final_action', 'N/A')}")
else:
    print(f"Error: {response.text}")

# Test 2: Get specific email with all analyses
if response.status_code == 200 and data['emails']:
    email_id = data['emails'][0]['id']
    print(f"\n2. GET /api/emails/{email_id} - Get email details")
    print("-" * 80)
    response = requests.get(f"{BASE_URL}/api/emails/{email_id}")
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        detail = response.json()
        print(f"Email: {detail['email']['subject']}")
        print(f"Analyses available: {', '.join(detail['analyses'].keys())}")
        print("\nAnalysis Summary:")
        for agent_name, analysis in detail['analyses'].items():
            if analysis:
                print(f"  {agent_name:15} | Risk: {analysis.get('risk_score', 'N/A'):4} | Threat: {analysis.get('threat_level', 'N/A'):10}")
    else:
        print(f"Error: {response.text}")
else:
    print("\nNo emails found to test detail endpoint")

print("\n" + "=" * 80)
print("Tests Complete")
print("=" * 80)
