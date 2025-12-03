#!/usr/bin/env python3
"""Test chat endpoint"""
import requests
import json

BASE_URL = "http://localhost:8000"

# Get an email ID first
print("Getting email list...")
emails_response = requests.get(f"{BASE_URL}/api/emails")
emails = emails_response.json()["emails"]

if not emails:
    print("No emails found. Send a test email first.")
    exit(1)

email_id = emails[0]["id"]
subject = emails[0]["subject"]

print(f"\nTesting chat with email: {subject} ({email_id})")
print("=" * 80)

# Test questions
questions = [
    "Is this email safe?",
    "Why was this classified as low risk?",
    "What should I do with this email?"
]

for i, question in enumerate(questions, 1):
    print(f"\n{i}. User: {question}")
    print("-" * 80)
    
    response = requests.post(
        f"{BASE_URL}/api/emails/{email_id}/chat",
        params={"message": question}
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"AI: {data['response']}\n")
    else:
        print(f"Error {response.status_code}: {response.text}\n")

print("=" * 80)
print("Chat test complete!")
