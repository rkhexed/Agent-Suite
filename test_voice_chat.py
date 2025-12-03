#!/usr/bin/env python3
"""Test voice chat endpoint"""
import requests
import sys

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

print(f"\nTesting voice chat with email: {subject} ({email_id})")
print("=" * 80)

# Check if audio file was provided
if len(sys.argv) < 2:
    print("Usage: python test_voice_chat.py <audio_file.wav>")
    print("\nTo create a test audio file, you can:")
    print("1. Record yourself asking 'Is this email safe?' on your phone")
    print("2. Or use text-to-speech: ")
    print("   - macOS: say 'Is this email safe?' -o test_audio.wav")
    print("   - Linux: espeak 'Is this email safe?' -w test_audio.wav")
    exit(1)

audio_file = sys.argv[1]

print(f"\nUploading audio file: {audio_file}")
print("-" * 80)

try:
    with open(audio_file, 'rb') as f:
        files = {'audio': (audio_file, f, 'audio/wav')}
        response = requests.post(
            f"{BASE_URL}/api/emails/{email_id}/chat/voice",
            files=files
        )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Transcription: \"{data['transcription']}\"")
        print("\n" + "=" * 80)
        print("AI Response:")
        print("=" * 80)
        print(data['response'])
        print("\n" + "=" * 80)
        print(f"Timestamp: {data['timestamp']}")
    else:
        print(f"❌ Error {response.status_code}: {response.text}")
        
except FileNotFoundError:
    print(f"❌ Audio file not found: {audio_file}")
except Exception as e:
    print(f"❌ Error: {str(e)}")

print("\n" + "=" * 80)
print("Voice chat test complete!")
