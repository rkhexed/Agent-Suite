#!/usr/bin/env python3
"""Generate test audio file using gTTS"""
try:
    from gtts import gTTS
    import os
    
    text = "Is this email safe?"
    print(f"Generating audio: '{text}'")
    
    tts = gTTS(text=text, lang='en', slow=False)
    tts.save("test_audio.mp3")
    
    print("✅ Created test_audio.mp3")
    print("\nNow run: python test_voice_chat.py test_audio.mp3")
    
except ImportError:
    print("gTTS not installed. Installing...")
    os.system("pip install gtts")
    print("\nNow run this script again: python generate_test_audio.py")
