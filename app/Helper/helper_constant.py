from typing import Dict, List, Any
from enum import Enum
from pathlib import Path

# Email Pattern Types
class EmailPatternType(Enum):
    PHISHING = "phishing"
    URGENCY = "urgency"
    AUTHORITY = "authority"
    SOCIAL_ENGINEERING = "social_engineering"
    SUSPICIOUS = "suspicious"
    CREDENTIAL_HARVEST = "credential_harvest"
    MALWARE = "malware"
    BEC = "business_email_compromise"

# ML Model Constants
MODEL_PATHS = {
    "phishing": Path("models/phishing_detection"),
    "intent": Path("models/intent_classification"),
    "semantic": Path("models/semantic_similarity")
}

# Threat Analysis Weights
THREAT_SCORE_WEIGHTS = {
    "phishing_detection": 0.30,
    "intent_classification": 0.20,
    "semantic_analysis": 0.20,
    "url_analysis": 0.15,
    "sender_analysis": 0.15
}

# URL and Domain Analysis
URL_ANALYSIS_CONFIG = {
    "max_redirects": 3,
    "timeout": 5,
    "verify_ssl": True
}

SUSPICIOUS_TLDS = {
    "high_risk": [".xyz", ".top", ".work", ".loan", ".click"],
    "medium_risk": [".info", ".site", ".biz", ".online"],
    "monitoring": [".app", ".dev", ".tech"]
}

# Email Headers for Analysis
IMPORTANT_HEADERS = {
    "authentication": [
        "Authentication-Results",
        "DKIM-Signature",
        "Received-SPF",
        "ARC-Authentication-Results"
    ],
    "routing": [
        "Received",
        "Return-Path",
        "X-Originating-IP"
    ],
    "client": [
        "X-Mailer",
        "User-Agent",
        "X-Email-Client"
    ]
}

# Recommendation Templates
RECOMMENDATION_TEMPLATES = {
    "phishing": [
        "Do not click on any links in this email",
        "Do not download any attachments",
        "Do not provide any sensitive information",
        "Report this email to your security team",
        "Forward this email as an attachment to preserve headers"
    ],
    "suspicious_sender": [
        "Verify the sender's identity through official channels",
        "Check the full email address carefully, not just the display name",
        "Look for slight misspellings or domain variations",
        "Contact the supposed sender through a known, verified method",
        "Check previous communication patterns with this sender"
    ],
    "urgent": [
        "Do not act immediately on urgent requests without verification",
        "Be especially cautious of urgent financial requests",
        "Contact the sender through a different channel to confirm",
        "Review the request with your supervisor if it involves sensitive actions",
        "Check if this follows normal business procedures"
    ],
    "credential_harvest": [
        "Never enter credentials through email links",
        "Access services directly through official websites",
        "Enable two-factor authentication on your accounts",
        "Report attempted credential theft to IT security",
        "Check for similar phishing attempts targeting colleagues"
    ],
    "malware": [
        "Do not open any attachments from this sender",
        "Scan any downloaded files with antivirus",
        "Check file extensions carefully",
        "Be cautious of password-protected archives",
        "Report potential malware to your security team"
    ],
    "bec": [
        "Verify any financial requests through phone or in person",
        "Check for subtle changes in email domains",
        "Follow established financial approval procedures",
        "Be cautious of changes to payment details",
        "Verify requests that bypass normal procedures"
    ]
}

# Analysis Configuration
ANALYSIS_CONFIG = {
    "model": {
        "max_length": 512,
        "batch_size": 16,
        "confidence_threshold": 0.7,
        "similarity_threshold": 0.85
    },
    "cache": {
        "ttl": 3600,  # 1 hour
        "max_size": 1000,
        "redis_prefix": "email_analysis:"
    },
    "rate_limits": {
        "url_checks": 100,  # per minute
        "api_calls": 1000,  # per hour
        "model_inference": 500  # per minute
    }
}