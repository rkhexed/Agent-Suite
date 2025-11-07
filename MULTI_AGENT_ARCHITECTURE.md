# Multi-Agent Email Security Architecture

## System Overview

This document outlines the implementation of a multi-agent email security system based on the research architecture with four specialized agents coordinated by a central Coordination Agent.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Coordination Agent                        │
│  (Confidence-Weighted Aggregation + Explainability)         │
│  Weights: Linguistic 0.30, Technical 0.25,                  │
│           Behavioral 0.25, ThreatIntel 0.20                 │
└────────────────┬────────────────────────────────────────────┘
                 │
        ┌────────┴────────┐
        │  Email Input    │
        │  (from n8n)     │
        └────────┬────────┘
                 │
     ┌───────────┼───────────┬───────────┬───────────┐
     │           │           │           │           │
┌────▼────┐ ┌───▼────┐ ┌───▼────┐ ┌───▼─────┐ ┌───▼────┐
│Linguistic│ │Technical│ │Behavior│ │ Threat  │ │  ML    │
│ Analysis │ │Forensics│ │ Pattern│ │  Intel  │ │ Models │
│  Agent   │ │  Agent  │ │  Agent │ │  Agent  │ │ Layer  │
└─────┬────┘ └────┬───┘ └────┬───┘ └────┬────┘ └────┬───┘
      │           │          │           │           │
      └───────────┴──────────┴───────────┴───────────┘
                         │
                  ┌──────▼──────┐
                  │  Final Risk │
                  │ Assessment  │
                  │   + Report  │
                  └─────────────┘
```

## Agent Specifications

### 1. Linguistic Analysis Agent (Weight: 0.30)

**Purpose:** Detect psychological manipulation tactics in email content

**Capabilities:**
- Urgency detection (time-limited offers, immediate action required)
- Authority exploitation (impersonation of executives, IT, finance)
- Fear appeals (account suspension, legal threats, security warnings)
- Emotional manipulation (curiosity, greed, sympathy)

**ML Models:**
- Primary: Fine-tuned DeBERTa-v3 or RoBERTa for phishing detection
- Secondary: Sentiment analysis model
- Tertiary: Named Entity Recognition for authority figure detection

**Input:**
- Email subject line
- Email body (normalized text)
- Sender display name

**Output:**
```python
{
    "agent": "linguistic",
    "risk_score": 0.85,  # 0-1 scale
    "confidence": 0.92,
    "indicators": [
        {
            "type": "urgency",
            "severity": "HIGH",
            "evidence": "Act now before midnight...",
            "confidence": 0.95
        },
        {
            "type": "authority_exploitation",
            "severity": "MEDIUM",
            "evidence": "CEO urgent request...",
            "confidence": 0.88
        }
    ],
    "manipulation_tactics": ["urgency", "authority"],
    "semantic_patterns": [...],
    "processing_time_ms": 234
}
```

### 2. Technical Forensics Agent (Weight: 0.25)

**Purpose:** Analyze technical email security indicators

**Capabilities:**
- SPF (Sender Policy Framework) validation
- DKIM (DomainKeys Identified Mail) verification
- DMARC (Domain-based Message Authentication) checks
- Domain reputation assessment (age, registration, blacklists)
- URL analysis (malicious links, redirects, typosquatting)
- Header anomaly detection (spoofed headers, suspicious routing)
- IP reputation checking

**External Integrations:**
- VirusTotal API (URL/domain reputation)
- PhishTank API (known phishing URLs)
- Google Safe Browsing API
- WHOIS lookups (domain age/registration)
- DNS queries (SPF/DKIM/DMARC records)

**Input:**
- Email headers (full raw headers)
- URLs extracted from email body
- Sender domain and IP address
- Email metadata

**Output:**
```python
{
    "agent": "technical_forensics",
    "risk_score": 0.72,
    "confidence": 0.95,
    "authentication": {
        "spf": {"status": "FAIL", "confidence": 1.0},
        "dkim": {"status": "PASS", "confidence": 1.0},
        "dmarc": {"status": "FAIL", "confidence": 1.0}
    },
    "domain_analysis": {
        "sender_domain": "suspicious-bank.com",
        "age_days": 15,
        "reputation_score": 0.2,
        "is_disposable": false,
        "typosquatting_target": "legitimate-bank.com"
    },
    "url_analysis": [
        {
            "url": "http://malicious-link.com/login",
            "threat_score": 0.95,
            "virustotal_detections": 45,
            "categories": ["phishing", "malware"]
        }
    ],
    "header_anomalies": [
        {
            "type": "mismatched_from",
            "severity": "HIGH",
            "details": "Display name doesn't match domain"
        }
    ],
    "processing_time_ms": 567
}
```

### 3. Behavioral Pattern Agent (Weight: 0.25)

**Purpose:** Detect anomalies in communication patterns and sender behavior

**Capabilities:**
- Temporal anomaly detection (unusual send times, frequency)
- Sender behavior profiling (deviation from historical patterns)
- Relational context analysis (unusual sender-recipient pairs)
- Communication graph analysis
- BEC (Business Email Compromise) detection
- Spear-phishing pattern recognition

**ML Approach:**
- Isolation Forest for anomaly detection
- LSTM for temporal pattern analysis
- Graph Neural Networks for relationship modeling
- Baseline profiling with statistical methods

**Input:**
- Current email metadata
- Historical email database (sender patterns)
- Organizational relationship graph
- Temporal features (send time, frequency)

**Output:**
```python
{
    "agent": "behavioral_pattern",
    "risk_score": 0.68,
    "confidence": 0.78,
    "anomalies": [
        {
            "type": "temporal",
            "severity": "MEDIUM",
            "description": "Email sent at unusual time (3:47 AM)",
            "baseline_deviation": 2.8  # std deviations
        },
        {
            "type": "sender_behavior",
            "severity": "HIGH",
            "description": "First time sender to this recipient",
            "confidence": 0.85
        }
    ],
    "baseline_metrics": {
        "avg_emails_per_day": 3.2,
        "typical_send_hours": [9, 10, 11, 14, 15, 16],
        "relationship_strength": 0.0  # new contact
    },
    "bec_indicators": [
        {
            "indicator": "urgent_wire_transfer",
            "confidence": 0.72
        }
    ],
    "processing_time_ms": 145
}
```

### 4. Threat Intelligence Agent (Weight: 0.20)

**Purpose:** Correlate email with known threats and campaigns

**Capabilities:**
- Real-time threat feed integration
- Known campaign correlation
- MITRE ATT&CK technique mapping
- Zero-day indicator detection
- IOC (Indicators of Compromise) matching
- Threat actor attribution

**External Integrations:**
- AlienVault OTX (Open Threat Exchange)
- Abuse.ch (URLhaus, ThreatFox)
- PhishTank
- MISP (Malware Information Sharing Platform)
- Custom threat intelligence feeds

**Input:**
- Email content hashes
- URLs and domains
- IP addresses
- File attachments (hashes)
- Email metadata

**Output:**
```python
{
    "agent": "threat_intelligence",
    "risk_score": 0.88,
    "confidence": 0.93,
    "matched_campaigns": [
        {
            "campaign_id": "APT-2024-1337",
            "campaign_name": "Banking Trojan Campaign Q4 2024",
            "confidence": 0.89,
            "first_seen": "2024-10-15",
            "threat_actor": "TA505"
        }
    ],
    "ioc_matches": [
        {
            "type": "url",
            "value": "http://malicious-domain.com",
            "threat_feeds": ["PhishTank", "URLhaus"],
            "first_reported": "2024-11-01"
        }
    ],
    "mitre_techniques": [
        {
            "technique_id": "T1566.001",
            "technique_name": "Phishing: Spearphishing Attachment",
            "confidence": 0.85
        },
        {
            "technique_id": "T1598.003",
            "technique_name": "Phishing for Information: Spearphishing Link",
            "confidence": 0.92
        }
    ],
    "threat_level": "HIGH",
    "processing_time_ms": 423
}
```

### 5. Coordination Agent (Master Agent)

**Purpose:** Synthesize all agent outputs and generate final assessment

**Aggregation Formula:**
```python
# Base weights
weights = {
    "linguistic": 0.30,
    "technical": 0.25,
    "behavioral": 0.25,
    "threat_intel": 0.20
}

# Weighted aggregation with confidence adjustment
final_risk = sum(
    agent_risk * agent_confidence * weight
    for agent_risk, agent_confidence, weight in agent_outputs
) / sum(
    agent_confidence * weight
    for agent_confidence, weight in agent_outputs
)

# Uncertainty calculation
uncertainty = 1 - (sum(confidences) / len(confidences))
```

**Risk Categorization:**
- **HIGH**: final_risk ≥ 0.70
- **MEDIUM**: 0.40 ≤ final_risk < 0.70
- **LOW**: final_risk < 0.40

**Explainability Generation:**
1. Identify top contributing agents (by weighted risk contribution)
2. Extract key evidence from each agent
3. Synthesize narrative explaining the decision
4. Generate actionable recommendations

**Output:**
```python
{
    "coordination": {
        "final_risk_score": 0.78,
        "risk_level": "HIGH",
        "uncertainty": 0.15,
        "confidence": 0.85
    },
    "agent_contributions": [
        {
            "agent": "threat_intelligence",
            "weighted_contribution": 0.24,
            "risk_score": 0.88,
            "confidence": 0.93
        },
        {
            "agent": "linguistic",
            "weighted_contribution": 0.23,
            "risk_score": 0.85,
            "confidence": 0.92
        },
        # ... other agents
    ],
    "top_indicators": [
        {
            "source": "threat_intelligence",
            "type": "campaign_match",
            "severity": "HIGH",
            "description": "Matched known banking trojan campaign"
        },
        {
            "source": "technical_forensics",
            "type": "spf_failure",
            "severity": "HIGH",
            "description": "SPF validation failed"
        },
        {
            "source": "linguistic",
            "type": "urgency",
            "severity": "HIGH",
            "description": "Urgent action manipulation detected"
        }
    ],
    "explanation": {
        "summary": "This email exhibits multiple high-risk indicators consistent with a phishing attack. The message matches a known banking trojan campaign (APT-2024-1337) and fails critical authentication checks (SPF). The content employs urgency manipulation tactics commonly used in social engineering.",
        
        "key_findings": [
            "Email matched known threat campaign with 89% confidence",
            "Failed SPF authentication - likely spoofed sender",
            "Urgent language detected: 'Act now before midnight'",
            "Sender domain registered only 15 days ago",
            "First-time communication from this sender"
        ],
        
        "risk_breakdown": {
            "threat_intelligence": "HIGH - Active campaign match",
            "technical": "HIGH - Authentication failures",
            "linguistic": "HIGH - Manipulation tactics present",
            "behavioral": "MEDIUM - Unusual communication pattern"
        }
    },
    "recommendations": [
        "🚨 DO NOT click any links or open attachments",
        "🚨 DO NOT provide any credentials or sensitive information",
        "✅ Report this email to security team immediately",
        "✅ Verify sender authenticity through separate channel",
        "✅ Delete this email after reporting",
        "ℹ️ Similar emails may target other employees"
    ],
    "metadata": {
        "analysis_timestamp": "2024-11-06T10:23:45Z",
        "total_processing_time_ms": 1369,
        "system_version": "3.0.0",
        "models_used": [
            "deberta-v3-phishing-finetuned",
            "isolation-forest-behavioral",
            "threat-correlation-v2"
        ]
    }
}
```

## Implementation Structure

```
app/
├── Agents/
│   ├── __init__.py
│   ├── coordination_agent.py       # Master coordinator
│   ├── linguistic_agent.py         # Psychological manipulation detection
│   ├── technical_forensics_agent.py # Email authentication & URL analysis
│   ├── behavioral_pattern_agent.py  # Anomaly detection
│   ├── threat_intelligence_agent.py # Threat feed integration
│   └── base_agent.py               # Shared agent interface
│
├── ML/
│   ├── __init__.py
│   ├── semantic_analysis.py        # NLP models (for linguistic agent)
│   ├── anomaly_detection.py        # Behavioral models
│   ├── threat_correlation.py       # Threat intel matching
│   └── model_registry.py           # Model management
│
├── Tools/
│   ├── __init__.py
│   ├── email_analysis_tool.py      # CrewAI tool wrapper
│   ├── authentication_validator.py # SPF/DKIM/DMARC
│   ├── url_analyzer.py             # URL scanning & reputation
│   ├── header_parser.py            # Email header analysis
│   └── threat_feed_client.py       # API clients for threat feeds
│
├── Helper/
│   ├── __init__.py
│   ├── helper_preprocessing.py     # Email preprocessing
│   ├── helper_pydantic.py          # Data models
│   ├── helper_constant.py          # Constants & configs
│   ├── helper_aggregation.py       # Risk aggregation logic
│   └── helper_explainability.py    # Explanation generation
│
└── Services/
    ├── __init__.py
    ├── virustotal_service.py       # VirusTotal integration
    ├── phishtank_service.py        # PhishTank integration
    ├── alienvault_service.py       # AlienVault OTX
    ├── whois_service.py            # WHOIS lookups
    └── dns_service.py              # DNS queries
```

## Workflow

1. **Email Input** → Coordination Agent receives email from n8n
2. **Parallel Analysis** → Coordination Agent dispatches to 4 specialized agents
3. **Agent Processing** → Each agent performs specialized analysis
4. **Result Aggregation** → Coordination Agent collects all results
5. **Risk Calculation** → Weighted aggregation with confidence adjustment
6. **Explanation Generation** → Synthesize human-readable report
7. **Output** → Return comprehensive analysis to n8n workflow

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| **Overall Accuracy** | ≥ 97% | ~50% |
| **False Positive Rate** | < 1% | Unknown |
| **Processing Time** | < 3 seconds | ~2-3s |
| **Agent Contribution Balance** | No single agent > 40% | N/A |
| **Explainability Score** | > 4.0/5.0 | N/A |

## Configuration

```python
# config.py
AGENT_WEIGHTS = {
    "linguistic": 0.30,
    "technical_forensics": 0.25,
    "behavioral_pattern": 0.25,
    "threat_intelligence": 0.20
}

RISK_THRESHOLDS = {
    "HIGH": 0.70,
    "MEDIUM": 0.40,
    "LOW": 0.0
}

MODELS = {
    "linguistic": {
        "primary": "microsoft/deberta-v3-base",  # Fine-tuned
        "sentiment": "cardiffnlp/twitter-roberta-base-sentiment"
    },
    "behavioral": {
        "anomaly": "isolation_forest_v2.pkl",
        "temporal": "lstm_temporal_v1.h5"
    },
    "threat_intel": {
        "campaign_matcher": "threat_correlation_v2.pkl"
    }
}

EXTERNAL_APIS = {
    "virustotal": {
        "enabled": True,
        "api_key": "env:VIRUSTOTAL_API_KEY",
        "rate_limit": 500  # per day for free tier
    },
    "phishtank": {
        "enabled": True,
        "api_key": "env:PHISHTANK_API_KEY"
    },
    "alienvault": {
        "enabled": True,
        "api_key": "env:ALIENVAULT_API_KEY"
    }
}
```

## Next Steps

1. ✅ Create architecture document (this file)
2. 🔲 Implement base agent interface
3. 🔲 Implement each specialized agent
4. 🔲 Implement coordination agent with aggregation
5. 🔲 Add external service integrations
6. 🔲 Create comprehensive test suite
7. 🔲 Add monitoring and metrics
8. 🔲 Deploy and validate

---

**Version:** 3.0.0  
**Last Updated:** November 6, 2024  
**Status:** Architecture Design Complete - Ready for Implementation
