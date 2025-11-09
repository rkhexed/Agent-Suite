# Multi-Agent Email Security Architecture

## System Overview

This document outlines the implementation of a multi-agent email security system with **three specialized agents** coordinated by a central Coordination Agent. This is a research-focused implementation suitable for academic evaluation, not enterprise deployment.

**Agents:**
1. **Linguistic Analysis Agent** - ML-based semantic/psychological manipulation detection
2. **Technical Forensics Agent** - Infrastructure validation (SPF/DKIM/DMARC, headers, domain age)
3. **Threat Intelligence Agent** - Known threat correlation (threat feeds, IOC matching, campaigns)

**Removed from Research Scope:**
- ~~Behavioral Pattern Agent~~ - Requires historical email database and enterprise-scale data collection (not suitable for research/academic setting)

## Architecture Diagram

```
┌───────────────────────────────────────────────────────────┐
│                  Coordination Agent                        │
│  (Confidence-Weighted Aggregation + Explainability)       │
│  Weights: Linguistic 0.34, Technical 0.33,                │
│           ThreatIntel 0.33                                │
└────────────────┬──────────────────────────────────────────┘
                 │
        ┌────────┴────────┐
        │  Email Input    │
        │  (from n8n)     │
        └────────┬────────┘
                 │
     ┌───────────┼───────────┬───────────┐
     │           │           │           │
┌────▼────┐ ┌───▼────┐ ┌───▼─────┐ ┌───▼────┐
│Linguistic│ │Technical│ │ Threat  │ │  ML    │
│ Analysis │ │Forensics│ │  Intel  │ │ Models │
│  Agent   │ │  Agent  │ │  Agent  │ │ Layer  │
│          │ │         │ │         │ │        │
│ ML-Based │ │Infra    │ │Known    │ │BERT    │
│Semantics │ │Validate │ │Threats  │ │Models  │
└─────┬────┘ └────┬───┘ └────┬────┘ └────┬───┘
      │           │           │           │
      └───────────┴───────────┴───────────┘
                  │
           ┌──────▼──────┐
           │ Final Risk  │
           │ Assessment  │
           │  + Report   │
           └─────────────┘
```

## Agent Specifications

### 1. Linguistic Analysis Agent (Weight: 0.34)

**Purpose:** Detect psychological manipulation tactics in email content using ML models only (no pattern matching)

**Capabilities:**
- Phishing detection using fine-tuned transformer models
- Intent classification (suspicious/urgent/informative)
- Semantic similarity to known manipulation patterns
- Named Entity Recognition for entity detection

**ML Models (100% ML-based, academically defensible):**
- Primary: `dima806/phishing-email-detection` (fine-tuned BERT, 99.98% accuracy)
- Secondary: `all-MiniLM-L6-v2` (SentenceTransformer for semantic embeddings)
- Tertiary: `dslim/bert-base-NER` (Named Entity Recognition)
- LLM: Groq Llama 3.3 70B (FREE tier, 30 req/min)

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
            "type": "phishing",
            "severity": "HIGH",
            "evidence": "ML model confidence: 0.9999",
            "confidence": 0.9998
        },
        {
            "type": "suspicious_intent",
            "severity": "MEDIUM",
            "evidence": "Intent classification: suspicious=0.9998, urgent=0.7998",
            "confidence": 0.9998
        }
    ],
    "processing_time_ms": 234
}
```

**Status:** ✅ IMPLEMENTED - Pure ML-based, no hardcoded patterns

---

### 2. Technical Forensics Agent (Weight: 0.33)

**Scope:** Infrastructure validation ONLY - does NOT query threat feeds (that's Threat Intelligence Agent's job)

**Purpose:** Validate email infrastructure authenticity (is this email technically legitimate?)

**Capabilities:**
1. **Email Authentication** (RFC standard validation)
   - SPF (Sender Policy Framework) validation via DNS
   - DKIM (DomainKeys Identified Mail) verification
   - DMARC (Domain-based Message Authentication) checks
   
2. **Domain Infrastructure Analysis**
   - WHOIS lookups (domain age, registration date)
   - Typosquatting detection (Levenshtein distance vs known brands)
   - Disposable email domain detection
   - DNS MX record validation

3. **Header Anomaly Detection**
   - From/Return-Path mismatch detection
   - Display name spoofing
   - Unusual Received chain routing
   - Missing/malformed standard headers

4. **URL Structure Analysis** (structural validation only)
   - URL shortener detection (bit.ly, tinyurl.com, etc.)
   - Non-standard port detection
   - Protocol validation (http vs https)
   - Malformed URL detection

**External Integrations (Infrastructure only, NO threat feeds):**
- WHOIS lookups (domain age/registration) - FREE
- DNS queries (SPF/DKIM/DMARC records) - FREE
- No VirusTotal, PhishTank, etc. (moved to Threat Intelligence Agent)

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
        "spf": {"status": "FAIL", "confidence": 1.0, "details": "Sender IP not authorized"},
        "dkim": {"status": "PASS", "confidence": 1.0, "details": "Valid signature"},
        "dmarc": {"status": "FAIL", "confidence": 1.0, "details": "Policy=reject, SPF failed"}
    },
    "domain_infrastructure": {
        "sender_domain": "suspicious-bank.com",
        "age_days": 15,
        "registration_date": "2024-10-24",
        "registrar": "Namecheap",
        "is_disposable": false,
        "typosquatting_target": "legitimate-bank.com",
        "typosquatting_distance": 1,  # Levenshtein distance
        "mx_records_valid": true
    },
    "header_anomalies": [
        {
            "type": "mismatched_from",
            "severity": "HIGH",
            "description": "Display name 'Legitimate Bank' doesn't match domain 'suspicious-bank.com'",
            "confidence": 1.0
        },
        {
            "type": "unusual_routing",
            "severity": "MEDIUM",
            "description": "Email routed through 7 countries in unusual pattern",
            "confidence": 0.75
        }
    ],
    "url_structure": [
        {
            "url": "http://bit.ly/abc123",
            "is_shortened": true,
            "protocol": "http",  # not https
            "uses_non_standard_port": false,
            "structure_risk": 0.6
        }
    ],
    "processing_time_ms": 567
}
```

**Status:** 🔲 NOT YET IMPLEMENTED

**Dependencies:**
- `dnspython` (DNS queries)
- `python-whois` (WHOIS lookups)
- `Levenshtein` (typosquatting detection)

---

### 3. Threat Intelligence Agent (Weight: 0.33)

**Scope:** Known threat correlation ONLY - does NOT do infrastructure validation (that's Technical Forensics Agent's job)

**Purpose:** Correlate email artifacts with known threats and campaigns (has this threat been seen before?)

**Capabilities:**
1. **Threat Feed Lookups**
   - PhishTank (known phishing URLs) - FREE, unlimited
   - VirusTotal (URL/domain/IP reputation) - FREE tier: 500/day
   - AlienVault OTX (global threat intelligence) - FREE
   - Abuse.ch URLhaus/ThreatFox (malicious URLs) - FREE

2. **Campaign Correlation**
   - Match to known attack campaigns
   - Threat actor attribution
   - Attack pattern recognition
   - Temporal correlation (active campaigns)

3. **IOC (Indicators of Compromise) Matching**
   - URL/domain matching against threat feeds
   - IP address blacklist checking
   - File hash matching (attachments)
   - Content hash correlation

4. **MITRE ATT&CK Mapping**
   - Technique identification (T1566.001, etc.)
   - Tactic classification
   - Kill chain analysis

**External Integrations (Threat feeds only, NO infrastructure validation):**
- PhishTank API - FREE
- VirusTotal API - FREE tier (500/day)
- AlienVault OTX - FREE
- Abuse.ch (URLhaus, ThreatFox) - FREE
- MISP (optional) - FREE

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
    "threat_feeds": [
        {
            "feed": "PhishTank",
            "url": "http://malicious-domain.com",
            "status": "KNOWN_PHISHING",
            "first_reported": "2024-11-01",
            "confidence": 1.0
        },
        {
            "feed": "VirusTotal",
            "url": "http://malicious-domain.com",
            "detections": 45,
            "total_engines": 90,
            "categories": ["phishing", "malware"],
            "threat_score": 0.95
        },
        {
            "feed": "AlienVault_OTX",
            "domain": "malicious-domain.com",
            "pulse_count": 12,
            "threat_score": 9.2,
            "associated_malware": ["Emotet", "TrickBot"]
        }
    ],
    "campaign_matches": [
        {
            "campaign_id": "APT-2024-1337",
            "campaign_name": "Banking Trojan Campaign Q4 2024",
            "confidence": 0.89,
            "first_seen": "2024-10-15",
            "threat_actor": "TA505",
            "active": true
        }
    ],
    "ioc_matches": [
        {
            "type": "url",
            "value": "http://malicious-domain.com",
            "sources": ["PhishTank", "URLhaus", "OTX"],
            "threat_types": ["phishing", "credential_theft"]
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
    "processing_time_ms": 423
}
```

**Status:** 🔲 NOT YET IMPLEMENTED

**Dependencies:**
- `aiohttp` (async HTTP for API calls)

---

### 4. Coordination Agent (Master Agent)

**Purpose:** Synthesize all agent outputs and generate final assessment

**Aggregation Formula:**
```python
# Base weights (3-agent system for research)
weights = {
    "linguistic": 0.34,
    "technical_forensics": 0.33,
    "threat_intelligence": 0.33
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
│   ├── coordination_agent.py          # Master coordinator (3-agent system)
│   ├── linguistic_agent.py            # ✅ IMPLEMENTED - ML-based semantic analysis
│   ├── technical_forensics_agent.py   # 🔲 TODO - Infrastructure validation
│   ├── threat_intelligence_agent.py   # 🔲 TODO - Threat feed integration
│   └── base_agent.py                  # Shared agent interface
│
├── ML/
│   ├── __init__.py
│   ├── semantic_analysis.py           # ✅ IMPLEMENTED - NLP models for linguistic agent
│   └── model_registry.py              # Model management
│
├── Tools/
│   ├── __init__.py
│   ├── email_analysis.py              # ✅ IMPLEMENTED - Linguistic tool (pure ML)
│   ├── technical_forensics.py         # 🔲 TODO - Technical validation tool
│   ├── authentication_validator.py    # 🔲 TODO - SPF/DKIM/DMARC
│   ├── domain_analyzer.py             # 🔲 TODO - WHOIS/typosquatting
│   ├── header_parser.py               # 🔲 TODO - Header anomaly detection
│   └── threat_feed_client.py          # 🔲 TODO - Threat intelligence APIs
│
├── Helper/
│   ├── __init__.py
│   ├── helper_preprocessing.py        # ✅ IMPLEMENTED - Email preprocessing
│   ├── helper_pydantic.py             # ✅ IMPLEMENTED - Data models
│   ├── helper_constant.py             # ✅ IMPLEMENTED - Constants & configs
│   ├── helper_aggregation.py          # 🔲 TODO - Risk aggregation (3-agent)
│   └── helper_explainability.py       # 🔲 TODO - Explanation generation
│
└── Services/
    ├── __init__.py
    ├── virustotal_service.py          # 🔲 TODO - VirusTotal integration
    ├── phishtank_service.py           # 🔲 TODO - PhishTank integration
    ├── alienvault_service.py          # 🔲 TODO - AlienVault OTX
    ├── whois_service.py               # 🔲 TODO - WHOIS lookups
    └── dns_service.py                 # 🔲 TODO - DNS queries (SPF/DKIM/DMARC)
```

**Note:** Behavioral Pattern Agent removed - requires enterprise-scale historical data not suitable for research.

## Workflow

1. **Email Input** → Coordination Agent receives email from n8n
2. **Parallel Analysis** → Coordination Agent dispatches to 3 specialized agents
   - Linguistic Agent (ML-based semantic analysis)
   - Technical Forensics Agent (infrastructure validation)
   - Threat Intelligence Agent (threat feed correlation)
3. **Agent Processing** → Each agent performs specialized analysis
4. **Result Aggregation** → Coordination Agent collects all results
5. **Risk Calculation** → Weighted aggregation (0.34, 0.33, 0.33) with confidence adjustment
6. **Explanation Generation** → Synthesize human-readable report
7. **Output** → Return comprehensive analysis to n8n workflow

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| **Overall Accuracy** | ≥ 95% | TBD |
| **False Positive Rate** | < 2% | TBD |
| **Processing Time** | < 5 seconds | ~3-4s (linguistic only) |
| **Agent Contribution Balance** | No single agent > 40% | TBD |
| **Explainability Score** | > 4.0/5.0 | TBD |

**Note:** Targets adjusted for 3-agent research system (vs 4-agent enterprise system)

## Configuration

```python
# config.py - Research Configuration (3-agent system)

AGENT_WEIGHTS = {
    "linguistic": 0.34,
    "technical_forensics": 0.33,
    "threat_intelligence": 0.33
}

RISK_THRESHOLDS = {
    "HIGH": 0.70,
    "MEDIUM": 0.40,
    "LOW": 0.0
}

MODELS = {
    "linguistic": {
        "phishing": "dima806/phishing-email-detection",  # Fine-tuned BERT
        "embeddings": "all-MiniLM-L6-v2",  # SentenceTransformer
        "ner": "dslim/bert-base-NER"  # Named Entity Recognition
    }
}

EXTERNAL_APIS = {
    # Threat Intelligence Agent only
    "virustotal": {
        "enabled": True,
        "api_key": "env:VIRUSTOTAL_API_KEY",
        "rate_limit": 500,  # per day for free tier
        "requests_per_minute": 4
    },
    "phishtank": {
        "enabled": True,
        "api_key": "env:PHISHTANK_API_KEY",
        "rate_limit": None  # unlimited for free tier
    },
    "alienvault": {
        "enabled": True,
        "api_key": "env:ALIENVAULT_API_KEY",
        "rate_limit": 1000  # per hour
    },
    
    # Technical Forensics Agent - no API keys needed (DNS/WHOIS are free)
    "whois": {
        "enabled": True,
        "timeout": 5
    },
    "dns": {
        "enabled": True,
        "timeout": 3
    }
}

LLM_CONFIG = {
    "provider": "groq",
    "model": "llama-3.3-70b-versatile",
    "api_key": "env:GROQ_API_KEY",
    "rate_limit": 30,  # per minute (free tier)
    "temperature": 0.1  # low for consistent analysis
}
```

## Next Steps

1. ✅ Create architecture document (this file)
2. ✅ Implement Linguistic Agent (pure ML-based)
3. 🔲 Implement Technical Forensics Agent (infrastructure validation)
4. 🔲 Implement Threat Intelligence Agent (threat feed correlation)
5. 🔲 Implement Coordination Agent (3-agent aggregation)
6. 🔲 Add external service integrations
7. 🔲 Create comprehensive test suite
8. 🔲 Add monitoring and metrics
9. 🔲 Deploy and validate

---

**Version:** 3.1.0 (Revised for research focus)
**Last Updated:** November 8, 2024  
**Status:** Architecture Updated - Linguistic Agent Complete, 2 Agents Remaining
**Changes from v3.0.0:**
- Removed Behavioral Pattern Agent (enterprise-only, requires historical data)
- Adjusted to 3-agent system with weights: 0.34, 0.33, 0.33
- Clarified separation between Technical Forensics (infrastructure) and Threat Intelligence (threat feeds)
- Updated to reflect pure ML-based Linguistic Agent implementation
- Added free-tier API constraints for research setting
