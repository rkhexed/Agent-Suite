# Multi-Agent Email Security Architecture

## System Overview

This document outlines the implementation of a multi-agent email security system with **three specialized agents** coordinated by a central Coordination Agent. This is a research-focused implementation suitable for academic evaluation, not enterprise deployment.

**Agents:**
1. **Linguistic Analysis Agent** - ML-based semantic/psychological manipulation detection (Weight: 0.60)
2. **Technical Validation Agent** - Lightweight domain age validation via WHOIS (Weight: 0.20)
3. **Threat Intelligence Agent** - Known threat correlation via Google Safe Browsing & AbuseIPDB (Weight: 0.20)

**Removed from Research Scope:**
- ~~Behavioral Pattern Agent~~ - Requires historical email database and enterprise-scale data collection (not suitable for research/academic setting)
- ~~VirusTotal Integration~~ - Rate limits (4 req/min) too restrictive for evaluation dataset processing

## Architecture Diagram

```
┌───────────────────────────────────────────────────────────┐
│                  Coordination Agent                        │
│  (Confidence-Weighted Aggregation + Explainability)       │
│  Weights: Linguistic 0.60, Technical 0.20,                │
│           ThreatIntel 0.20                                │
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
│ Analysis │ │Validation│ │  Intel  │ │ Models │
│  Agent   │ │  Agent  │ │  Agent  │ │ Layer  │
│ (60%)    │ │  (20%)  │ │  (20%)  │ │        │
│ ML-Based │ │Domain   │ │Google SB│ │BERT    │
│Semantics │ │Age Check│ │AbuseIPDB│ │99.98%  │
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

### 1. Linguistic Analysis Agent (Weight: 0.60 - PRIMARY DEFENSE)

**Purpose:** Detect psychological manipulation tactics in email content using ML models only (no pattern matching)

**Rationale for 60% Weight:** 
- Pure ML-based detection (99.98% BERT accuracy)
- Most effective against zero-day phishing attacks
- Detects social engineering regardless of infrastructure
- Research-worthy contribution (novel ML application)

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

### 2. Technical Validation Agent (Weight: 0.20 - LIGHTWEIGHT INFRASTRUCTURE)

**Scope:** Ultra-lightweight domain age validation ONLY (no SPF/DKIM/DMARC - redundant with email providers)

**Purpose:** Detect suspiciously new domains (< 30 days) which is a strong phishing indicator

**Rationale for 20% Weight:**
- Single focused signal (domain age)
- Data-driven threshold (< 30 days = phishing)
- Fast WHOIS lookups (~500ms)
- Academically defensible metric

**Capabilities:**
1. **Domain Age Validation**
   - WHOIS lookups (domain registration date)
   - Age calculation in days
   - Risk scoring based on age thresholds
   
2. **URL Metrics** (basic counting only)
   - URL extraction from email body
   - Count of URLs in email
   - External link detection

**External Integrations:**
- WHOIS lookups via `python-whois` - FREE, no API key
- DNS queries via `dnspython` - FREE, no API key

**Input:**
- Email sender address
- Email body (for URL extraction)

**Output:**
```python
{
    "agent": "technical_validation",
    "risk_score": 0.7,
    "confidence": 0.9,
    "domain_validation": {
        "domain": "suspicious-newsite.com",
        "age_days": 15,
        "registration_date": "2025-10-24T00:00:00",
        "is_new_domain": true,  # < 30 days
        "risk_score": 0.7,
        "whois_available": true
    },
    "url_count": 1,
    "has_external_links": true,
    "processing_time_ms": 567
}
```

**Risk Thresholds:**
- < 7 days: 0.9 (very high risk)
- < 30 days: 0.7 (high risk - phishing threshold)
- < 90 days: 0.4 (medium risk)
- < 365 days: 0.2 (low-medium risk)
- >= 365 days: 0.1 (established domain)

**Status:** ✅ IMPLEMENTED - WHOIS-based domain age validation working

**Dependencies:**
- `python-whois` (WHOIS lookups)
- `dnspython` (DNS queries)
- `python-whois` (WHOIS lookups)
- `Levenshtein` (typosquatting detection)

---

### 3. Threat Intelligence Agent (Weight: 0.20 - KNOWN THREAT DETECTION)

**Scope:** Query external threat intelligence databases ONLY (does NOT do infrastructure validation)

**Purpose:** Check URLs and IPs against global threat intelligence feeds to detect known malicious entities

**Rationale for 20% Weight:**
- Catches known phishing campaigns and malware distribution
- Complements ML detection (known vs unknown threats)
- Fast API calls (~500ms for Google Safe Browsing)
- **NO VirusTotal** (rate limits too restrictive: 4 req/min)

**Capabilities:**
1. **URL Threat Intelligence**
   - Google Safe Browsing API (10,000 req/day)
   - Checks URLs against phishing/malware databases
   - Threat type classification (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE)

2. **IP Reputation Checking**
   - AbuseIPDB API (1,000 req/day)
   - IP abuse confidence scoring (0-100%)
   - Spam/malware/brute-force history
   - Geographic origin and usage type

**External Integrations (Threat feeds only):**
- Google Safe Browsing API - FREE (10,000/day)
- AbuseIPDB API - FREE (1,000/day)
- **Excluded:** VirusTotal (4 req/min too restrictive), PhishTank (redundant with Google SB), AlienVault OTX (overkill for research)

**Input:**
- URLs extracted from email body
- Sender IP address from headers
- Email metadata

**Output:**
```python
{
    "agent": "threat_intelligence",
    "risk_score": 0.88,
    "confidence": 0.95,
    "urls_checked": [
        {
            "url": "http://malicious-domain.com/phish.html",
            "is_malicious": true,
            "risk_score": 0.95,
            "threat_sources": [
                {
                    "source": "Google Safe Browsing",
                    "malicious": true,
                    "threat_type": "SOCIAL_ENGINEERING",
                    "confidence": 0.95,
                    "details": "Flagged as phishing site"
                }
            ]
        }
    ],
    "ip_reputation": {
        "ip_address": "185.220.101.50",
        "is_malicious": true,
        "abuse_score": 87,  # 0-100 (AbuseIPDB confidence)
        "total_reports": 145,
        "country": "RU",
        "usage_type": "Data Center"
    },
    "malicious_count": 2,  # URLs + IP flagged
    "total_checks": 2,
    "processing_time_ms": 523
}
```

**Status:** ✅ IMPLEMENTED - Google Safe Browsing & AbuseIPDB integration complete

**Dependencies:**
- `requests` (HTTP for API calls)
- Google Safe Browsing API key (FREE, set in .env)
- AbuseIPDB API key (FREE, set in .env)
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

**Purpose:** Synthesize all agent outputs, generate final assessment, and recommend automated actions

**Aggregation Formula:**
```python
# Base weights (3-agent system for research)
# Linguistic is primary (60%) - ML-based, detects zero-day attacks
# Technical + ThreatIntel are supporting (20% each)
weights = {
    "linguistic": 0.60,
    "technical_validation": 0.20,
    "threat_intelligence": 0.20
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
3. Synthesize narrative explaining the decision using LLM (Groq Llama 3.3 70B)
4. Generate actionable recommendations

**Automated Actions Framework:**

The coordination agent generates recommended actions based on risk level and confidence:

| Risk Level | Confidence | Actions |
|------------|-----------|---------|
| **CRITICAL** (≥0.90) + High Conf (≥0.85) | High | • Quarantine (auto-execute)<br>• Block sender (requires approval)<br>• Alert security team (auto-execute)<br>• Audit log (auto-execute) |
| **HIGH** (0.70-0.89) | Medium-High | • Quarantine (auto-execute)<br>• Tag as "SUSPECTED_PHISHING"<br>• Audit log |
| **MEDIUM** (0.40-0.69) | Medium | • Tag as "REVIEW_REQUIRED"<br>• Audit log |
| **LOW** (<0.40) | Any | • No action required<br>• Optional: Light audit log |

**Action Types Supported:**
- ✅ **QUARANTINE**: Move email to quarantine folder (n8n auto-execute)
- ✅ **BLOCK_SENDER**: Add sender email/domain to blocklist (requires admin approval for domains)
- ✅ **ALERT**: Send notifications via email/Slack/webhook (n8n auto-execute)
- ✅ **TAG**: Apply Gmail label or Exchange category (n8n auto-execute)
- ✅ **LOG**: Write to audit database/file (n8n auto-execute)
- ❌ **DELETE**: Removed - too risky for false positives

**Action Schema:**
```python
class RecommendedAction(BaseModel):
    action_type: str  # QUARANTINE, BLOCK_SENDER, ALERT, TAG, LOG, NO_ACTION
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float  # 0-1 confidence in this action
    parameters: dict  # Action-specific parameters (e.g., quarantine reason, alert channels)
    requires_approval: bool  # True if human approval needed before execution
    reasoning: str  # Human-readable explanation of why this action is recommended
```

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
        {
            "agent": "technical_validation",
            "weighted_contribution": 0.19,
            "risk_score": 0.75,
            "confidence": 0.88
        }
    ],
    "top_indicators": [
        {
            "source": "threat_intelligence",
            "type": "malicious_url",
            "severity": "HIGH",
            "description": "URL flagged as MALWARE by Google Safe Browsing",
            "evidence": "http://malicious-site.com flagged with 0.95 confidence"
        },
        {
            "source": "technical_validation",
            "type": "new_domain",
            "severity": "HIGH",
            "description": "Domain registered only 15 days ago",
            "evidence": "Domain age: 15 days (threshold: 30 days for phishing risk)"
        },
        {
            "source": "linguistic",
            "type": "phishing_detection",
            "severity": "HIGH",
            "description": "BERT model detected phishing content",
            "evidence": "Model confidence: 0.9998 (99.98% phishing probability)"
        }
    ],
    "explanation": {
        "summary": "This email exhibits multiple high-risk indicators consistent with a phishing attack. The primary concerns are: (1) URL flagged as malware by Google Safe Browsing, (2) domain registered only 15 days ago, and (3) ML model detected phishing language patterns with 99.98% confidence.",
        
        "key_findings": [
            "🚨 CRITICAL: URL matches known malware database (Google Safe Browsing)",
            "⚠️ HIGH: Sender domain registered only 15 days ago",
            "⚠️ HIGH: BERT model detected phishing content (99.98% confidence)",
            "⚠️ MEDIUM: Urgent language manipulation tactics detected",
            "ℹ️ INFO: Sender IP has moderate abuse score (AbuseIPDB: 45%)"
        ],
        
        "risk_breakdown": {
            "threat_intelligence": "HIGH (0.88) - Known malicious URL detected",
            "linguistic": "HIGH (0.85) - ML model confirms phishing patterns",
            "technical_validation": "HIGH (0.75) - Suspiciously new domain"
        },
        
        "narrative": "The Threat Intelligence Agent identified a URL in the email body that matches Google Safe Browsing's malware database with high confidence (0.95). This alone is a strong indicator of malicious intent. Additionally, the Technical Validation Agent discovered that the sender's domain was registered only 15 days ago, which is a common characteristic of phishing campaigns that use disposable domains. Finally, the Linguistic Analysis Agent's fine-tuned BERT model detected phishing language patterns with 99.98% accuracy, including urgency manipulation and credential harvesting indicators. The convergence of all three agents pointing to malicious activity provides high confidence (0.85) in the HIGH risk classification."
    },
    "recommended_actions": [
        {
            "action_type": "QUARANTINE",
            "priority": "CRITICAL",
            "confidence": 0.85,
            "parameters": {
                "reason": "High-confidence phishing detection with known malware URL",
                "folder": "Quarantine/Phishing"
            },
            "requires_approval": false,
            "reasoning": "Email contains known malware URL and exhibits multiple phishing indicators. Immediate quarantine protects user from potential harm."
        },
        {
            "action_type": "BLOCK_SENDER",
            "priority": "HIGH",
            "confidence": 0.78,
            "parameters": {
                "scope": "domain",
                "sender_domain": "suspicious-newsite.com",
                "block_duration": "permanent"
            },
            "requires_approval": true,
            "reasoning": "Sender domain shows malicious patterns (new domain + malware distribution). Recommend blocking entire domain, but requires admin approval due to impact."
        },
        {
            "action_type": "ALERT",
            "priority": "CRITICAL",
            "confidence": 0.85,
            "parameters": {
                "channels": ["email", "slack"],
                "recipients": ["security-team@company.com"],
                "message": "High-confidence phishing email detected with known malware URL",
                "include_analysis": true
            },
            "requires_approval": false,
            "reasoning": "Security team must be notified immediately about active phishing attempt with malware distribution."
        },
        {
            "action_type": "TAG",
            "priority": "HIGH",
            "confidence": 0.85,
            "parameters": {
                "label": "PHISHING_DETECTED",
                "color": "red"
            },
            "requires_approval": false,
            "reasoning": "Visual indicator for any user who might encounter this email in quarantine."
        },
        {
            "action_type": "LOG",
            "priority": "MEDIUM",
            "confidence": 0.85,
            "parameters": {
                "retention_days": 365,
                "include_full_analysis": true,
                "log_level": "security_incident"
            },
            "requires_approval": false,
            "reasoning": "Comprehensive audit trail for security review and potential incident response."
        }
    ],
    "user_recommendations": [
        "🚨 DO NOT click any links or open attachments in this email",
        "🚨 DO NOT provide any credentials or sensitive information",
        "✅ This email has been automatically quarantined for your protection",
        "✅ Security team has been notified and is investigating",
        "ℹ️ If you believe this is a false positive, contact security team for review"
    ],
    "metadata": {
        "analysis_timestamp": "2025-11-09T10:23:45Z",
        "total_processing_time_ms": 1456,
        "system_version": "3.1.0",
        "agents_used": ["linguistic", "technical_validation", "threat_intelligence"],
        "models_used": [
            "dima806/phishing-email-detection (BERT)",
            "all-MiniLM-L6-v2 (embeddings)",
            "dslim/bert-base-NER"
        ],
        "external_apis_called": [
            "Google Safe Browsing",
            "AbuseIPDB",
            "WHOIS"
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
│   ├── helper_aggregation.py          # 🔲 TODO - Risk aggregation (3-agent weighted)
│   ├── helper_explainability.py       # 🔲 TODO - Explanation generation (LLM-based)
│   └── helper_actions.py              # 🔲 TODO - Action recommendation logic
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
   - Technical Validation Agent (domain age validation)
   - Threat Intelligence Agent (threat feed correlation)
3. **Agent Processing** → Each agent performs specialized analysis
4. **Result Aggregation** → Coordination Agent collects all results
5. **Risk Calculation** → Weighted aggregation (60-20-20) with confidence adjustment
6. **Explanation Generation** → Synthesize human-readable report using LLM
7. **Action Recommendation** → Generate automated actions based on risk/confidence
8. **Output** → Return comprehensive analysis to n8n workflow
9. **n8n Action Execution** → n8n processes recommended actions:
   - Auto-execute: QUARANTINE, ALERT, TAG, LOG (no approval needed)
   - Approval flow: BLOCK_SENDER (admin approval via Slack/email)
   - Audit trail: All actions logged to database

## n8n Integration & Action Execution

**n8n Workflow Integration:**

```javascript
// Example n8n node: Process Coordination Agent Response
const coordinationResult = $json.coordination;
const actions = $json.recommended_actions;

// Initialize action execution results
const executionResults = [];

for (const action of actions) {
  if (action.requires_approval) {
    // Send to admin approval workflow
    const approvalRequest = {
      action: action.action_type,
      priority: action.priority,
      reasoning: action.reasoning,
      confidence: action.confidence,
      parameters: action.parameters,
      timestamp: new Date().toISOString()
    };
    
    // Post to Slack for admin approval
    await $http.post('https://hooks.slack.com/services/YOUR_WEBHOOK', {
      text: `⚠️ Action Approval Required: ${action.action_type}`,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Priority:* ${action.priority}\n*Confidence:* ${(action.confidence * 100).toFixed(1)}%\n*Reasoning:* ${action.reasoning}`
          }
        },
        {
          type: 'actions',
          elements: [
            { type: 'button', text: { type: 'plain_text', text: 'Approve' }, value: 'approve', style: 'primary' },
            { type: 'button', text: { type: 'plain_text', text: 'Reject' }, value: 'reject', style: 'danger' }
          ]
        }
      ]
    });
    
    executionResults.push({ action: action.action_type, status: 'pending_approval' });
    
  } else {
    // Auto-execute action
    let result;
    
    switch (action.action_type) {
      case 'QUARANTINE':
        // Move email to quarantine folder
        result = await $gmail.moveMessage({
          messageId: $json.email_id,
          destinationFolder: action.parameters.folder || 'Quarantine'
        });
        executionResults.push({ action: 'QUARANTINE', status: 'executed', result });
        break;
        
      case 'ALERT':
        // Send alerts via configured channels
        const channels = action.parameters.channels || ['email'];
        
        if (channels.includes('slack')) {
          await $http.post('https://hooks.slack.com/services/YOUR_WEBHOOK', {
            text: `🚨 Security Alert: ${action.parameters.message}`,
            attachments: action.parameters.include_analysis ? [coordinationResult] : []
          });
        }
        
        if (channels.includes('email')) {
          await $email.send({
            to: action.parameters.recipients,
            subject: `[Security Alert] ${action.priority}: ${action.parameters.message}`,
            body: JSON.stringify(coordinationResult, null, 2)
          });
        }
        
        executionResults.push({ action: 'ALERT', status: 'executed', channels });
        break;
        
      case 'TAG':
        // Apply Gmail label
        result = await $gmail.addLabel({
          messageId: $json.email_id,
          label: action.parameters.label
        });
        executionResults.push({ action: 'TAG', status: 'executed', label: action.parameters.label });
        break;
        
      case 'LOG':
        // Write to audit database
        await $postgres.insert({
          table: 'security_audit_log',
          data: {
            timestamp: new Date().toISOString(),
            email_id: $json.email_id,
            risk_level: coordinationResult.risk_level,
            risk_score: coordinationResult.final_risk_score,
            confidence: coordinationResult.confidence,
            actions_taken: JSON.stringify(actions),
            full_analysis: JSON.stringify(coordinationResult),
            retention_days: action.parameters.retention_days || 90
          }
        });
        executionResults.push({ action: 'LOG', status: 'executed' });
        break;
        
      case 'NO_ACTION':
        executionResults.push({ action: 'NO_ACTION', status: 'skipped' });
        break;
    }
  }
}

return {
  coordination: coordinationResult,
  actions_executed: executionResults,
  processing_complete: true
};
```

**Action Approval Workflow (Slack Integration):**

```javascript
// Example n8n node: Handle Slack Approval Response
const approvalResponse = $json.actions[0].value; // 'approve' or 'reject'
const actionRequest = $json.original_request;

if (approvalResponse === 'approve') {
  switch (actionRequest.action) {
    case 'BLOCK_SENDER':
      // Add sender to Gmail filter/blocklist
      if (actionRequest.parameters.scope === 'domain') {
        await $gmail.createFilter({
          from: `*@${actionRequest.parameters.sender_domain}`,
          action: 'DELETE' // or 'TRASH' or 'SPAM'
        });
      } else {
        await $gmail.createFilter({
          from: actionRequest.parameters.sender_email,
          action: 'DELETE'
        });
      }
      
      // Log the action
      await $postgres.insert({
        table: 'security_actions',
        data: {
          action: 'BLOCK_SENDER',
          approved_by: $json.user.id,
          approved_at: new Date().toISOString(),
          parameters: actionRequest.parameters
        }
      });
      
      // Confirm in Slack
      await $http.post('https://hooks.slack.com/services/YOUR_WEBHOOK', {
        text: `✅ BLOCK_SENDER action executed: ${actionRequest.parameters.sender_domain || actionRequest.parameters.sender_email}`
      });
      break;
  }
} else {
  // Log rejection
  await $postgres.insert({
    table: 'security_actions',
    data: {
      action: actionRequest.action,
      status: 'rejected',
      rejected_by: $json.user.id,
      rejected_at: new Date().toISOString(),
      rejection_reason: $json.rejection_reason || 'Manual review'
    }
  });
}
```

**Database Schema for Audit Logging:**

```sql
-- security_audit_log table
CREATE TABLE security_audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    email_id VARCHAR(255) NOT NULL,
    sender VARCHAR(255),
    subject TEXT,
    risk_level VARCHAR(20) NOT NULL, -- HIGH, MEDIUM, LOW
    risk_score DECIMAL(3,2) NOT NULL, -- 0.00-1.00
    confidence DECIMAL(3,2) NOT NULL,
    actions_taken JSONB,
    full_analysis JSONB,
    retention_days INTEGER DEFAULT 90,
    expires_at TIMESTAMPTZ GENERATED ALWAYS AS (timestamp + (retention_days || ' days')::INTERVAL) STORED,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- security_actions table
CREATE TABLE security_actions (
    id SERIAL PRIMARY KEY,
    action VARCHAR(50) NOT NULL, -- QUARANTINE, BLOCK_SENDER, etc.
    status VARCHAR(20) NOT NULL, -- executed, pending, rejected
    priority VARCHAR(20),
    confidence DECIMAL(3,2),
    parameters JSONB,
    approved_by VARCHAR(100),
    approved_at TIMESTAMPTZ,
    rejected_by VARCHAR(100),
    rejected_at TIMESTAMPTZ,
    rejection_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_audit_log_risk_level ON security_audit_log(risk_level);
CREATE INDEX idx_audit_log_timestamp ON security_audit_log(timestamp);
CREATE INDEX idx_audit_log_expires_at ON security_audit_log(expires_at);
CREATE INDEX idx_actions_status ON security_actions(status);
CREATE INDEX idx_actions_created_at ON security_actions(created_at);
```

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
# config.py - Research Configuration (3-agent system with automated actions)

AGENT_WEIGHTS = {
    "linguistic": 0.60,  # Primary ML-based defense
    "technical_validation": 0.20,  # Domain age support
    "threat_intelligence": 0.20  # Known threats support
}

RISK_THRESHOLDS = {
    "CRITICAL": 0.90,  # Extreme risk with very high confidence
    "HIGH": 0.70,
    "MEDIUM": 0.40,
    "LOW": 0.0
}

# Action configuration
ACTION_CONFIG = {
    "auto_execute_threshold": {
        "QUARANTINE": 0.70,  # Auto-quarantine at HIGH risk
        "ALERT": 0.70,       # Auto-alert at HIGH risk
        "TAG": 0.40,         # Auto-tag at MEDIUM risk
        "LOG": 0.0           # Always log
    },
    "approval_required": {
        "BLOCK_SENDER": True,  # Always require approval
        "DELETE": False         # Disabled (too risky)
    },
    "confidence_threshold": 0.85,  # Minimum confidence for CRITICAL actions
    "alert_channels": ["email", "slack"],
    "quarantine_folder": "Quarantine/Phishing",
    "audit_retention_days": {
        "CRITICAL": 365,
        "HIGH": 180,
        "MEDIUM": 90,
        "LOW": 30
    }
}

MODELS = {
    "linguistic": {
        "phishing": "dima806/phishing-email-detection",  # Fine-tuned BERT (99.98%)
        "embeddings": "all-MiniLM-L6-v2",  # SentenceTransformer
        "ner": "dslim/bert-base-NER"  # Named Entity Recognition
    }
}

EXTERNAL_APIS = {
    # Threat Intelligence Agent only
    "google_safe_browsing": {
        "enabled": True,
        "api_key": "env:GOOGLE_SAFE_BROWSING_API_KEY",
        "rate_limit": 10000,  # per day
        "timeout": 5
    },
    "abuseipdb": {
        "enabled": True,
        "api_key": "env:ABUSEIPDB_API_KEY",
        "rate_limit": 1000,  # per day
        "timeout": 5
    },
    # Excluded: VirusTotal (4 req/min too restrictive for evaluation)
    
    # Technical Validation Agent - no API keys needed
    "whois": {
        "enabled": True,
        "timeout": 5
    }
}

LLM_CONFIG = {
    "provider": "groq",
    "model": "llama-3.3-70b-versatile",
    "api_key": "env:GROQ_API_KEY",
    "rate_limit": 30,  # per minute (free tier)
    "temperature": 0.1,  # low for consistent analysis
    "max_tokens": 2000,  # for explanation generation
    "use_for_explainability": True
}

N8N_CONFIG = {
    "webhook_url": "env:N8N_WEBHOOK_URL",
    "approval_webhook": "env:N8N_APPROVAL_WEBHOOK",
    "slack_webhook": "env:SLACK_WEBHOOK_URL",
    "audit_database": {
        "host": "env:POSTGRES_HOST",
        "database": "env:POSTGRES_DB",
        "user": "env:POSTGRES_USER",
        "password": "env:POSTGRES_PASSWORD"
    }
}
```

## Next Steps

1. ✅ Create architecture document (this file)
2. ✅ Implement Linguistic Agent (pure ML-based)
3. ✅ Implement Technical Validation Agent (domain age WHOIS)
4. ✅ Implement Threat Intelligence Agent (Google Safe Browsing + AbuseIPDB)
5. 🔲 Implement Coordination Agent (3-agent aggregation + actions)
   - Risk aggregation with 60-20-20 weights
   - Confidence-adjusted scoring
   - LLM-based explanation generation
   - Automated action recommendations (quarantine, block, alert, tag, log)
6. 🔲 Add external service integrations (complete API error handling)
7. 🔲 Create comprehensive test suite (end-to-end coordination testing)
8. 🔲 Add monitoring and metrics
9. 🔲 Deploy and validate with n8n workflow integration

---

**Version:** 3.2.0 (Revised for research focus with automated actions)
**Last Updated:** November 9, 2025  
**Status:** 3 Agents Complete, Coordination Agent Ready for Implementation
**Changes from v3.1.0:**
- Added automated action framework (QUARANTINE, BLOCK_SENDER, ALERT, TAG, LOG)
- Removed auto-delete action (too risky for false positives)
- Added action approval workflow (critical actions require admin approval)
- Enhanced explainability with LLM-generated narratives
- Updated coordination agent output schema with recommended_actions array
- Added helper_actions.py module for action recommendation logic
- Defined risk-based action thresholds (CRITICAL ≥0.90, HIGH ≥0.70, etc.)
- Integrated n8n workflow automation capabilities
