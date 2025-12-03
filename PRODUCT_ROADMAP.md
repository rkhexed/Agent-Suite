# Multi-Agent Email Security Product Roadmap
**Demo Product Implementation Plan**

## Product Vision
Build a working demo where emails are automatically analyzed by AI agents, stored in a database, and users can interactively chat (text/voice) about agent decisions for each email.

---

## Phase 1: Agent API Foundation (Week 1)
**Goal:** Get n8n workflow working with agent APIs

### 1.1 FastAPI Server Setup
**File:** `main.py`
- Configure FastAPI application with CORS
- Set up request/response models with Pydantic
- Add basic error handling
- Health check endpoint

### 1.2 Agent Endpoints
**Endpoints to implement:**
- `POST /api/linguistic/analyze` - Linguistic analysis agent
- `POST /api/technical/analyze` - Technical validation agent  
- `POST /api/threat-intel/analyze` - Threat intelligence agent
- `POST /api/coordination/analyze` - Coordination/aggregation agent

**Request Format:**
```json
{
  "email_id": "unique_id",
  "subject": "Email subject",
  "sender": "sender@example.com",
  "body": "Email content",
  "headers": {},
  "metadata": {}
}
```

**Response Format:**
```json
{
  "agent": "linguistic",
  "risk_score": 0.85,
  "threat_level": "HIGH",
  "confidence": 0.92,
  "indicators": ["urgency_language", "authority_impersonation"],
  "analysis": "Detailed explanation...",
  "timestamp": "2025-11-26T10:30:00Z"
}
```

### 1.3 Agent Integration
- Import existing agents (LinguisticAgent, TechnicalValidationAgent, ThreatIntelAgent, CoordinationAgent)
- Create async wrappers to handle CrewAI synchronous execution
- Implement proper error handling and timeouts
- Add logging for debugging

### 1.4 Testing & Validation
- Test each endpoint individually with Postman/curl
- Test n8n workflow with real emails
- Verify all 3 agents → coordination agent flow
- Document any API issues

**Deliverable:** Working API server that n8n can call to analyze emails

**Timeline:** 2-3 days

---

## Phase 2: Database Infrastructure (Week 1-2)
**Goal:** Persistent storage for emails and agent analyses

### 2.1 PostgreSQL Setup
- Install PostgreSQL locally (or Docker container)
- Create database: `phishing_detection_db`
- Set up connection string in `.env` file
- Configure SQLAlchemy engine

### 2.2 Database Schema Design
**Tables:**

#### `emails`
```sql
CREATE TABLE emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id VARCHAR(255) UNIQUE NOT NULL,
    subject TEXT,
    sender VARCHAR(255),
    recipient VARCHAR(255),
    body TEXT,
    headers JSONB,
    received_at TIMESTAMP DEFAULT NOW(),
    processed_at TIMESTAMP,
    final_risk_score DECIMAL(3,2),
    final_threat_level VARCHAR(20),
    final_verdict VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### `agent_analyses`
```sql
CREATE TABLE agent_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id UUID REFERENCES emails(id) ON DELETE CASCADE,
    agent_type VARCHAR(50) NOT NULL,  -- 'linguistic', 'technical', 'threat_intel', 'coordination'
    risk_score DECIMAL(3,2),
    threat_level VARCHAR(20),
    confidence DECIMAL(3,2),
    indicators JSONB,
    analysis TEXT,
    raw_response JSONB,
    executed_at TIMESTAMP DEFAULT NOW(),
    execution_time_ms INTEGER
);
```

#### `chat_sessions`
```sql
CREATE TABLE chat_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id UUID REFERENCES emails(id) ON DELETE CASCADE,
    started_at TIMESTAMP DEFAULT NOW(),
    last_message_at TIMESTAMP DEFAULT NOW(),
    message_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active'  -- 'active', 'closed'
);
```

#### `chat_messages`
```sql
CREATE TABLE chat_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES chat_sessions(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,  -- 'user', 'assistant'
    message TEXT NOT NULL,
    input_mode VARCHAR(20),  -- 'text', 'voice'
    timestamp TIMESTAMP DEFAULT NOW(),
    metadata JSONB
);
```

### 2.3 SQLAlchemy Models
**File:** `app/Database/models.py`
- Email model with relationships
- AgentAnalysis model
- ChatSession model  
- ChatMessage model
- Add indexes for performance (email_id, timestamps)

### 2.4 Database Operations
**File:** `app/Database/operations.py`
- `create_email()` - Insert email record
- `add_agent_analysis()` - Store individual agent result
- `get_email_with_analyses()` - Retrieve email + all agent results
- `create_chat_session()` - Start new conversation
- `add_chat_message()` - Store chat message
- `get_chat_history()` - Retrieve conversation

### 2.5 Database API Endpoints
**File:** `main.py` (add these endpoints)
- `POST /api/emails` - Store email + all agent analyses (called by n8n)
- `GET /api/emails` - List all emails with pagination
- `GET /api/emails/{email_id}` - Get email details + all analyses
- `DELETE /api/emails/{email_id}` - Delete email (optional)

**Deliverable:** Working database with API to store/retrieve email analyses

**Timeline:** 3-4 days

---

## Phase 3: Chat Agent Implementation (Week 2)
**Goal:** Interactive chat agent with email-specific context

### 3.1 EmailReviewChatAgent Design
**File:** `app/Agents/email_review_chat_agent.py`

**Responsibilities:**
- Load email + all 4 agent analyses from database
- Maintain conversation context
- Answer user questions about agent decisions
- Explain risk scores, indicators, recommendations
- Provide actionable insights

**System Prompt:**
```
You are an AI assistant helping users understand email security analysis.

EMAIL CONTEXT:
- Subject: {subject}
- Sender: {sender}
- Risk Score: {final_risk_score} ({final_threat_level})

AGENT ANALYSES:
1. Linguistic Agent (Weight: 60%):
   - Risk: {linguistic_risk}
   - Indicators: {linguistic_indicators}
   - Analysis: {linguistic_analysis}

2. Technical Agent (Weight: 20%):
   - Risk: {technical_risk}
   - Indicators: {technical_indicators}
   - Analysis: {technical_analysis}

3. Threat Intel Agent (Weight: 20%):
   - Risk: {threat_intel_risk}
   - Indicators: {threat_intel_indicators}
   - Analysis: {threat_intel_analysis}

4. Final Decision (Coordination):
   - Overall Risk: {coordination_risk}
   - Verdict: {verdict}
   - Reasoning: {coordination_analysis}

Answer user questions about this analysis. Be concise, accurate, and helpful.
```

### 3.2 Chat Agent Features
- **Context Loading:** Retrieve email + all analyses from DB
- **Memory:** Keep last 10 message exchanges (ConversationBufferWindowMemory)
- **LLM:** Use Mistral (already configured)
- **Response Format:** Conversational, educational, actionable

### 3.3 Chat API Endpoints
**File:** `main.py` (add these endpoints)

- `POST /api/emails/{email_id}/chat`
  - Request: `{"message": "Why was this flagged as phishing?"}`
  - Response: `{"response": "...", "session_id": "..."}`

- `GET /api/emails/{email_id}/chat/history`
  - Returns: Array of all messages in conversation

- `POST /api/emails/{email_id}/chat/voice`
  - Request: Audio file upload
  - Process: Whisper transcription → Chat agent → Response
  - Response: `{"transcription": "...", "response": "...", "session_id": "..."}`

### 3.4 Chat Logic
- Check if chat session exists for this email
- If not, create new session and load email context
- If exists, load conversation history
- Process user message with full context
- Store message and response in database
- Return response

**Deliverable:** Working chat agent that can discuss email analyses

**Timeline:** 4-5 days

---

## Phase 4: Voice Integration (Week 2-3)
**Goal:** Enable voice input for chat

### 4.1 Whisper Setup
- Install: `pip install openai-whisper`
- Download Whisper base model (74 MB)
- Create model loader with caching
- Test transcription accuracy

### 4.2 Audio Processing
**File:** `app/ML/voice_transcription.py`
- Accept audio uploads (mp3, wav, m4a, webm)
- Convert to format Whisper expects
- Transcribe with Whisper base model
- Return transcription text

### 4.3 Voice Endpoint Implementation
- Handle multipart/form-data file uploads
- Validate file size (max 10 MB)
- Call transcription service
- Pass transcription to chat agent
- Return both transcription and response

### 4.4 Testing
- Test with various audio formats
- Measure transcription speed
- Verify accuracy with sample recordings
- Test error handling (invalid files, too large, corrupted)

**Deliverable:** Working voice input for chat

**Timeline:** 3-4 days

---

## Phase 5: n8n Workflow Integration (Week 3)
**Goal:** Complete end-to-end automation

### 5.1 Current n8n Workflow Analysis
- Review existing workflow
- Identify integration points
- Plan minimal changes

### 5.2 Workflow Updates
**Add database storage step:**
1. Email arrives
2. Call 3 agent APIs (parallel)
3. Collect all 3 responses
4. Call coordination agent API
5. **NEW:** Call `POST /api/emails` with all results
6. Store response for tracking

**Workflow Structure:**
```
Email Trigger
  ├─> Linguistic API
  ├─> Technical API
  └─> Threat Intel API
       └─> Coordination API
            └─> Store in Database
                 └─> (Optional) Notify Frontend
```

### 5.3 Error Handling
- Retry logic for failed agent calls
- Fallback if coordination agent fails
- Database storage verification
- Alert on critical failures

### 5.4 Testing
- Test with real emails
- Verify database records created correctly
- Confirm all agent analyses stored
- Test error scenarios (agent timeout, DB unavailable)

**Deliverable:** Fully automated email processing with database storage

**Timeline:** 2-3 days

---

## Phase 6: Frontend Connection (Week 3-4)
**Goal:** Connect Lovable UI to backend

### 6.1 Frontend Requirements Analysis
- Review Lovable-generated frontend code
- Identify required API endpoints
- Document data format expectations

### 6.2 API Configuration
**File:** Frontend `.env` or config file
```
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000  # (if using WebSocket)
```

### 6.3 Frontend Features
**Email List View:**
- Fetch: `GET /api/emails`
- Display: Subject, sender, risk score, threat level, timestamp
- Sorting/filtering by risk level, date
- Pagination

**Email Detail View:**
- Fetch: `GET /api/emails/{email_id}`
- Display: Full email content, all agent analyses, final verdict
- Visual risk score indicator
- Expandable agent sections

**Chat Interface:**
- Text input box
- Voice recording button
- Chat message history
- Real-time response streaming (optional)
- Loading states

### 6.4 Frontend-Backend Integration
- Configure CORS in FastAPI
- Test all API endpoints from frontend
- Handle loading states
- Implement error boundaries
- Add retry logic for failed requests

### 6.5 User Experience Polish
- Loading spinners for agent processing
- Success/error notifications
- Responsive design
- Dark/light mode (if supported)
- Email search functionality

**Deliverable:** Fully connected frontend with all features working

**Timeline:** 3-4 days

---

## Phase 7: Testing & Polish (Week 4)
**Goal:** Production-ready demo

### 7.1 End-to-End Testing
- Send test emails through n8n
- Verify database storage
- Test chat functionality
- Test voice input
- Check all error scenarios

### 7.2 Performance Optimization
- Database query optimization (add indexes)
- Agent response caching (if appropriate)
- Frontend lazy loading
- API response compression

### 7.3 Documentation
**Create user guide:**
- How to set up the system
- How to use the chat interface
- How to interpret risk scores
- Troubleshooting common issues

**Create developer guide:**
- Architecture overview
- API documentation
- Database schema
- Deployment instructions

### 7.4 Demo Preparation
- Prepare sample emails (phishing + legitimate)
- Create demo script/walkthrough
- Record demo video (optional)
- Prepare FAQ

### 7.5 Bug Fixes & Refinements
- Fix any discovered bugs
- Improve error messages
- Add helpful tooltips
- Polish UI/UX

**Deliverable:** Polished demo ready for presentation

**Timeline:** 3-4 days

---

## Total Timeline Estimate
**3-4 weeks for complete working demo**

### Week 1: Foundation
- Days 1-3: Agent APIs + n8n integration
- Days 4-7: Database setup + storage API

### Week 2: Intelligence Layer
- Days 8-12: Chat agent implementation
- Days 13-14: Voice integration (Whisper)

### Week 3: Integration
- Days 15-17: n8n workflow updates
- Days 18-21: Frontend connection

### Week 4: Polish
- Days 22-25: Testing, bug fixes, documentation
- Days 26-28: Demo preparation & refinement

---

## Success Metrics for Demo
- ✅ Email automatically processed by 3 agents + coordination
- ✅ All results stored in PostgreSQL
- ✅ User can view email list with risk scores
- ✅ User can click email to see detailed agent analyses
- ✅ User can chat (text) about any email
- ✅ User can chat (voice) using Whisper
- ✅ Chat agent provides helpful, accurate responses
- ✅ System handles 100+ emails without issues
- ✅ No crashes or major bugs during demo

---

## Technologies Stack Summary
| Component | Technology | Purpose |
|-----------|-----------|---------|
| Backend API | FastAPI | REST endpoints for agents & chat |
| Database | PostgreSQL | Persistent storage |
| ORM | SQLAlchemy | Database models & queries |
| Workflow | n8n | Email automation & orchestration |
| Agents | CrewAI | Multi-agent framework |
| LLM | Mistral API | Agent reasoning & chat |
| ML Models | BERT, Transformers | Phishing detection, NER |
| Voice | Whisper (local) | Speech-to-text |
| Frontend | Lovable (React) | User interface |

---

## Next Immediate Actions
1. ✅ **START HERE:** Create `main.py` with 4 agent endpoints
2. Test agent APIs with n8n workflow
3. Set up PostgreSQL database
4. Implement database storage API
5. Build chat agent
6. Continue through phases...

**Ready to begin Phase 1: Agent API Foundation?**
