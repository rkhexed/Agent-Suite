# Agent Suite - Cybersecurity AI Agents with n8n Orchestration

A Python-based AI agent system for cybersecurity email analysis, built with CrewAI and designed to work with n8n for workflow orchestration.

## 🏗️ Architecture

This system implements a **Python AI Agents + n8n Orchestration** architecture:

- **Python Components**: Individual AI agent services built with CrewAI
- **n8n Integration**: HTTP-based orchestration layer for workflow coordination
- **FastAPI Services**: Each agent runs as a separate HTTP service
- **Standardized Interface**: Consistent request/response format for n8n integration

## 🤖 Agent Services

Each agent is a specialized CrewAI crew that can be called via HTTP:

1. **Linguistic Analysis** (Port 8001) - NLP analysis, sentiment detection, social engineering
2. **Technical Analysis** (Port 8002) - Email header analysis, forensics, technical indicators  
3. **Behavioral Analysis** (Port 8003) - Pattern analysis, behavioral indicators
4. **Threat Intelligence** (Port 8004) - Threat feed integration, IOCs, reputation analysis
5. **Coordination** (Port 8005) - Decision fusion, result aggregation
6. **Chatbot** (Port 8006) - General purpose interface, email drafting, action reversal

## 🚀 Quick Start

### Setup

```bash
# Install uv (fast Python package manager)
pip install uv

# Install dependencies
uv sync

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate
```

### Running Services

```bash
# Show all available endpoints and integration info
python main.py show-endpoints

# Start individual agents
python main.py linguistic      # Port 8001
python main.py technical       # Port 8002
python main.py behavioral      # Port 8003
python main.py threat-intel    # Port 8004
python main.py coordination    # Port 8005
python main.py chatbot         # Port 8006

# Test linguistic agent
python main.py test-linguistic
```

### Using the Service Runner

```bash
# Alternative way to run services
python app/Agents/service_runner.py linguistic --port 8001
python app/Agents/service_runner.py technical --port 8002
# ... etc
```

## 🔗 n8n Integration

### HTTP Endpoints

Each agent provides these endpoints:

- `POST /analyze` - Main analysis endpoint (n8n will call this)
- `POST /process` - Alternative endpoint name
- `GET /health` - Health check for monitoring
- `GET /info` - Agent capabilities and information
- `GET /` - Service status

### Request Format

```json
{
  "email_data": {
    "subject": "Email subject here",
    "content": "Email body content here",
    "sender": "sender@example.com",
    "recipient": "recipient@example.com",
    "headers": {},
    "attachments": []
  },
  "metadata": {
    "source": "n8n_workflow",
    "priority": "normal"
  },
  "request_id": "n8n_request_001"
}
```

### Response Format

```json
{
  "agent_name": "Linguistic Analysis Crew",
  "request_id": "n8n_request_001",
  "status": "success",
  "confidence_score": 0.85,
  "findings": [
    {
      "type": "suspicious_pattern",
      "severity": "medium",
      "confidence": 0.8,
      "description": "Urgency indicators detected"
    }
  ],
  "recommendations": [
    "Review email content carefully",
    "Verify sender identity"
  ],
  "processing_time": 2.5,
  "timestamp": "2024-01-01T12:00:00"
}
```

## 🛠️ Development

### Adding New Libraries

1. Add to `pyproject.toml` in dependencies section
2. Use version constraints (e.g., `>=1.0.0`)
3. Update lock file: `uv lock`
4. Sync: `uv sync`
5. Activate: `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Linux/Mac)

### Project Structure

```
Agent-Suite/
├── pyproject.toml          # Project configuration & dependencies
├── main.py                 # Main entry point and service launcher
├── README.md              # This file
├── uv.lock                # Dependency lock file
└── app/                   # Main application code
    ├── Agents/            # Agent implementations
    │   ├── basic_agent.py # Base CrewAI crew class
    │   ├── linguistic_agent.py # Linguistic analysis crew
    │   ├── fastapi_service.py # FastAPI service wrapper
    │   └── service_runner.py # Service launcher
    ├── Helper/            # Utility functions
    │   ├── helper_constant.py
    │   └── helper_prompt.py
    ├── LLM/               # Language model integration
    │   └── llm.py
    ├── ML/                # Machine learning components
    │   └── semantic_tone.py
    └── Tools/             # External tool integrations
        ├── domain_auth.py
        └── tone_smthn.py
```

## 🔧 Technology Stack

- **Package Manager**: `uv` (fast Python package manager)
- **Python Version**: 3.12.0 (strictly pinned)
- **AI Framework**: CrewAI for agent orchestration
- **Web Framework**: FastAPI for HTTP services
- **Orchestration**: n8n for workflow management

### Key Dependencies

- **AI/ML**: `crewai`, `langchain`, `langgraph`, `scikit-learn`
- **Cloud**: `google-cloud-secret-manager`, `pinecone`
- **Web**: `fastapi`, `uvicorn`
- **Data**: `pandas`, `redis`
- **Utilities**: `pydantic`, `python-dotenv`, `tenacity`

## 📋 TODO

- [x] Create CrewAI-based base agent structure
- [x] Implement linguistic analysis agent
- [x] Set up FastAPI service framework
- [x] Create service runner and main entry point
- [ ] Implement technical analysis agent
- [ ] Implement behavioral analysis agent
- [ ] Implement threat intelligence agent
- [ ] Implement coordination agent
- [ ] Implement chatbot agent
- [ ] Add comprehensive testing
- [ ] Create n8n workflow examples

## 🤝 Contributing

1. Follow the existing code structure
2. Use CrewAI for agent implementation
3. Ensure FastAPI compatibility for n8n integration
4. Add proper error handling and logging
5. Update documentation as needed

## 📄 License

[Add your license information here]