#!/usr/bin/env python3
"""
FastAPI Main Server - Multi-Agent Email Security System
Provides REST API endpoints for n8n workflow integration
"""

import sys
import os
from typing import Dict, Any
import time
import asyncio
import logging
from datetime import datetime

# Add the app directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import agents
from app.Agents.linguistic_agent import LinguisticAnalysisCrew
from app.Agents.technical_validation_agent import TechnicalValidationCrew
from app.Agents.threat_intel_agent import ThreatIntelligenceCrew
from app.Agents.coordination_agent import CoordinationCrew

# Import Pydantic models and helpers
from app.Helper.helper_pydantic import AnalyzeRequest, AgentResponse, CoordinationRequest
from app.Helper.helper_api import format_agent_response
from app.Helper.helper_database import (
    init_database, store_email, store_agent_analysis, 
    update_email_final_assessment, get_email_by_id, list_recent_emails
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Agent Initialization
# ============================================================================

app = FastAPI(
    title="Multi-Agent Email Security API",
    description="REST API for multi-agent phishing detection system",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For demo purposes; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Agent Initialization
# ============================================================================

# Initialize agent crews lazily (on first request)
linguistic_crew = None
technical_crew = None
threat_intel_crew = None
coordination_crew = None


def get_linguistic_crew():
    """Get or create linguistic analysis crew"""
    global linguistic_crew
    if linguistic_crew is None:
        logger.info("Initializing Linguistic Analysis Crew...")
        linguistic_crew = LinguisticAnalysisCrew()
        linguistic_crew.setup_crew()
    return linguistic_crew


def get_technical_crew():
    """Get or create technical validation crew"""
    global technical_crew
    if technical_crew is None:
        logger.info("Initializing Technical Validation Crew...")
        technical_crew = TechnicalValidationCrew()
        technical_crew.setup_crew()
    return technical_crew


def get_threat_intel_crew():
    """Get or create threat intelligence crew"""
    global threat_intel_crew
    if threat_intel_crew is None:
        logger.info("Initializing Threat Intelligence Crew...")
        threat_intel_crew = ThreatIntelligenceCrew()
        threat_intel_crew.setup_crew()
    return threat_intel_crew


def get_coordination_crew():
    """Get or create coordination crew"""
    global coordination_crew
    if coordination_crew is None:
        logger.info("Initializing Coordination Crew...")
        coordination_crew = CoordinationCrew()
    return coordination_crew


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint - API status"""
    return {
        "service": "Multi-Agent Email Security API",
        "status": "operational",
        "version": "1.0.0",
        "agents": ["linguistic", "technical", "threat-intel", "coordination"],
        "endpoints": {
            "linguistic": "/api/linguistic/analyze",
            "technical": "/api/technical/analyze",
            "threat_intel": "/api/threat-intel/analyze",
            "coordination": "/api/coordination/analyze"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    from datetime import datetime
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "agents_loaded": {
            "linguistic": linguistic_crew is not None,
            "technical": technical_crew is not None,
            "threat_intel": threat_intel_crew is not None,
            "coordination": coordination_crew is not None
        }
    }


@app.post("/api/linguistic/analyze", response_model=AgentResponse)
async def analyze_linguistic(request: AnalyzeRequest):
    """
    Linguistic Analysis Agent Endpoint
    Analyzes email content for social engineering, urgency, authority impersonation
    """
    start_time = time.time()
    
    try:
        logger.info(f"Linguistic analysis requested for email: {request.email_id}")
        
        # Store email in database (creates UUID if new)
        email_uuid = store_email(
            email_uid=request.email_id,
            subject=request.subject,
            sender=request.sender,
            recipient=request.recipient or "",
            body=request.body,
            headers=request.headers or {},
            metadata=request.metadata or {}
        )
        logger.info(f"Email stored with UUID: {email_uuid}")
        
        crew = get_linguistic_crew()
        
        # Prepare request data for CrewAI
        request_data = {
            "email_data": {
                "subject": request.subject,
                "sender": request.sender,
                "body": request.body,
                "recipient": request.recipient or "",
                "headers": request.headers or {}
            },
            "request_id": request.email_id,
            "metadata": request.metadata or {"source": "api"}
        }
        
        # Run CrewAI crew (process_request method)
        crew_response = await crew.process_request(request_data)
        
        execution_time = int((time.time() - start_time) * 1000)
        
        # Format response
        response = format_agent_response(
            "linguistic",
            request.email_id,
            crew_response,
            execution_time
        )
        
        # Store analysis in database
        store_agent_analysis(email_uuid, "linguistic", response)
        
        logger.info(f"Linguistic analysis completed: {execution_time}ms")
        return response
        
    except Exception as e:
        logger.error(f"Linguistic analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/technical/analyze", response_model=AgentResponse)
async def analyze_technical(request: AnalyzeRequest):
    """
    Technical Validation Agent Endpoint
    Analyzes email headers, DNS, domain reputation, technical indicators
    """
    start_time = time.time()
    
    try:
        logger.info(f"Technical analysis requested for email: {request.email_id}")
        
        # Get or create email UUID
        email_uuid = store_email(
            email_uid=request.email_id,
            subject=request.subject,
            sender=request.sender,
            recipient=request.recipient or "",
            body=request.body,
            headers=request.headers or {},
            metadata=request.metadata or {}
        )
        
        crew = get_technical_crew()
        
        # Prepare request data for CrewAI
        request_data = {
            "email_data": {
                "subject": request.subject,
                "sender": request.sender,
                "body": request.body,
                "recipient": request.recipient or "",
                "headers": request.headers or {}
            },
            "request_id": request.email_id,
            "metadata": request.metadata or {"source": "api"}
        }
        
        # Run CrewAI crew
        crew_response = await crew.process_request(request_data)
        
        execution_time = int((time.time() - start_time) * 1000)
        
        # Format response
        response = format_agent_response(
            "technical",
            request.email_id,
            crew_response,
            execution_time
        )
        
        # Store analysis in database
        store_agent_analysis(email_uuid, "technical", response)
        
        logger.info(f"Technical analysis completed: {execution_time}ms")
        return response
        
    except Exception as e:
        logger.error(f"Technical analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/threat-intel/analyze", response_model=AgentResponse)
async def analyze_threat_intel(request: AnalyzeRequest):
    """
    Threat Intelligence Agent Endpoint
    Checks against threat feeds, blacklists, reputation databases
    """
    start_time = time.time()
    
    try:
        logger.info(f"Threat intel analysis requested for email: {request.email_id}")
        
        # Get or create email UUID
        email_uuid = store_email(
            email_uid=request.email_id,
            subject=request.subject,
            sender=request.sender,
            recipient=request.recipient or "",
            body=request.body,
            headers=request.headers or {},
            metadata=request.metadata or {}
        )
        
        crew = get_threat_intel_crew()
        
        # Prepare request data for CrewAI
        request_data = {
            "email_data": {
                "subject": request.subject,
                "sender": request.sender,
                "body": request.body,
                "recipient": request.recipient or "",
                "headers": request.headers or {}
            },
            "request_id": request.email_id,
            "metadata": request.metadata or {"source": "api"}
        }
        
        # Run CrewAI crew
        crew_response = await crew.process_request(request_data)
        
        execution_time = int((time.time() - start_time) * 1000)
        
        # Format response
        response = format_agent_response(
            "threat_intel",
            request.email_id,
            crew_response,
            execution_time
        )
        
        # Store analysis in database
        store_agent_analysis(email_uuid, "threat_intel", response)
        
        logger.info(f"Threat intel analysis completed: {execution_time}ms")
        return response
        
    except Exception as e:
        logger.error(f"Threat intel analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/coordination/analyze", response_model=AgentResponse)
async def analyze_coordination(request: CoordinationRequest):
    """
    Coordination Agent Endpoint
    Aggregates results from all 3 agents and makes final decision
    Uses 60-20-20 weighted aggregation (Linguistic 60%, Technical 20%, Threat Intel 20%)
    """
    start_time = time.time()
    
    try:
        logger.info(f"Coordination analysis requested for email: {request.email_id}")
        
        # Get email UUID from database
        email_uuid = store_email(
            email_uid=request.email_id,
            subject="",  # Already stored by previous agents
            sender="",
            recipient="",
            body="",
            headers={},
            metadata={}
        )
        
        crew = get_coordination_crew()
        
        # CoordinationCrew.analyze() expects: email_data, linguistic_result, technical_result, threat_intel_result
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            crew.analyze,
            request.email_data or {},
            request.linguistic_result,
            request.technical_result,
            request.threat_intel_result
        )
        
        execution_time = int((time.time() - start_time) * 1000)
        
        # Format response
        response = format_agent_response(
            "coordination",
            request.email_id,
            result,
            execution_time
        )
        
        # Store coordination analysis
        store_agent_analysis(email_uuid, "coordination", response)
        
        # Update email with final assessment
        final_action = "QUARANTINE" if response.get("risk_score", 0) >= 0.5 else "ALLOW"
        update_email_final_assessment(
            email_uuid,
            response.get("risk_score", 0),
            response.get("threat_level", "UNKNOWN"),
            final_action
        )
        
        logger.info(f"Coordination analysis completed: {execution_time}ms, Action: {final_action}")
        return response
        
    except Exception as e:
        logger.error(f"Coordination analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ============================================================================
# Email Retrieval Endpoints (for Frontend)
# ============================================================================

@app.get("/api/emails")
async def list_emails(
    limit: int = 10,
    offset: int = 0,
    risk_filter: str = None  # "high", "medium", "low", or None for all
):
    """
    List recent emails with their final risk assessments.
    
    Query Parameters:
    - limit: Maximum number of emails to return (default: 10)
    - offset: Number of emails to skip for pagination (default: 0)
    - risk_filter: Filter by threat level ("high", "medium", "low", or None)
    
    Returns:
    - Array of email summaries with risk scores and actions
    """
    try:
        logger.info(f"Retrieving emails: limit={limit}, offset={offset}, filter={risk_filter}")
        emails = list_recent_emails(limit, offset)
        
        # Apply risk filter if specified
        if risk_filter:
            risk_filter_upper = risk_filter.upper()
            emails = [e for e in emails if e.get("final_threat_level") == risk_filter_upper]
        
        logger.info(f"Retrieved {len(emails)} emails")
        return {
            "emails": emails,
            "count": len(emails),
            "limit": limit,
            "offset": offset,
            "filter": risk_filter
        }
        
    except Exception as e:
        logger.error(f"Failed to retrieve emails: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve emails: {str(e)}")


@app.get("/api/emails/{email_id}")
async def get_email_details(email_id: str):
    """
    Get full email details including all agent analyses.
    
    Path Parameters:
    - email_id: UUID of the email
    
    Returns:
    - email: Email metadata and content
    - analyses: All 4 agent analyses (linguistic, technical, threat_intel, coordination)
    """
    try:
        logger.info(f"Retrieving email details: {email_id}")
        email_data = get_email_by_id(email_id)
        
        if not email_data:
            raise HTTPException(status_code=404, detail=f"Email {email_id} not found")
        
        logger.info(f"Retrieved email: {email_data['email'].get('subject', 'No Subject')}")
        return email_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve email {email_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve email: {str(e)}")
    
@app.get("/api/emails/{email_id}/details")
async def get_email_details(email_id: str):
    """
    Returns concise email details for frontend display.
    """
    from app.Helper.helper_database import get_email_by_id
    email_data = get_email_by_id(email_id)
    if not email_data:
        raise HTTPException(status_code=404, detail=f"Email {email_id} not found")
    email = email_data["email"]
    return {
        "id": email["id"],
        "sender": email["sender"],
        "subject": email["subject"],
        "timestamp": email["received_at"],
        "body": email["body"],
        "final_risk_score": email.get("final_risk_score"),
        "final_action": email.get("final_action")
    }


# ============================================================================
# Email Review Chat Endpoints (5th Agent)
# ============================================================================

from pydantic import BaseModel

class ChatRequest(BaseModel):
    message: str

@app.post("/api/emails/{email_id}/chat")
async def chat_about_email(email_id: str, request: ChatRequest):
    """
    Chat with AI about a specific email's security analysis (text-based).
    
    Path Parameters:
    - email_id: UUID of the email
    
    Body Parameters:
    - message: User's question/message
    
    Returns:
    - response: AI's response to the user's question
    - timestamp: Response timestamp
    """
    try:
        from app.Agents.email_review_chat_agent import EmailReviewChatAgent
        message = request.message
        logger.info(f"Chat request for email {email_id}: {message[:100]}")
        
        # Get email data with all analyses
        email_data = get_email_by_id(email_id)
        if not email_data:
            raise HTTPException(status_code=404, detail=f"Email {email_id} not found")
        
        # Initialize chat agent
        chat_agent = EmailReviewChatAgent()
        
        # Get response
        response = chat_agent.chat(
            email_data=email_data,
            user_message=message,
            conversation_history=None  # TODO: Add session management for history
        )
        
        logger.info(f"Chat response generated for email {email_id}")
        
        return {
            "email_id": email_id,
            "response": response,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat failed for email {email_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Chat failed: {str(e)}")


@app.post("/api/emails/{email_id}/chat/voice")
async def chat_about_email_voice(email_id: str, audio: UploadFile = File(...)):
    """
    Chat with AI about a specific email's security analysis using voice input.
    
    Path Parameters:
    - email_id: UUID of the email
    
    Body Parameters:
    - audio: Audio file (mp3, wav, m4a, etc.)
    
    Returns:
    - transcription: What the user said
    - response: AI's response to the user's question
    - timestamp: Response timestamp
    """
    import tempfile
    import whisper
    
    try:
        from app.Agents.email_review_chat_agent import EmailReviewChatAgent
        
        logger.info(f"Voice chat request for email {email_id}")
        
        # Get email data with all analyses
        email_data = get_email_by_id(email_id)
        if not email_data:
            raise HTTPException(status_code=404, detail=f"Email {email_id} not found")
        
        # Save uploaded audio to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as temp_audio:
            content = await audio.read()
            temp_audio.write(content)
            temp_audio_path = temp_audio.name
        
        try:
            # Load Whisper model (using 'base' for balance of speed/accuracy)
            logger.info("Loading Whisper model...")
            model = whisper.load_model("base")  # Options: tiny, base, small, medium, large
            
            # Transcribe audio
            logger.info(f"Transcribing audio file: {audio.filename}")
            result = model.transcribe(temp_audio_path)
            transcription = result["text"]
            
            logger.info(f"Transcription: {transcription}")
            
            # Initialize chat agent
            chat_agent = EmailReviewChatAgent()
            
            # Get response using transcribed text
            response = chat_agent.chat(
                email_data=email_data,
                user_message=transcription,
                conversation_history=None
            )
            
            logger.info(f"Voice chat response generated for email {email_id}")
            
            return {
                "email_id": email_id,
                "transcription": transcription,
                "response": response,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
        finally:
            # Clean up temp file
            os.remove(temp_audio_path)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Voice chat failed for email {email_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Voice chat failed: {str(e)}")


# ============================================================================
# Application Startup
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    logger.info("=" * 60)
    logger.info("Multi-Agent Email Security API Starting...")
    logger.info("=" * 60)
    
    # Initialize database
    logger.info("Initializing SQLite database...")
    if init_database():
        logger.info("✅ Database initialized successfully")
    else:
        logger.error("❌ Database initialization failed")
    
    logger.info("Endpoints available:")
    logger.info("  POST /api/linguistic/analyze")
    logger.info("  POST /api/technical/analyze")
    logger.info("  POST /api/threat-intel/analyze")
    logger.info("  POST /api/coordination/analyze")
    logger.info("  GET  /api/emails")
    logger.info("  GET  /api/emails/{id}")
    logger.info("=" * 60)


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown"""
    logger.info("Shutting down Multi-Agent Email Security API...")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Start the FastAPI server"""
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )


if __name__ == "__main__":
    main()
