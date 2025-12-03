"""
Database Helper Functions
SQLite connection and CRUD operations for email security analysis
"""
import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from uuid import UUID
import uuid
import json

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

# Database connection - SQLite for simplicity
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "phishing_detection.db"
)
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Create engine
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database():
    """Initialize SQLite database tables"""
    try:
        with engine.connect() as conn:
            # Create tables using SQLite syntax
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS emails (
                    id TEXT PRIMARY KEY,
                    email_uid TEXT UNIQUE,
                    subject TEXT,
                    sender TEXT,
                    recipient TEXT,
                    body TEXT,
                    headers TEXT,
                    metadata TEXT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    final_risk_score REAL,
                    final_threat_level TEXT,
                    final_action TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS agent_analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id TEXT,
                    agent_name TEXT,
                    risk_score REAL,
                    threat_level TEXT,
                    confidence REAL,
                    indicators TEXT,
                    analysis TEXT,
                    execution_time_ms INTEGER,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email_id) REFERENCES emails(id)
                )
            """))
            
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS coordination_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_id TEXT,
                    final_risk_score REAL,
                    risk_level TEXT,
                    aggregated_certainty TEXT,
                    detailed_reasoning TEXT,
                    uncertainty REAL,
                    agent_contributions TEXT,
                    explanation TEXT,
                    recommended_actions TEXT,
                    execution_time_ms INTEGER,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email_id) REFERENCES emails(id)
                )
            """))
            
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_emails_email_uid ON emails(email_uid)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_agent_analyses_email_id ON agent_analyses(email_id)
            """))
            
            conn.commit()
            
        logger.info(f"SQLite database initialized at {DB_PATH}")
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        return False


def store_email(
    email_uid: str,
    subject: str,
    sender: str,
    recipient: str,
    body: str,
    headers: Dict[str, Any] = None,
    metadata: Dict[str, Any] = None
) -> str:
    """
    Store or update email record, return UUID
    
    Returns:
        UUID string of the email record
    """
    db = SessionLocal()
    try:
        # Check if email already exists
        result = db.execute(
            text("SELECT id FROM emails WHERE email_uid = :uid"),
            {"uid": email_uid}
        ).fetchone()
        
        if result:
            email_id = result[0]
            logger.info(f"Email {email_uid} already exists with ID {email_id}")
        else:
            # Generate new UUID
            email_id = str(uuid.uuid4())
            
            # Insert new email
            db.execute(
                text("""
                    INSERT INTO emails (id, email_uid, subject, sender, recipient, body, headers, metadata)
                    VALUES (:id, :uid, :subject, :sender, :recipient, :body, :headers, :metadata)
                """),
                {
                    "id": email_id,
                    "uid": email_uid,
                    "subject": subject,
                    "sender": sender,
                    "recipient": recipient,
                    "body": body,
                    "headers": json.dumps(headers or {}),
                    "metadata": json.dumps(metadata or {})
                }
            )
            db.commit()
            logger.info(f"Stored new email {email_uid} with ID {email_id}")
        
        return email_id
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to store email: {str(e)}")
        raise
    finally:
        db.close()


def store_agent_analysis(
    email_id: str,
    agent_name: str,
    analysis: Dict[str, Any]
) -> int:
    """
    Store agent analysis result
    
    Args:
        email_id: UUID string of the email
        agent_name: Name of the agent
        analysis: Complete analysis result dictionary
        
    Returns:
        ID of the analysis record
    """
    db = SessionLocal()
    try:
        db.execute(
            text("""
                INSERT INTO agent_analyses 
                (email_id, agent_name, risk_score, threat_level, confidence, 
                 indicators, analysis, execution_time_ms)
                VALUES (:email_id, :agent, :risk, :threat, :conf, :indicators, :analysis, :time)
            """),
            {
                "email_id": email_id,
                "agent": agent_name,
                "risk": analysis.get("risk_score", 0.0),
                "threat": analysis.get("threat_level", "UNKNOWN"),
                "conf": analysis.get("confidence", 0.0),
                "indicators": json.dumps(analysis.get("indicators", [])),
                "analysis": analysis.get("analysis", ""),
                "time": analysis.get("execution_time_ms", 0)
            }
        )
        
        db.commit()
        logger.info(f"Stored {agent_name} analysis for email {email_id}")
        
        return 1
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to store agent analysis: {str(e)}")
        raise
    finally:
        db.close()


def update_email_final_assessment(
    email_id: str,
    risk_score: float,
    threat_level: str,
    action: str
):
    """
    Update email with final coordination assessment
    
    Args:
        email_id: UUID string of the email
        risk_score: Final aggregated risk score
        threat_level: Final threat level
        action: Final action (QUARANTINE, ALLOW)
    """
    db = SessionLocal()
    try:
        db.execute(
            text("""
                UPDATE emails 
                SET final_risk_score = :risk, 
                    final_threat_level = :threat,
                    final_action = :action
                WHERE id = :email_id
            """),
            {
                "email_id": email_id,
                "risk": risk_score,
                "threat": threat_level,
                "action": action
            }
        )
        db.commit()
        logger.info(f"Updated final assessment for email {email_id}: {action}")
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update email assessment: {str(e)}")
        raise
    finally:
        db.close()


def get_email_by_id(email_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve email with all agent analyses
    
    Args:
        email_id: UUID string of the email
        
    Returns:
        Dictionary containing email and all analyses, or None if not found
    """
    db = SessionLocal()
    try:
        logger.info(f"Getting email details for ID: {email_id}")
        
        # Get email
        email_result = db.execute(
            text("SELECT * FROM emails WHERE id = :id"),
            {"id": email_id}
        ).fetchone()
        
        if not email_result:
            logger.warning(f"Email {email_id} not found")
            return None
        
        # Get all agent analyses
        analyses_result = db.execute(
            text("""
                SELECT agent_name, risk_score, threat_level, confidence, 
                       indicators, analysis, execution_time_ms, analyzed_at
                FROM agent_analyses 
                WHERE email_id = :id
                ORDER BY analyzed_at ASC
            """),
            {"id": email_id}
        ).fetchall()
        
        # Build response
        email_dict = dict(email_result._mapping)
        
        # Handle received_at datetime
        received_at = email_dict.get("received_at")
        
        logger.info(f"Found email with {len(analyses_result)} analyses")
        
        return {
            "email": {
                "id": str(email_dict["id"]),
                "email_uid": email_dict["email_uid"],
                "subject": email_dict["subject"],
                "sender": email_dict["sender"],
                "recipient": email_dict["recipient"],
                "body": email_dict["body"],
                "received_at": received_at,
                "final_risk_score": email_dict.get("final_risk_score"),
                "final_threat_level": email_dict.get("final_threat_level"),
                "final_action": email_dict.get("final_action")
            },
            "analyses": {
                row.agent_name: {
                    "risk_score": row.risk_score,
                    "threat_level": row.threat_level,
                    "confidence": row.confidence,
                    "indicators": row.indicators,
                    "analysis": row.analysis,
                    "execution_time_ms": row.execution_time_ms
                }
                for row in analyses_result
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to retrieve email: {str(e)}", exc_info=True)
        return None
    finally:
        db.close()


def list_recent_emails(limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
    """
    List recent emails with summary info
    
    Args:
        limit: Maximum number of emails to return
        offset: Offset for pagination
        
    Returns:
        List of email summaries
    """
    db = SessionLocal()
    try:
        logger.info(f"Querying emails with limit={limit}, offset={offset}")
        results = db.execute(
            text("""
                SELECT 
                    e.id,
                    e.subject,
                    e.sender,
                    e.recipient,
                    e.received_at,
                    e.final_risk_score,
                    e.final_threat_level,
                    e.final_action,
                    COUNT(a.id) as analysis_count
                FROM emails e
                LEFT JOIN agent_analyses a ON e.id = a.email_id
                GROUP BY e.id
                ORDER BY e.received_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"limit": limit, "offset": offset}
        ).fetchall()
        
        logger.info(f"Query returned {len(results)} rows")
        
        emails = []
        for row in results:
            try:
                # Handle received_at - might be string or datetime
                received_at = row[4]
                if received_at and not isinstance(received_at, str):
                    received_at = received_at.isoformat()
                
                emails.append({
                    "id": str(row[0]),  # e.id
                    "subject": row[1],  # e.subject
                    "sender": row[2],  # e.sender
                    "recipient": row[3],  # e.recipient
                    "received_at": received_at,  # e.received_at
                    "final_risk_score": row[5],  # e.final_risk_score
                    "final_threat_level": row[6],  # e.final_threat_level
                    "final_action": row[7],  # e.final_action
                    "analysis_count": row[8]  # COUNT(a.id)
                })
            except Exception as e:
                logger.error(f"Failed to parse row: {str(e)} | Row data: {row}")
                continue
        
        logger.info(f"Successfully parsed {len(emails)} emails")
        return emails
        
    except Exception as e:
        logger.error(f"Failed to list emails: {str(e)}")
        return []
    finally:
        db.close()
