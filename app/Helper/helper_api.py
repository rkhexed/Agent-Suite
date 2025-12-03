"""
API Helper Functions
Utility functions for formatting and processing API requests/responses
"""
from typing import Dict, Any
from datetime import datetime


def format_agent_response(
    agent_name: str,
    email_id: str,
    crew_result: Any,
    execution_time_ms: int
) -> Dict[str, Any]:
    """
    Format CrewAI crew result into standardized API response
    
    CrewAI crews return structured output via Pydantic models.
    Extract the relevant fields and format for API response.
    """
    # Handle different result types
    if hasattr(crew_result, 'dict'):
        # Pydantic model result
        result_dict = crew_result.dict()
    elif isinstance(crew_result, dict):
        # Already a dictionary
        result_dict = crew_result
    else:
        # String or other type - wrap it
        result_dict = {"raw_output": str(crew_result)}
    
    # Extract fields with fallbacks
    # Coordination agent uses "final_risk_score", others use "risk_score"
    risk_score = result_dict.get("final_risk_score", result_dict.get("risk_score", 0.0))
    
    # Coordination agent uses "risk_level", others might not have threat_level
    threat_level = result_dict.get("risk_level", result_dict.get("threat_level", "UNKNOWN"))
    
    # If still UNKNOWN and we have a risk score, derive it
    if threat_level == "UNKNOWN" and risk_score > 0:
        if risk_score >= 0.90:
            threat_level = "CRITICAL"
        elif risk_score >= 0.70:
            threat_level = "HIGH"
        elif risk_score >= 0.40:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
    
    # Coordination agent uses "aggregated_certainty", others use "certainty_level"
    confidence = result_dict.get("aggregated_certainty", result_dict.get("certainty_level", result_dict.get("confidence", 0.0)))
    
    # Convert certainty level to confidence score if needed
    if isinstance(confidence, str):
        confidence_map = {
            "DEFINITIVE": 0.95, 
            "HIGH": 0.85, 
            "MEDIUM": 0.70, 
            "LOW": 0.50,
            "INCONCLUSIVE": 0.30
        }
        confidence = confidence_map.get(confidence.upper(), 0.50)
    
    # Extract analysis text - handle complex objects
    # Coordination agent returns "explanation" object, others return "analysis_reasoning"
    analysis = result_dict.get("analysis_reasoning", result_dict.get("explanation", result_dict.get("reasoning", result_dict.get("detailed_reasoning", ""))))
    
    # If analysis is a dict (like from coordination agent), convert to string
    if isinstance(analysis, dict):
        # Coordination agent returns structured explanation
        summary = analysis.get("summary", "")
        narrative = analysis.get("narrative", "")
        analysis = f"{summary}\n\n{narrative}" if narrative else summary
    
    return {
        "agent": agent_name,
        "email_id": email_id,
        "risk_score": float(risk_score),
        "threat_level": str(threat_level),
        "confidence": float(confidence),
        "indicators": result_dict.get("indicators", result_dict.get("threat_indicators", [])),
        "analysis": str(analysis),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "execution_time_ms": execution_time_ms,
        "raw_result": result_dict  # Include full result for debugging
    }
