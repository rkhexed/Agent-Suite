"""
Technical Email Validation Tool - Lightweight domain age validation
"""
from typing import Dict, Any, Type
from crewai.tools import BaseTool
from pydantic import BaseModel
import logging
import time

from app.Helper.helper_pydantic import (
    TechnicalValidationInput,
    TechnicalValidationResult,
    DomainValidation
)
from app.Helper.helper_preprocessing import EmailPreprocessor
from app.Tools.domain_validator import DomainAgeValidator

logger = logging.getLogger(__name__)


class TechnicalValidationTool(BaseTool):
    name: str = "Technical Email Validation Tool"
    description: str = """Lightweight technical validation focusing on domain age analysis.
    Validates sender domain age via WHOIS lookups to detect suspiciously new domains 
    (< 30 days = likely phishing). Also provides basic email metrics like URL count 
    and external link detection. Does NOT query threat feeds - that's the Threat 
    Intelligence Agent's job."""
    args_schema: Type[BaseModel] = TechnicalValidationInput
    
    def __init__(self, **data):
        """Initialize technical validation components"""
        super().__init__(**data)
        # Initialize components as private attributes (Pydantic frozen model)
        object.__setattr__(self, '_preprocessor', EmailPreprocessor())
        object.__setattr__(self, '_domain_validator', DomainAgeValidator())
    
    def _run(self, email_data: Dict[str, Any]) -> str:
        """
        Performs lightweight technical validation
        
        Args:
            email_data: Email content data
                {
                    "sender": "user@example.com",
                    "body": "email body with URLs...",
                    "subject": "email subject"
                }
        
        Returns:
            JSON string containing validation results
        """
        start_time = time.time()
        
        try:
            sender = email_data.get('sender', '')
            body = email_data.get('body', '')
            
            # Extract sender domain
            sender_domain = sender.split('@')[-1] if '@' in sender else ''
            
            if not sender_domain:
                logger.warning("No sender domain found in email data")
                return self._error_result("No sender domain found")
            
            # 1. Domain Age Validation (primary signal)
            domain_validation = self._domain_validator.validate(sender_domain)
            
            # 2. Simple Email Metrics
            urls = self._preprocessor.extract_markdown_links(body)
            url_count = len(urls)
            
            # Check for external links (URLs with different domain than sender)
            has_external = any(
                sender_domain not in url.lower()
                for url in urls
            ) if urls else False
            
            # 3. Calculate Overall Risk
            # Primary signal is domain age risk
            risk_score = domain_validation.risk_score
            
            # Confidence based on WHOIS availability
            confidence = 0.9 if domain_validation.whois_available else 0.5
            
            # Calculate processing time
            processing_time = int((time.time() - start_time) * 1000)
            
            # Build result
            result = TechnicalValidationResult(
                risk_score=risk_score,
                confidence=confidence,
                domain_validation=domain_validation,
                url_count=url_count,
                has_external_links=has_external,
                processing_time_ms=processing_time
            )
            
            logger.info(f"Technical validation complete: risk={risk_score:.2f}, domain_age={domain_validation.age_days}")
            
            # Return as JSON string (CrewAI best practice)
            import json
            return json.dumps(result.dict(), default=str)
            
        except Exception as e:
            logger.error(f"Error in technical validation: {str(e)}", exc_info=True)
            return self._error_result(str(e))
    
    def _error_result(self, error_msg: str) -> str:
        """Return error result as JSON"""
        error_result = {
            "error": error_msg,
            "risk_score": 0.5,
            "confidence": 0.0
        }
        import json
        return json.dumps(error_result)
