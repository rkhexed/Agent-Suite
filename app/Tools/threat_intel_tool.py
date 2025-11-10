"""
Threat Intelligence Tool - CrewAI BaseTool wrapper for threat intelligence checking
"""
from crewai.tools import BaseTool
from typing import Type, Any, List
from pydantic import BaseModel, Field
import logging
import time
import re

from app.Tools.threat_intel_checker import ThreatIntelligenceChecker
from app.Helper.helper_preprocessing import EmailPreprocessor
from app.Helper.helper_pydantic import ThreatIntelligenceInput

logger = logging.getLogger(__name__)


class ThreatIntelligenceTool(BaseTool):
    """
    CrewAI tool for threat intelligence analysis.
    
    Uses Google Safe Browsing and AbuseIPDB to check:
    - URLs in email body for known phishing/malware
    - Sender IP reputation
    
    NO VirusTotal (rate limits too restrictive for evaluation)
    """
    
    name: str = "Threat Intelligence Tool"
    description: str = """Check URLs and IPs against threat intelligence databases.
    Queries Google Safe Browsing and AbuseIPDB to detect
    known malicious URLs, phishing sites, and suspicious IP addresses.
    Does NOT use VirusTotal to avoid rate limit issues during evaluation."""
    
    args_schema: Type[BaseModel] = ThreatIntelligenceInput
    
    def __init__(self, **data):
        """Initialize threat intelligence components"""
        super().__init__(**data)
        # Initialize components as private attributes (Pydantic frozen model)
        object.__setattr__(self, '_checker', ThreatIntelligenceChecker())
    
    def _run(self, email_data: dict) -> str:
        """
        Execute threat intelligence checks on email
        
        Args:
            email_data: Email content dictionary
            
        Returns:
            JSON string with threat intelligence results
        """
        start_time = time.time()
        
        try:
            logger.info("Starting threat intelligence analysis")
            
            # Extract email components
            body = email_data.get('body', '')
            sender = email_data.get('sender', '')
            headers = email_data.get('headers', {})
            
            # Extract URLs from email body
            urls = self._extract_urls(body)
            logger.info(f"Extracted {len(urls)} URLs from email")
            
            # Extract IP from headers if available
            ip_address = self._extract_ip_from_headers(headers)
            
            # Check URLs
            url_checks = []
            if urls:
                url_checks = self._checker.check_multiple_urls(urls)
            
            # Check IP reputation
            ip_check = None
            if ip_address:
                ip_check = self._checker.check_ip(ip_address)
            
            # Calculate overall metrics
            malicious_count = sum(1 for check in url_checks if check.is_malicious)
            total_checks = len(url_checks)
            
            # Add IP to malicious count if applicable
            if ip_check and ip_check.is_malicious:
                malicious_count += 1
                total_checks += 1
            
            # Calculate overall risk score
            if total_checks > 0:
                # Weighted average: URLs are more important than IP
                url_risk = sum(check.risk_score for check in url_checks) / len(url_checks) if url_checks else 0.0
                ip_risk = (ip_check.abuse_confidence_score / 100.0) if ip_check and ip_check.is_malicious else 0.0
                
                # Weight: URLs 70%, IP 30%
                if url_checks and ip_check:
                    risk_score = (url_risk * 0.7) + (ip_risk * 0.3)
                elif url_checks:
                    risk_score = url_risk
                elif ip_check:
                    risk_score = ip_risk
                else:
                    risk_score = 0.0
            else:
                risk_score = 0.0  # No threats found
            
            # Calculate confidence
            if total_checks > 0:
                confidence = 0.85 if malicious_count > 0 else 0.80  # Lower confidence for "clean" results
            else:
                confidence = 0.50  # Low confidence when no checks performed
            
            processing_time = int((time.time() - start_time) * 1000)
            
            # Build result
            result = {
                "risk_score": round(risk_score, 2),
                "confidence": confidence,
                "urls_checked": [
                    {
                        "url": check.url,
                        "is_malicious": check.is_malicious,
                        "risk_score": check.risk_score,
                        "threat_sources": [
                            {
                                "source": source.source_name,
                                "malicious": source.is_malicious,
                                "threat_type": source.threat_type,
                                "details": source.details
                            }
                            for source in check.threat_sources
                        ]
                    }
                    for check in url_checks
                ],
                "ip_reputation": {
                    "ip_address": ip_check.ip_address,
                    "is_malicious": ip_check.is_malicious,
                    "abuse_score": ip_check.abuse_confidence_score,
                    "total_reports": ip_check.total_reports,
                    "country": ip_check.country_code
                } if ip_check else None,
                "malicious_count": malicious_count,
                "total_checks": total_checks,
                "processing_time_ms": processing_time
            }
            
            logger.info(f"Threat intelligence analysis complete: {malicious_count}/{total_checks} malicious")
            
            import json
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Threat intelligence check failed: {str(e)}")
            
            # Return safe defaults on error
            return json.dumps({
                "risk_score": 0.5,
                "confidence": 0.0,
                "urls_checked": [],
                "ip_reputation": None,
                "malicious_count": 0,
                "total_checks": 0,
                "processing_time_ms": 0,
                "error": str(e)
            })
    
    def _extract_urls(self, text: str) -> List[str]:
        """
        Extract URLs from text using regex
        
        Args:
            text: Text to extract URLs from
            
        Returns:
            List of URLs
        """
        # URL regex pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls
    
    def _extract_ip_from_headers(self, headers: dict) -> str:
        """
        Extract originating IP from email headers
        
        Args:
            headers: Email headers dictionary
            
        Returns:
            IP address or None
        """
        # Common headers that contain originating IP
        ip_headers = [
            'X-Originating-IP',
            'X-Sender-IP',
            'X-Real-IP',
            'X-Forwarded-For'
        ]
        
        for header in ip_headers:
            if header in headers:
                ip = headers[header]
                # Clean up IP (remove brackets, whitespace)
                ip = ip.strip().strip('<>[]')
                # Basic validation: contains dots and numbers
                if '.' in ip and any(c.isdigit() for c in ip):
                    logger.info(f"Extracted IP from {header}: {ip}")
                    return ip
        
        logger.warning("No originating IP found in headers")
        return None
