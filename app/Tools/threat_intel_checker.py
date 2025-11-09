"""
Threat Intelligence Checker - Google Safe Browsing & AbuseIPDB
NO VirusTotal to avoid rate limit issues (4 req/min too restrictive)
"""
import requests
import logging
import os
from typing import List, Optional, Tuple
from datetime import datetime

from app.Helper.helper_pydantic import (
    ThreatSource, 
    URLThreatCheck, 
    IPReputationCheck
)

logger = logging.getLogger(__name__)


class ThreatIntelligenceChecker:
    """
    Lightweight threat intelligence checker using:
    - Google Safe Browsing API (10,000 req/day - FREE)
    - AbuseIPDB API (1,000 req/day - FREE)
    
    NO VirusTotal (4 req/min too restrictive for evaluation)
    """
    
    def __init__(self):
        # Get API keys from environment variables
        self.google_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        
        # API endpoints
        self.google_safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        
        # Timeouts
        self.request_timeout = 5  # seconds
        
        logger.info("ThreatIntelligenceChecker initialized")
        if not self.google_api_key:
            logger.warning("Google Safe Browsing API key not found in environment")
        if not self.abuseipdb_api_key:
            logger.warning("AbuseIPDB API key not found in environment")
    
    def check_url(self, url: str) -> URLThreatCheck:
        """
        Check if URL is malicious using Google Safe Browsing
        
        Args:
            url: URL to check
            
        Returns:
            URLThreatCheck with threat sources and risk score
        """
        logger.info(f"Checking URL: {url}")
        
        threat_sources = []
        
        # Check Google Safe Browsing
        if self.google_api_key:
            google_result = self._check_google_safe_browsing(url)
            if google_result:
                threat_sources.append(google_result)
        else:
            logger.warning("Skipping Google Safe Browsing (no API key)")
        
        # Determine if malicious
        is_malicious = any(source.is_malicious for source in threat_sources)
        
        # Calculate risk score (average of all sources)
        if threat_sources:
            risk_score = sum(s.confidence for s in threat_sources if s.is_malicious) / len(threat_sources)
        else:
            risk_score = 0.0  # No checks = assume safe
        
        return URLThreatCheck(
            url=url,
            is_malicious=is_malicious,
            threat_sources=threat_sources,
            risk_score=risk_score,
            checked_at=datetime.utcnow()
        )
    
    def check_ip(self, ip_address: str) -> Optional[IPReputationCheck]:
        """
        Check IP reputation using AbuseIPDB
        
        Args:
            ip_address: IP address to check
            
        Returns:
            IPReputationCheck or None if check fails
        """
        if not self.abuseipdb_api_key:
            logger.warning("Skipping AbuseIPDB check (no API key)")
            return None
        
        logger.info(f"Checking IP: {ip_address}")
        
        try:
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,  # Check last 90 days
                'verbose': True
            }
            
            response = requests.get(
                self.abuseipdb_url,
                headers=headers,
                params=params,
                timeout=self.request_timeout
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                abuse_score = data.get('abuseConfidenceScore', 0)
                is_malicious = abuse_score > 50  # > 50% confidence = malicious
                
                return IPReputationCheck(
                    ip_address=ip_address,
                    is_malicious=is_malicious,
                    abuse_confidence_score=abuse_score,
                    total_reports=data.get('totalReports', 0),
                    country_code=data.get('countryCode'),
                    usage_type=data.get('usageType')
                )
            else:
                logger.warning(f"AbuseIPDB API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {str(e)}")
            return None
    
    def _check_google_safe_browsing(self, url: str) -> Optional[ThreatSource]:
        """
        Check URL against Google Safe Browsing API
        
        Returns:
            ThreatSource or None if check fails
        """
        try:
            payload = {
                "client": {
                    "clientId": "athena-email-security",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",  # Phishing
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"{self.google_safe_browsing_url}?key={self.google_api_key}",
                json=payload,
                timeout=self.request_timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if threats found
                if 'matches' in data and len(data['matches']) > 0:
                    threat_type = data['matches'][0].get('threatType', 'UNKNOWN')
                    
                    logger.warning(f"Google Safe Browsing: {url} flagged as {threat_type}")
                    
                    return ThreatSource(
                        source_name="Google Safe Browsing",
                        is_malicious=True,
                        threat_type=threat_type,
                        confidence=0.95,  # Google is highly reliable
                        details=f"Flagged as {threat_type}"
                    )
                else:
                    # No threats found
                    logger.info(f"Google Safe Browsing: {url} is clean")
                    return ThreatSource(
                        source_name="Google Safe Browsing",
                        is_malicious=False,
                        threat_type=None,
                        confidence=0.90,
                        details="No threats detected"
                    )
            else:
                logger.error(f"Google Safe Browsing API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Google Safe Browsing check failed: {str(e)}")
            return None
    
    def check_multiple_urls(self, urls: List[str]) -> List[URLThreatCheck]:
        """
        Check multiple URLs for threats
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of URLThreatCheck results
        """
        results = []
        
        # Limit to first 5 URLs to avoid rate limits
        urls_to_check = urls[:5]
        
        if len(urls) > 5:
            logger.warning(f"Limiting URL checks to 5 (received {len(urls)})")
        
        for url in urls_to_check:
            result = self.check_url(url)
            results.append(result)
        
        return results
