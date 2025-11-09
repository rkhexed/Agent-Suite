"""
Domain Age Validator - Lightweight WHOIS-based domain validation
"""
import whois
from datetime import datetime
import logging
from typing import Optional, Tuple

from app.Helper.helper_pydantic import DomainValidation

logger = logging.getLogger(__name__)


class DomainAgeValidator:
    """Simple domain age validation using WHOIS lookups"""
    
    def __init__(self):
        self.whois_timeout = 5  # seconds
    
    def validate(self, domain: str) -> DomainValidation:
        """
        Check domain age and calculate risk score
        
        Args:
            domain: Domain name to validate (e.g., 'example.com')
            
        Returns:
            DomainValidation with age, risk score, and metadata
        """
        logger.info(f"Validating domain: {domain}")
        
        # Get WHOIS data
        age_days, reg_date, whois_available = self._get_domain_age(domain)
        
        # Calculate risk based on age
        risk_score = self._calculate_risk(age_days, whois_available)
        
        # Determine if new domain (< 30 days)
        is_new = age_days is not None and age_days < 30
        
        return DomainValidation(
            domain=domain,
            age_days=age_days,
            registration_date=reg_date,
            is_new_domain=is_new,
            risk_score=risk_score,
            whois_available=whois_available
        )
    
    def _get_domain_age(self, domain: str) -> Tuple[Optional[int], Optional[datetime], bool]:
        """
        Query WHOIS for domain registration date and calculate age
        
        Returns:
            (age_in_days, registration_date, whois_available)
        """
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            # WHOIS sometimes returns a list of dates
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                # Make sure both datetimes are naive (no timezone info) for comparison
                if creation_date.tzinfo is not None:
                    # Remove timezone info for comparison
                    creation_date = creation_date.replace(tzinfo=None)
                
                # Calculate age in days
                age_days = (datetime.now() - creation_date).days
                logger.info(f"Domain {domain} age: {age_days} days (registered {creation_date})")
                return (age_days, creation_date, True)
            
            logger.warning(f"No creation date found for {domain}")
            return (None, None, True)
            
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {str(e)}")
            return (None, None, False)
    
    def _calculate_risk(self, age_days: Optional[int], whois_available: bool) -> float:
        """
        Calculate domain risk score (0-1) based on age
        
        Risk Thresholds (research-backed):
        - < 7 days: 0.9 (very high risk - newly registered)
        - < 30 days: 0.7 (high risk - common phishing threshold)
        - < 90 days: 0.4 (medium risk - relatively new)
        - < 365 days: 0.2 (low-medium risk)
        - >= 365 days: 0.1 (low risk - established domain)
        
        Args:
            age_days: Domain age in days
            whois_available: Whether WHOIS data was available
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        if not whois_available:
            # WHOIS unavailable - moderate risk (could be privacy-protected)
            return 0.3
        
        if age_days is None:
            # No registration date - low risk (likely old domain with private registration)
            return 0.2
        
        # Age-based risk scoring
        if age_days < 7:
            return 0.9  # Very new domain (< 1 week) - very high risk
        elif age_days < 30:
            return 0.7  # New domain (< 1 month) - high risk
        elif age_days < 90:
            return 0.4  # Relatively new (< 3 months) - medium risk
        elif age_days < 365:
            return 0.2  # Less than 1 year - low-medium risk
        else:
            return 0.1  # Established domain (>= 1 year) - low risk
