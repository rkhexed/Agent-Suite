"""
Action Recommendation Helper - Generate automated actions based on risk assessment

Supports actions: QUARANTINE, BLOCK_SENDER, ALERT, TAG, LOG, NO_ACTION
"""
import logging
from typing import List, Dict, Any
from app.Helper.helper_pydantic import RecommendedAction

logger = logging.getLogger(__name__)


class ActionRecommender:
    """
    Recommends automated actions based on risk score and confidence
    """
    
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
    
    @classmethod
    def recommend_actions(
        cls,
        risk_score: float,
        risk_level: str,
        certainty: str = "MEDIUM",  # New parameter (replaces confidence)
        override_active: bool = False,  # New parameter for threat intelligence override
        email_data: Dict[str, Any] = {},
        agent_contributions: List[Dict[str, Any]] = []
    ) -> List[RecommendedAction]:
        """
        Generate recommended actions based on risk assessment with certainty levels
        
        Args:
            risk_score: Final aggregated risk score (0-1)
            risk_level: Risk category (CRITICAL, HIGH, MEDIUM, LOW)
            certainty: Aggregated certainty level (DEFINITIVE/HIGH/MEDIUM/LOW/INCONCLUSIVE)
            override_active: Whether threat intelligence override is active
            email_data: Original email data for context
            agent_contributions: Agent contribution details
            
        Returns:
            List of recommended actions
        """
        actions = []
        
        sender = email_data.get("sender", "unknown")
        sender_domain = sender.split("@")[-1] if "@" in sender else sender
        
        # Convert certainty to numeric confidence for threshold checks
        certainty_to_confidence = {
            "DEFINITIVE": 0.95,
            "HIGH": 0.85,
            "MEDIUM": 0.70,
            "LOW": 0.50,
            "INCONCLUSIVE": 0.30
        }
        confidence = certainty_to_confidence.get(certainty, 0.70)
        
        # THREAT INTELLIGENCE OVERRIDE: DEFINITIVE threats get immediate QUARANTINE+BLOCK
        if override_active:
            logger.warning(f"🚨 OVERRIDE ACTIVE - Applying DEFINITIVE threat actions")
            actions.extend([
                RecommendedAction(
                    action_type="QUARANTINE",
                    priority="CRITICAL",
                    confidence=0.95,
                    parameters={
                        "reason": "DEFINITIVE threat detected by authoritative threat intelligence sources",
                        "folder": cls.ACTION_CONFIG["quarantine_folder"]
                    },
                    requires_approval=False,
                    reasoning="Threat intelligence flagged this email with DEFINITIVE certainty (Google Safe Browsing or AbuseIPDB 100%). "
                             "This is a confirmed threat from authoritative sources - immediate quarantine required."
                ),
                RecommendedAction(
                    action_type="BLOCK_SENDER",
                    priority="CRITICAL",
                    confidence=0.95,
                    parameters={
                        "scope": "email",
                        "sender_email": sender,
                        "block_duration": "permanent"
                    },
                    requires_approval=False,
                    reasoning=f"Sender '{sender}' confirmed malicious by threat intelligence databases. Blocking immediately."
                )
            ])
            return actions  # Skip normal action logic for override
        
        # CRITICAL RISK (≥ 0.90) + DEFINITIVE/HIGH CERTAINTY
        if risk_score >= 0.90 and certainty in ["DEFINITIVE", "HIGH"]:
            logger.info(f"CRITICAL risk detected ({risk_score:.2f}, {certainty}) - recommending aggressive actions")
            
            actions.extend([
                RecommendedAction(
                    action_type="QUARANTINE",
                    priority="CRITICAL",
                    confidence=confidence,
                    parameters={
                        "reason": f"High-certainty phishing detection with critical risk indicators ({certainty})",
                        "folder": cls.ACTION_CONFIG["quarantine_folder"]
                    },
                    requires_approval=False,
                    reasoning=f"Email exhibits multiple critical phishing indicators with {certainty} certainty. "
                             "Immediate quarantine protects user from potential harm."
                ),
                RecommendedAction(
                    action_type="BLOCK_SENDER",
                    priority="CRITICAL",
                    confidence=confidence,
                    parameters={
                        "scope": "domain",
                        "sender_domain": sender_domain,
                        "sender_email": sender,
                        "block_duration": "permanent"
                    },
                    requires_approval=True,
                    reasoning=f"Sender domain '{sender_domain}' shows malicious patterns with {certainty} certainty. "
                             f"Blocking entire domain recommended, but requires admin approval due to impact."
                ),
                RecommendedAction(
                    action_type="ALERT",
                    priority="CRITICAL",
                    confidence=confidence,
                    parameters={
                        "channels": cls.ACTION_CONFIG["alert_channels"],
                        "recipients": ["security-team@company.com"],
                        "message": f"CRITICAL phishing email detected with {confidence*100:.1f}% confidence",
                        "include_analysis": True
                    },
                    requires_approval=False,
                    reasoning="Security team must be notified immediately about critical phishing attempt."
                ),
                RecommendedAction(
                    action_type="TAG",
                    priority="CRITICAL",
                    confidence=confidence,
                    parameters={
                        "label": "PHISHING_CRITICAL",
                        "color": "red"
                    },
                    requires_approval=False,
                    reasoning="Visual indicator for any user who might encounter this email."
                ),
                RecommendedAction(
                    action_type="LOG",
                    priority="CRITICAL",
                    confidence=confidence,
                    parameters={
                        "retention_days": cls.ACTION_CONFIG["audit_retention_days"]["CRITICAL"],
                        "include_full_analysis": True,
                        "log_level": "security_incident"
                    },
                    requires_approval=False,
                    reasoning="Comprehensive audit trail for security review and incident response (365 day retention)."
                )
            ])
        
        # HIGH RISK (0.70-0.89)
        elif risk_score >= 0.70:
            logger.info(f"HIGH risk detected ({risk_score:.2f}) - recommending protective actions")
            
            actions.extend([
                RecommendedAction(
                    action_type="QUARANTINE",
                    priority="HIGH",
                    confidence=confidence,
                    parameters={
                        "reason": "Suspected phishing with multiple risk indicators",
                        "folder": cls.ACTION_CONFIG["quarantine_folder"]
                    },
                    requires_approval=False,
                    reasoning="Multiple risk indicators detected. Quarantine for user safety."
                ),
                RecommendedAction(
                    action_type="TAG",
                    priority="HIGH",
                    confidence=confidence,
                    parameters={
                        "label": "SUSPECTED_PHISHING",
                        "color": "orange"
                    },
                    requires_approval=False,
                    reasoning="Flag for user awareness and tracking."
                ),
                RecommendedAction(
                    action_type="ALERT",
                    priority="HIGH",
                    confidence=confidence,
                    parameters={
                        "channels": ["email"],
                        "recipients": ["security-team@company.com"],
                        "message": f"High-risk phishing email detected ({confidence*100:.1f}% confidence)",
                        "include_analysis": True
                    },
                    requires_approval=False,
                    reasoning="Notify security team of high-risk detection for monitoring."
                ),
                RecommendedAction(
                    action_type="LOG",
                    priority="HIGH",
                    confidence=confidence,
                    parameters={
                        "retention_days": cls.ACTION_CONFIG["audit_retention_days"]["HIGH"],
                        "include_full_analysis": True,
                        "log_level": "security_warning"
                    },
                    requires_approval=False,
                    reasoning="Audit trail for security review (180 day retention)."
                )
            ])
        
        # MEDIUM RISK (0.40-0.69)
        elif risk_score >= 0.40:
            logger.info(f"MEDIUM risk detected ({risk_score:.2f}) - recommending monitoring actions")
            
            actions.extend([
                RecommendedAction(
                    action_type="TAG",
                    priority="MEDIUM",
                    confidence=confidence,
                    parameters={
                        "label": "REVIEW_REQUIRED",
                        "color": "yellow"
                    },
                    requires_approval=False,
                    reasoning="Some suspicious indicators present. User should review before taking action on email."
                ),
                RecommendedAction(
                    action_type="LOG",
                    priority="MEDIUM",
                    confidence=confidence,
                    parameters={
                        "retention_days": cls.ACTION_CONFIG["audit_retention_days"]["MEDIUM"],
                        "include_full_analysis": False,
                        "log_level": "info"
                    },
                    requires_approval=False,
                    reasoning="Track for pattern analysis (90 day retention)."
                )
            ])
        
        # LOW RISK (< 0.40)
        else:
            logger.info(f"LOW risk detected ({risk_score:.2f}) - no protective actions needed")
            
            actions.append(
                RecommendedAction(
                    action_type="NO_ACTION",
                    priority="LOW",
                    confidence=confidence,
                    parameters={},
                    requires_approval=False,
                    reasoning="Email appears legitimate with no significant risk indicators."
                )
            )
            
            # Optional: Light logging for legitimate emails
            if risk_score > 0.1:  # Very small risk detected
                actions.append(
                    RecommendedAction(
                        action_type="LOG",
                        priority="LOW",
                        confidence=confidence,
                        parameters={
                            "retention_days": cls.ACTION_CONFIG["audit_retention_days"]["LOW"],
                            "include_full_analysis": False,
                            "log_level": "debug"
                        },
                        requires_approval=False,
                        reasoning="Minimal logging for baseline analysis (30 day retention)."
                    )
                )
        
        logger.info(f"Generated {len(actions)} recommended actions for {risk_level} risk")
        return actions
    
    @classmethod
    def generate_user_recommendations(
        cls,
        risk_level: str,
        recommended_actions: List[RecommendedAction],
        agent_contributions: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Generate user-facing recommendations (what the user should do)
        
        Args:
            risk_level: Risk category
            recommended_actions: List of recommended actions
            agent_contributions: Agent contribution details
            
        Returns:
            List of user-facing recommendation strings
        """
        recommendations = []
        
        # Find if quarantine action exists
        is_quarantined = any(
            action.action_type == "QUARANTINE" 
            for action in recommended_actions
        )
        
        if risk_level == "CRITICAL":
            recommendations.extend([
                "🚨 DO NOT click any links or open attachments in this email",
                "🚨 DO NOT provide any credentials or sensitive information",
                "🚨 DO NOT reply to this email or engage with the sender",
            ])
            if is_quarantined:
                recommendations.append("✅ This email has been automatically quarantined for your protection")
            recommendations.extend([
                "✅ Security team has been notified and is investigating",
                "ℹ️ If you believe this is a false positive, contact security team immediately for review"
            ])
            
        elif risk_level == "HIGH":
            recommendations.extend([
                "⚠️ Exercise extreme caution with this email",
                "⚠️ Do not click links or download attachments unless verified",
            ])
            if is_quarantined:
                recommendations.append("✅ This email has been quarantined as a precaution")
            recommendations.extend([
                "✅ Verify sender authenticity through a separate channel before responding",
                "ℹ️ Report suspicious emails to your security team"
            ])
            
        elif risk_level == "MEDIUM":
            recommendations.extend([
                "⚠️ This email has some suspicious characteristics",
                "⚠️ Verify sender identity before clicking links or providing information",
                "✅ Check if you were expecting this email",
                "ℹ️ When in doubt, contact the supposed sender through known contact methods"
            ])
            
        else:  # LOW
            recommendations.extend([
                "✅ Email appears legitimate with no significant risk indicators",
                "ℹ️ Always verify unexpected requests, even from known senders"
            ])
        
        return recommendations
