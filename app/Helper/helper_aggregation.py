"""
Risk Aggregation Helper - Weighted scoring with confidence adjustment

Implements 60-20-20 weighting:
- Linguistic Agent: 60% (primary ML-based defense)
- Technical Validation: 20% (domain age support)
- Threat Intelligence: 20% (known threats support)
"""
import logging
from typing import Dict, List, Tuple
from app.Helper.helper_pydantic import AgentContribution

logger = logging.getLogger(__name__)


class RiskAggregator:
    """
    Aggregates risk scores from multiple agents using weighted scoring
    """
    
    # Agent weights (60-20-20 distribution)
    AGENT_WEIGHTS = {
        "linguistic": 0.60,
        "technical_validation": 0.20,
        "threat_intelligence": 0.20
    }
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        "CRITICAL": 0.90,
        "HIGH": 0.70,
        "MEDIUM": 0.40,
        "LOW": 0.0
    }
    
    @classmethod
    def aggregate_risk_scores(
        cls,
        linguistic_risk: float,
        linguistic_confidence: float,
        technical_risk: float,
        technical_confidence: float,
        threat_risk: float,
        threat_confidence: float
    ) -> Tuple[float, float, List[AgentContribution]]:
        """
        Aggregate risk scores from all 3 agents with weighted averaging
        
        Formula:
        final_risk = sum(agent_risk * agent_confidence * agent_weight) / sum(agent_confidence * agent_weight)
        
        Args:
            linguistic_risk: Risk score from Linguistic Agent (0-1)
            linguistic_confidence: Confidence from Linguistic Agent (0-1)
            technical_risk: Risk score from Technical Validation Agent (0-1)
            technical_confidence: Confidence from Technical Validation Agent (0-1)
            threat_risk: Risk score from Threat Intelligence Agent (0-1)
            threat_confidence: Confidence from Threat Intelligence Agent (0-1)
            
        Returns:
            Tuple of (final_risk_score, overall_confidence, agent_contributions)
        """
        
        # Calculate weighted contributions
        linguistic_contribution = (
            linguistic_risk * linguistic_confidence * cls.AGENT_WEIGHTS["linguistic"]
        )
        technical_contribution = (
            technical_risk * technical_confidence * cls.AGENT_WEIGHTS["technical_validation"]
        )
        threat_contribution = (
            threat_risk * threat_confidence * cls.AGENT_WEIGHTS["threat_intelligence"]
        )
        
        # Calculate normalization factor (sum of weighted confidences)
        normalization_factor = (
            linguistic_confidence * cls.AGENT_WEIGHTS["linguistic"] +
            technical_confidence * cls.AGENT_WEIGHTS["technical_validation"] +
            threat_confidence * cls.AGENT_WEIGHTS["threat_intelligence"]
        )
        
        # Prevent division by zero
        if normalization_factor == 0:
            logger.warning("All agent confidences are zero, defaulting to 0.5 risk")
            final_risk = 0.5
            overall_confidence = 0.0
        else:
            # Calculate final risk score (normalized weighted sum)
            final_risk = (
                linguistic_contribution + 
                technical_contribution + 
                threat_contribution
            ) / normalization_factor
            
            # Overall confidence is weighted average of agent confidences
            overall_confidence = (
                linguistic_confidence * cls.AGENT_WEIGHTS["linguistic"] +
                technical_confidence * cls.AGENT_WEIGHTS["technical_validation"] +
                threat_confidence * cls.AGENT_WEIGHTS["threat_intelligence"]
            )
        
        # Clamp values to [0, 1]
        final_risk = max(0.0, min(1.0, final_risk))
        overall_confidence = max(0.0, min(1.0, overall_confidence))
        
        # Build agent contribution details
        agent_contributions = [
            AgentContribution(
                agent_name="linguistic",
                risk_score=linguistic_risk,
                confidence=linguistic_confidence,
                weight=cls.AGENT_WEIGHTS["linguistic"],
                weighted_contribution=linguistic_contribution / normalization_factor if normalization_factor > 0 else 0.0,
                key_findings=[]  # Will be populated later
            ),
            AgentContribution(
                agent_name="technical_validation",
                risk_score=technical_risk,
                confidence=technical_confidence,
                weight=cls.AGENT_WEIGHTS["technical_validation"],
                weighted_contribution=technical_contribution / normalization_factor if normalization_factor > 0 else 0.0,
                key_findings=[]
            ),
            AgentContribution(
                agent_name="threat_intelligence",
                risk_score=threat_risk,
                confidence=threat_confidence,
                weight=cls.AGENT_WEIGHTS["threat_intelligence"],
                weighted_contribution=threat_contribution / normalization_factor if normalization_factor > 0 else 0.0,
                key_findings=[]
            )
        ]
        
        # Sort by contribution (highest first)
        agent_contributions.sort(key=lambda x: x.weighted_contribution, reverse=True)
        
        logger.info(f"Aggregated risk: {final_risk:.3f} (confidence: {overall_confidence:.3f})")
        logger.info(f"Contributions - Linguistic: {linguistic_contribution:.3f}, "
                   f"Technical: {technical_contribution:.3f}, "
                   f"Threat: {threat_contribution:.3f}")
        
        return final_risk, overall_confidence, agent_contributions
    
    @classmethod
    def aggregate_risk_scores_with_certainty(
        cls,
        linguistic_risk: float,
        linguistic_certainty: str,
        linguistic_reasoning: str,
        technical_risk: float,
        technical_certainty: str,
        technical_reasoning: str,
        threat_risk: float,
        threat_certainty: str,
        threat_reasoning: str
    ) -> Tuple[float, str, str, List[AgentContribution]]:
        """
        Aggregate risk scores with cybersecurity analyst certainty approach (NEW)
        
        Formula: Simple weighted average (no confidence adjustment)
        final_risk = (linguistic_risk * 0.60) + (technical_risk * 0.20) + (threat_risk * 0.20)
        
        Certainty aggregation:
        - If any agent is DEFINITIVE with high risk (≥0.90): aggregated certainty = DEFINITIVE
        - If majority are HIGH+: aggregated certainty = HIGH
        - If majority are MEDIUM+: aggregated certainty = MEDIUM
        - Otherwise: aggregated certainty = LOW or INCONCLUSIVE
        
        Args:
            linguistic_risk, technical_risk, threat_risk: Risk scores (0-1)
            linguistic_certainty, technical_certainty, threat_certainty: Certainty levels (DEFINITIVE/HIGH/MEDIUM/LOW/INCONCLUSIVE)
            linguistic_reasoning, technical_reasoning, threat_reasoning: Analysis reasoning strings
            
        Returns:
            Tuple of (final_risk_score, aggregated_certainty, detailed_reasoning, agent_contributions)
        """
        
        # Calculate simple weighted average (no confidence multiplication)
        linguistic_contribution = linguistic_risk * cls.AGENT_WEIGHTS["linguistic"]
        technical_contribution = technical_risk * cls.AGENT_WEIGHTS["technical_validation"]
        threat_contribution = threat_risk * cls.AGENT_WEIGHTS["threat_intelligence"]
        
        final_risk = linguistic_contribution + technical_contribution + threat_contribution
        final_risk = max(0.0, min(1.0, final_risk))
        
        # Aggregate certainty levels
        certainty_hierarchy = ["DEFINITIVE", "HIGH", "MEDIUM", "LOW", "INCONCLUSIVE"]
        certainty_scores = {
            "DEFINITIVE": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INCONCLUSIVE": 0
        }
        
        # Check for DEFINITIVE threats (highest priority)
        if threat_certainty == "DEFINITIVE" and threat_risk >= 0.90:
            aggregated_certainty = "DEFINITIVE"
        elif linguistic_certainty == "DEFINITIVE" and linguistic_risk >= 0.90:
            aggregated_certainty = "DEFINITIVE"
        else:
            # Weighted average of certainty scores
            weighted_certainty_score = (
                certainty_scores.get(linguistic_certainty, 2) * cls.AGENT_WEIGHTS["linguistic"] +
                certainty_scores.get(technical_certainty, 2) * cls.AGENT_WEIGHTS["technical_validation"] +
                certainty_scores.get(threat_certainty, 2) * cls.AGENT_WEIGHTS["threat_intelligence"]
            )
            
            # Map back to certainty level
            if weighted_certainty_score >= 3.5:
                aggregated_certainty = "DEFINITIVE"
            elif weighted_certainty_score >= 2.5:
                aggregated_certainty = "HIGH"
            elif weighted_certainty_score >= 1.5:
                aggregated_certainty = "MEDIUM"
            elif weighted_certainty_score >= 0.5:
                aggregated_certainty = "LOW"
            else:
                aggregated_certainty = "INCONCLUSIVE"
        
        # Build detailed reasoning
        detailed_reasoning = (
            f"COORDINATED ASSESSMENT (Risk: {final_risk:.2f}, Certainty: {aggregated_certainty}):\n\n"
            f"LINGUISTIC ANALYSIS ({linguistic_certainty}, {linguistic_risk:.2f}):\n{linguistic_reasoning}\n\n"
            f"TECHNICAL VALIDATION ({technical_certainty}, {technical_risk:.2f}):\n{technical_reasoning}\n\n"
            f"THREAT INTELLIGENCE ({threat_certainty}, {threat_risk:.2f}):\n{threat_reasoning}\n\n"
            f"FINAL ASSESSMENT: Weighted aggregation (60-20-20) produces {final_risk:.2f} risk with {aggregated_certainty} certainty."
        )
        
        # Build agent contributions
        agent_contributions = [
            AgentContribution(
                agent_name="linguistic",
                risk_score=linguistic_risk,
                certainty_level=linguistic_certainty,
                analysis_reasoning=linguistic_reasoning,
                weight=cls.AGENT_WEIGHTS["linguistic"],
                weighted_contribution=linguistic_contribution,
                key_findings=[]
            ),
            AgentContribution(
                agent_name="technical_validation",
                risk_score=technical_risk,
                certainty_level=technical_certainty,
                analysis_reasoning=technical_reasoning,
                weight=cls.AGENT_WEIGHTS["technical_validation"],
                weighted_contribution=technical_contribution,
                key_findings=[]
            ),
            AgentContribution(
                agent_name="threat_intelligence",
                risk_score=threat_risk,
                certainty_level=threat_certainty,
                analysis_reasoning=threat_reasoning,
                weight=cls.AGENT_WEIGHTS["threat_intelligence"],
                weighted_contribution=threat_contribution,
                key_findings=[]
            )
        ]
        
        logger.info(f"Aggregated risk: {final_risk:.3f} with {aggregated_certainty} certainty")
        logger.info(f"Contributions - Linguistic: {linguistic_contribution:.3f}, "
                   f"Technical: {technical_contribution:.3f}, "
                   f"Threat: {threat_contribution:.3f}")
        
        return final_risk, aggregated_certainty, detailed_reasoning, agent_contributions
    
    @classmethod
    def categorize_risk(cls, risk_score: float) -> str:
        """
        Categorize risk score into CRITICAL/HIGH/MEDIUM/LOW
        
        Args:
            risk_score: Final risk score (0-1)
            
        Returns:
            Risk level string
        """
        if risk_score >= cls.RISK_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif risk_score >= cls.RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        elif risk_score >= cls.RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        else:
            return "LOW"
    
    @classmethod
    def calculate_uncertainty(cls, confidences: List[float]) -> float:
        """
        Calculate uncertainty metric (1 - average confidence)
        
        Args:
            confidences: List of confidence scores from all agents
            
        Returns:
            Uncertainty score (0-1, where 0 is certain, 1 is uncertain)
        """
        if not confidences:
            return 1.0  # Maximum uncertainty if no confidences
        
        avg_confidence = sum(confidences) / len(confidences)
        uncertainty = 1.0 - avg_confidence
        
        return max(0.0, min(1.0, uncertainty))
    
    @classmethod
    def extract_key_findings(
        cls,
        agent_result: Dict,
        agent_name: str,
        max_findings: int = 3
    ) -> List[str]:
        """
        Extract key findings from an agent's result
        
        Args:
            agent_result: Complete agent result dictionary
            agent_name: Name of the agent
            max_findings: Maximum number of findings to extract
            
        Returns:
            List of key finding strings
        """
        findings = []
        
        try:
            # Extract findings based on agent type
            if agent_name == "linguistic":
                # Get top indicators from linguistic agent
                if "findings" in agent_result:
                    for finding in agent_result["findings"][:max_findings]:
                        severity = finding.get("severity", "UNKNOWN")
                        description = finding.get("description", "")
                        findings.append(f"{severity}: {description}")
                        
            elif agent_name == "technical_validation":
                # Extract domain age and URL metrics
                if "domain_validation" in agent_result:
                    domain_val = agent_result["domain_validation"]
                    if domain_val.get("is_new_domain"):
                        age = domain_val.get("age_days", "unknown")
                        findings.append(f"Domain registered only {age} days ago (high phishing risk)")
                
                if agent_result.get("has_external_links"):
                    url_count = agent_result.get("url_count", 0)
                    findings.append(f"Email contains {url_count} external link(s)")
                    
            elif agent_name == "threat_intelligence":
                # Extract malicious URLs and IP reputation
                malicious_count = agent_result.get("malicious_count", 0)
                if malicious_count > 0:
                    findings.append(f"{malicious_count} malicious URL(s) detected in threat databases")
                
                if "ip_reputation" in agent_result and agent_result["ip_reputation"]:
                    ip_rep = agent_result["ip_reputation"]
                    if ip_rep.get("is_malicious"):
                        abuse_score = ip_rep.get("abuse_score", 0)
                        findings.append(f"Sender IP has abuse score of {abuse_score}/100")
                        
        except Exception as e:
            logger.error(f"Error extracting findings from {agent_name}: {str(e)}")
        
        return findings[:max_findings]
