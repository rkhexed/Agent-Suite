"""
Coordination Agent - Aggregates results from 3 specialized agents

Receives pre-computed results from n8n workflow:
- Linguistic Agent (60% weight)
- Technical Validation Agent (20% weight)  
- Threat Intelligence Agent (20% weight)

Outputs:
- Final risk assessment with confidence
- LLM-generated explanation
- Automated action recommendations
"""
import logging
import time
from typing import Dict, Any
from datetime import datetime

from app.Agents.basic_agent import BaseCybersecurityCrew, AgentResponse
from app.Helper.helper_pydantic import CoordinationResult, CoordinationInput
from app.Helper.helper_aggregation import RiskAggregator
from app.Helper.helper_actions import ActionRecommender
from app.Helper.helper_explainability import ExplanationGenerator

logger = logging.getLogger(__name__)


class CoordinationCrew(BaseCybersecurityCrew):
    """
    Coordination Agent - Aggregates results from all 3 agents (n8n orchestration)
    
    Receives pre-computed results from:
    - Linguistic Analysis Agent (60% weight)
    - Technical Validation Agent (20% weight)
    - Threat Intelligence Agent (20% weight)
    
    Performs:
    - Weighted risk aggregation
    - LLM-based explanation generation
    - Action recommendation
    """
    
    def __init__(self):
        """Initialize coordination agent"""
        super().__init__("Coordination Agent", "1.0.0")
        
        # Initialize helper components
        self.risk_aggregator = RiskAggregator()
        self.action_recommender = ActionRecommender()
        self.explanation_generator = ExplanationGenerator()
    
    def analyze(
        self,
        email_data: Dict[str, Any],
        linguistic_result: Dict[str, Any],
        technical_result: Dict[str, Any],
        threat_intel_result: Dict[str, Any]
    ) -> CoordinationResult:
        """
        Coordinate and aggregate results from all 3 agents with cybersecurity analyst approach
        
        CRITICAL THREAT INTELLIGENCE OVERRIDE:
        If threat intelligence detects DEFINITIVE threats (Google Safe Browsing malware match OR 
        AbuseIPDB 100% abuse confidence), this OVERRIDES all other assessments and triggers
        immediate CRITICAL response regardless of other agent scores.
        
        Args:
            email_data: Original email data for context
            linguistic_result: Complete result from Linguistic Agent
            technical_result: Complete result from Technical Validation Agent
            threat_intel_result: Complete result from Threat Intelligence Agent
            
        Returns:
            CoordinationResult with final assessment, actions, and explanation
        """
        start_time = time.time()
        request_id = f"coord_{int(time.time() * 1000)}"
        
        logger.info(f"Processing coordination request {request_id}")
        
        try:
            # 1. Extract risk scores and certainty levels from each agent
            linguistic_risk, linguistic_certainty, linguistic_reasoning = self._extract_risk_and_certainty(
                linguistic_result, "linguistic"
            )
            technical_risk, technical_certainty, technical_reasoning = self._extract_risk_and_certainty(
                technical_result, "technical_validation"
            )
            threat_risk, threat_certainty, threat_reasoning = self._extract_risk_and_certainty(
                threat_intel_result, "threat_intelligence"
            )
            
            logger.info(f"Extracted scores - Linguistic: {linguistic_risk:.2f} ({linguistic_certainty}), "
                       f"Technical: {technical_risk:.2f} ({technical_certainty}), "
                       f"Threat: {threat_risk:.2f} ({threat_certainty})")
            
            # 2. CRITICAL OVERRIDE LOGIC: Check for DEFINITIVE threats from threat intelligence
            override_active = False
            if threat_certainty == "DEFINITIVE" and threat_risk >= 0.90:
                logger.warning("🚨 THREAT INTELLIGENCE OVERRIDE ACTIVATED - DEFINITIVE threat detected!")
                override_active = True
                final_risk = 0.95  # Force CRITICAL
                risk_level = "CRITICAL"
                aggregated_certainty = "DEFINITIVE"
                detailed_reasoning = (
                    f"CRITICAL THREAT DETECTED - Threat Intelligence Override Activated:\n\n"
                    f"{threat_reasoning}\n\n"
                    f"When authoritative threat databases (Google Safe Browsing, AbuseIPDB) "
                    f"flag content as malicious with DEFINITIVE certainty, this overrides all "
                    f"other analysis. This is a confirmed threat that requires immediate action.\n\n"
                    f"Supporting Analysis:\n"
                    f"- Linguistic: {linguistic_reasoning}\n"
                    f"- Technical: {technical_reasoning}"
                )
            else:
                # 3. Normal aggregation with 60-20-20 weighting
                final_risk, aggregated_certainty, detailed_reasoning, agent_contributions = (
                    self.risk_aggregator.aggregate_risk_scores_with_certainty(
                        linguistic_risk, linguistic_certainty, linguistic_reasoning,
                        technical_risk, technical_certainty, technical_reasoning,
                        threat_risk, threat_certainty, threat_reasoning
                    )
                )
                
                # 4. Categorize risk level
                risk_level = self.risk_aggregator.categorize_risk(final_risk)
            
            # 5. Build agent contributions for both override and normal cases
            if override_active:
                from app.Helper.helper_pydantic import AgentContribution
                agent_contributions = [
                    AgentContribution(
                        agent_name="linguistic",
                        risk_score=linguistic_risk,
                        certainty_level=linguistic_certainty,
                        analysis_reasoning=linguistic_reasoning,
                        weight=0.60,
                        weighted_contribution=0.0,  # Overridden
                        key_findings=[]
                    ),
                    AgentContribution(
                        agent_name="technical_validation",
                        risk_score=technical_risk,
                        certainty_level=technical_certainty,
                        analysis_reasoning=technical_reasoning,
                        weight=0.20,
                        weighted_contribution=0.0,  # Overridden
                        key_findings=[]
                    ),
                    AgentContribution(
                        agent_name="threat_intelligence",
                        risk_score=threat_risk,
                        certainty_level=threat_certainty,
                        analysis_reasoning=threat_reasoning,
                        weight=1.0,  # Override: 100% weight
                        weighted_contribution=0.95,  # Override to CRITICAL
                        key_findings=[]
                    )
                ]
            
            # 6. Calculate uncertainty based on certainty levels
            uncertainty = self._calculate_uncertainty_from_certainty([
                linguistic_certainty, technical_certainty, threat_certainty
            ])
            
            # 7. Extract key findings from each agent
            self._populate_agent_findings(
                agent_contributions,
                linguistic_result,
                technical_result,
                threat_intel_result
            )
            
            # 8. Generate explanation using LLM (only if not overridden - override has detailed_reasoning)
            if not override_active:
                logger.info("Generating explanation with LLM...")
                explanation = self.explanation_generator.generate_explanation(
                    email_data=email_data,
                    agent_contributions=agent_contributions,
                    final_risk_score=final_risk,
                    risk_level=risk_level,
                    aggregated_certainty=aggregated_certainty
                )
            else:
                # Override explanation
                from app.Helper.helper_pydantic import ExplanationSummary
                explanation = ExplanationSummary(
                    summary=f"CRITICAL THREAT: {threat_reasoning[:100]}",
                    narrative=detailed_reasoning,
                    key_findings=[f"🚨 DEFINITIVE threat detected by authoritative sources"],
                    risk_breakdown={
                        "threat_intelligence": f"DEFINITIVE ({threat_risk:.2f}) - OVERRIDE ACTIVE",
                        "linguistic": f"{linguistic_certainty} ({linguistic_risk:.2f})",
                        "technical": f"{technical_certainty} ({technical_risk:.2f})"
                    },
                    top_indicators=[]
                )
            
            # 9. Recommend actions based on risk/certainty (override uses QUARANTINE+BLOCK)
            logger.info(f"Generating action recommendations for {risk_level} risk...")
            recommended_actions = self.action_recommender.recommend_actions(
                risk_score=final_risk,
                risk_level=risk_level,
                certainty=aggregated_certainty,
                override_active=override_active,
                email_data=email_data,
                agent_contributions=[c.dict() for c in agent_contributions]
            )
            
            # 10. Generate user-facing recommendations
            user_recommendations = self.action_recommender.generate_user_recommendations(
                risk_level=risk_level,
                recommended_actions=recommended_actions,
                agent_contributions=[c.dict() for c in agent_contributions]
            )
            
            # 11. Build metadata
            processing_time = time.time() - start_time
            metadata = {
                "request_id": request_id,
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "total_processing_time_ms": int(processing_time * 1000),
                "system_version": "4.0.0",  # Updated for certainty-based system
                "agents_used": ["linguistic", "technical_validation", "threat_intelligence"],
                "agent_weights": {
                    "linguistic": 0.60 if not override_active else 0.0,
                    "technical_validation": 0.20 if not override_active else 0.0,
                    "threat_intelligence": 0.20 if not override_active else 1.0
                },
                "override_active": override_active,
                "models_used": [
                    "dima806/phishing-email-detection (BERT 99.98%)",
                    "all-MiniLM-L6-v2 (embeddings)",
                    "dslim/bert-base-NER",
                    "Mistral Small (explainability)"
                ],
                "external_apis_called": [
                    "Google Safe Browsing",
                    "AbuseIPDB",
                    "WHOIS"
                ]
            }
            
            # 12. Build final coordination result
            result = CoordinationResult(
                final_risk_score=final_risk,
                risk_level=risk_level,
                aggregated_certainty=aggregated_certainty,
                detailed_reasoning=detailed_reasoning,
                uncertainty=uncertainty,
                agent_contributions=agent_contributions,
                explanation=explanation,
                recommended_actions=recommended_actions,
                user_recommendations=user_recommendations,
                metadata=metadata,
                timestamp=datetime.utcnow(),
                processing_time=processing_time
            )
            
            logger.info(f"Coordination complete: {risk_level} risk ({final_risk:.3f}), "
                       f"certainty: {aggregated_certainty}, "
                       f"{len(recommended_actions)} actions, {processing_time:.2f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"Coordination failed: {str(e)}", exc_info=True)
            # Return safe fallback
            return self._generate_fallback_result(email_data, str(e))
    
    def _extract_risk_and_certainty(
        self,
        agent_result: Dict[str, Any],
        agent_name: str
    ) -> tuple[float, str, str]:
        """
        Extract risk score, certainty level, and reasoning from agent result (new format)
        
        Args:
            agent_result: Complete agent result dictionary
            agent_name: Name of the agent
            
        Returns:
            Tuple of (risk_score, certainty_level, analysis_reasoning)
        """
        default_risk = 0.5
        default_certainty = "MEDIUM"
        default_reasoning = "No analysis reasoning provided"
        
        try:
            # Extract from new AgentResponse format
            risk = agent_result.get("risk_score", default_risk)
            certainty = agent_result.get("certainty_level", default_certainty)
            reasoning = agent_result.get("analysis_reasoning", default_reasoning)
            
            # Clamp risk to [0, 1]
            risk = max(0.0, min(1.0, float(risk)))
            
            # Validate certainty level
            valid_certainties = ["DEFINITIVE", "HIGH", "MEDIUM", "LOW", "INCONCLUSIVE"]
            if certainty not in valid_certainties:
                logger.warning(f"{agent_name} returned invalid certainty: {certainty}, using MEDIUM")
                certainty = "MEDIUM"
            
            logger.info(f"{agent_name}: risk={risk:.2f}, certainty={certainty}")
            
            return risk, certainty, reasoning
            
        except Exception as e:
            logger.error(f"Error extracting risk/certainty from {agent_name}: {str(e)}")
            return default_risk, default_certainty, f"Error extracting data: {str(e)}"
    
    def _calculate_uncertainty_from_certainty(self, certainty_levels: list[str]) -> float:
        """
        Calculate overall uncertainty from certainty levels
        
        DEFINITIVE = 0.0 uncertainty
        HIGH = 0.1 uncertainty  
        MEDIUM = 0.3 uncertainty
        LOW = 0.6 uncertainty
        INCONCLUSIVE = 1.0 uncertainty
        
        Args:
            certainty_levels: List of certainty levels from agents
            
        Returns:
            Average uncertainty score (0.0 = certain, 1.0 = highly uncertain)
        """
        certainty_to_uncertainty = {
            "DEFINITIVE": 0.0,
            "HIGH": 0.1,
            "MEDIUM": 0.3,
            "LOW": 0.6,
            "INCONCLUSIVE": 1.0
        }
        
        uncertainties = [certainty_to_uncertainty.get(c, 0.5) for c in certainty_levels]
        return sum(uncertainties) / len(uncertainties) if uncertainties else 0.5
    
    def _populate_agent_findings(
        self,
        agent_contributions: list,
        linguistic_result: Dict[str, Any],
        technical_result: Dict[str, Any],
        threat_intel_result: Dict[str, Any]
    ):
        """
        Populate key_findings for each agent contribution
        
        Modifies agent_contributions in place
        """
        results_map = {
            "linguistic": linguistic_result,
            "technical_validation": technical_result,
            "threat_intelligence": threat_intel_result
        }
        
        for contrib in agent_contributions:
            agent_result = results_map.get(contrib.agent_name)
            if agent_result:
                findings = self.risk_aggregator.extract_key_findings(
                    agent_result,
                    contrib.agent_name,
                    max_findings=3
                )
                contrib.key_findings = findings
    
    def _generate_fallback_result(
        self,
        email_data: Dict[str, Any],
        error_message: str
    ) -> CoordinationResult:
        """
        Generate safe fallback result when coordination fails
        
        Args:
            email_data: Original email data
            error_message: Error description
            
        Returns:
            Safe fallback CoordinationResult
        """
        from app.Helper.helper_pydantic import (
            AgentContribution, ExplanationSummary, RecommendedAction
        )
        
        logger.warning("Using fallback coordination result due to error")
        
        return CoordinationResult(
            final_risk_score=0.5,
            risk_level="MEDIUM",
            aggregated_certainty="INCONCLUSIVE",
            detailed_reasoning=f"Coordination agent failed: {error_message}. Manual review recommended.",
            uncertainty=1.0,
            agent_contributions=[
                AgentContribution(
                    agent_name="linguistic",
                    risk_score=0.0,
                    certainty_level="INCONCLUSIVE",
                    analysis_reasoning="Error: Coordination failed",
                    weight=0.60,
                    weighted_contribution=0.0,
                    key_findings=["Error: Coordination failed"]
                )
            ],
            explanation=ExplanationSummary(
                summary="Email security analysis encountered an error.",
                narrative=f"Coordination agent failed: {error_message}. Manual review recommended.",
                key_findings=["⚠️ ERROR: Automated analysis failed"],
                risk_breakdown={"error": "Coordination failed"},
                top_indicators=[]
            ),
            recommended_actions=[
                RecommendedAction(
                    action_type="TAG",
                    priority="HIGH",
                    confidence=0.0,
                    parameters={"label": "ANALYSIS_ERROR"},
                    requires_approval=False,
                    reasoning="Automated analysis failed - manual review required"
                )
            ],
            user_recommendations=[
                "⚠️ Automated analysis encountered an error",
                "✅ Email has been flagged for manual security review",
                "ℹ️ Exercise caution until manual review is complete"
            ],
            metadata={
                "error": error_message,
                "fallback": True,
                "timestamp": datetime.utcnow().isoformat()
            },
            timestamp=datetime.utcnow()
        )
