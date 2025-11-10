"""
Explainability Helper - LLM-based explanation generation

Uses Gemini Flash to synthesize findings from all agents into coherent narratives
"""
import logging
from typing import Dict, List, Any
import json
from litellm import completion
import os

from app.Helper.helper_pydantic import ExplanationSummary, AgentContribution

logger = logging.getLogger(__name__)


class ExplanationGenerator:
    """
    Generates human-readable explanations using LLM
    """
    
    def __init__(self):
        """Initialize LLM configuration for explanation generation"""
        self.model = "gemini/gemini-2.0-flash-exp"
        self.api_key = os.getenv("GEMINI_KEY")
        self.temperature = 0.1
        self.max_tokens = 2000
    
    def generate_explanation(
        self,
        email_data: Dict[str, Any],
        agent_contributions: List[AgentContribution],
        final_risk_score: float,
        risk_level: str,
        aggregated_certainty: str = "MEDIUM"  # New parameter (default for backward compat)
    ) -> ExplanationSummary:
        """
        Generate comprehensive explanation using LLM
        
        Args:
            email_data: Original email data
            agent_contributions: Detailed agent contributions
            final_risk_score: Final aggregated risk score
            risk_level: Risk category (CRITICAL, HIGH, MEDIUM, LOW)
            aggregated_certainty: Aggregated certainty level (DEFINITIVE/HIGH/MEDIUM/LOW/INCONCLUSIVE)
            
        Returns:
            ExplanationSummary with narrative and structured findings
        """
        
        # Build context for LLM
        context = self._build_context(
            email_data, 
            agent_contributions, 
            final_risk_score, 
            risk_level, 
            aggregated_certainty
        )
        
        # Generate narrative using LLM
        narrative = self._generate_narrative(context)
        
        # Extract key findings from all agents
        key_findings = self._extract_key_findings(agent_contributions, risk_level)
        
        # Build risk breakdown
        risk_breakdown = self._build_risk_breakdown(agent_contributions, risk_level)
        
        # Generate summary
        summary = self._generate_summary(risk_level, final_risk_score, aggregated_certainty)
        
        # Extract top indicators
        top_indicators = self._extract_top_indicators(agent_contributions)
        
        return ExplanationSummary(
            summary=summary,
            narrative=narrative,
            key_findings=key_findings,
            risk_breakdown=risk_breakdown,
            top_indicators=top_indicators
        )
    
    def _build_context(
        self,
        email_data: Dict[str, Any],
        agent_contributions: List[AgentContribution],
        final_risk_score: float,
        risk_level: str,
        aggregated_certainty: str = "MEDIUM"
    ) -> str:
        """Build context string for LLM prompt"""
        
        context_parts = [
            "# Email Security Analysis Context",
            "",
            "## Email Details",
            f"Subject: {email_data.get('subject', 'N/A')}",
            f"Sender: {email_data.get('sender', 'N/A')}",
            f"Date: {email_data.get('date', 'N/A')}",
            "",
            "## Final Assessment",
            f"Risk Score: {final_risk_score:.2f} ({risk_level})",
            f"Certainty Level: {aggregated_certainty}",
            "",
            "## Agent Analysis Results"
        ]
        
        # Add each agent's contribution
        for contrib in agent_contributions:
            context_parts.extend([
                "",
                f"### {contrib.agent_name.replace('_', ' ').title()}",
                f"- Risk Score: {contrib.risk_score:.2f}",
                f"- Certainty Level: {contrib.certainty_level}",
                f"- Weight: {contrib.weight:.0%}",
                f"- Contribution to final score: {contrib.weighted_contribution:.2f}",
            ])
            
            if contrib.key_findings:
                context_parts.append("- Key Findings:")
                for finding in contrib.key_findings:
                    context_parts.append(f"  • {finding}")
        
        return "\n".join(context_parts)
    
    def _generate_narrative(self, context: str) -> str:
        """
        Generate narrative explanation using LLM
        
        Args:
            context: Context string with all analysis details
            
        Returns:
            LLM-generated narrative explanation
        """
        
        prompt = f"""You are an expert cybersecurity analyst explaining email security assessments to users.

Given the following email security analysis results, write a clear, concise narrative explanation (3-4 sentences) that:
1. Explains the overall risk assessment
2. Identifies the PRIMARY contributing factors (mention which agents found what)
3. Explains HOW different indicators converge (e.g., "The Linguistic Agent detected phishing language while the Threat Intelligence Agent confirmed the URL matches known malware databases")
4. Uses specific evidence (domain age, threat database matches, ML model confidence, etc.)
5. Is written for a technical but not necessarily security-expert audience

{context}

Write the explanation narrative (3-4 sentences, no bullet points):"""

        try:
            response = completion(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity analyst explaining email security assessments to users."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=self.temperature,
                api_key=self.api_key
            )
            
            narrative = response.choices[0].message.content.strip()
            
            # Fallback if LLM fails
            if not narrative or len(narrative) < 50:
                logger.warning("LLM generated insufficient narrative, using fallback")
                narrative = self._generate_fallback_narrative(context)
            
            logger.info(f"Generated narrative explanation ({len(narrative)} chars)")
            return narrative
            
        except Exception as e:
            logger.error(f"LLM narrative generation failed: {str(e)}")
            return self._generate_fallback_narrative(context)
    
    def _generate_fallback_narrative(self, context: str) -> str:
        """Generate fallback narrative without LLM"""
        # Extract risk level from context
        risk_line = [line for line in context.split('\n') if 'Risk Score:' in line]
        if risk_line:
            return f"Email security analysis completed. {risk_line[0]}. " \
                   "Multiple security agents analyzed this email using ML models, " \
                   "infrastructure validation, and threat intelligence databases. " \
                   "See detailed findings below for specific risk indicators."
        return "Email security analysis completed with multi-agent assessment."
    
    def _extract_key_findings(
        self,
        agent_contributions: List[AgentContribution],
        risk_level: str
    ) -> List[str]:
        """
        Extract and format key findings from all agents
        
        Returns:
            List of emoji-prefixed finding strings
        """
        findings = []
        
        # Add emoji based on severity
        emoji_map = {
            "CRITICAL": "🚨 CRITICAL",
            "HIGH": "⚠️ HIGH",
            "MEDIUM": "⚠️ MEDIUM",
            "LOW": "ℹ️ INFO"
        }
        
        for contrib in agent_contributions:
            for finding in contrib.key_findings:
                # Determine severity based on agent contribution
                if contrib.weighted_contribution >= 0.30:
                    severity = "CRITICAL" if risk_level == "CRITICAL" else "HIGH"
                elif contrib.weighted_contribution >= 0.15:
                    severity = "HIGH" if risk_level in ["CRITICAL", "HIGH"] else "MEDIUM"
                else:
                    severity = "MEDIUM" if risk_level != "LOW" else "LOW"
                
                prefix = emoji_map.get(severity, "ℹ️ INFO")
                findings.append(f"{prefix}: {finding}")
        
        # Sort by severity (CRITICAL first)
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
        findings.sort(key=lambda x: severity_order.index(
            x.split(":")[0].replace("🚨 ", "").replace("⚠️ ", "").replace("ℹ️ ", "").strip()
        ))
        
        return findings
    
    def _build_risk_breakdown(
        self,
        agent_contributions: List[AgentContribution],
        risk_level: str
    ) -> Dict[str, str]:
        """
        Build risk breakdown for each agent
        
        Returns:
            Dict mapping agent name to risk explanation
        """
        breakdown = {}
        
        for contrib in agent_contributions:
            agent_display_name = contrib.agent_name.replace('_', ' ').title()
            risk_category = self._categorize_agent_risk(contrib.risk_score)
            
            # Build explanation string
            explanation = f"{risk_category} ({contrib.risk_score:.2f})"
            
            # Add primary finding if available
            if contrib.key_findings:
                primary_finding = contrib.key_findings[0]
                # Remove any emoji prefixes from finding
                primary_finding = primary_finding.split(": ", 1)[-1]
                explanation += f" - {primary_finding}"
            
            breakdown[agent_display_name.lower()] = explanation
        
        return breakdown
    
    def _categorize_agent_risk(self, risk_score: float) -> str:
        """Categorize individual agent risk score"""
        if risk_score >= 0.90:
            return "CRITICAL"
        elif risk_score >= 0.70:
            return "HIGH"
        elif risk_score >= 0.40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_summary(
        self,
        risk_level: str,
        final_risk_score: float,
        aggregated_certainty: str = "MEDIUM"
    ) -> str:
        """
        Generate brief summary (1-2 sentences)
        
        Returns:
            Summary string
        """
        summaries = {
            "CRITICAL": f"This email exhibits critical security threats with {aggregated_certainty} certainty. "
                       "Multiple agents detected severe phishing indicators requiring immediate action.",
            
            "HIGH": f"This email shows strong phishing indicators with {aggregated_certainty} certainty. "
                   "Multiple security agents identified suspicious characteristics.",
            
            "MEDIUM": f"This email contains some suspicious characteristics ({final_risk_score*100:.0f}% risk score, {aggregated_certainty} certainty). "
                     "User review recommended before taking action.",
            
            "LOW": f"This email appears legitimate with minimal risk indicators ({final_risk_score*100:.0f}% risk score, {aggregated_certainty} certainty). "
                  "No significant threats detected."
        }
        
        return summaries.get(risk_level, "Email security analysis completed.")
    
    def _extract_top_indicators(
        self,
        agent_contributions: List[AgentContribution]
    ) -> List[Dict[str, Any]]:
        """
        Extract top indicators from all agents
        
        Returns:
            List of indicator dictionaries sorted by severity
        """
        indicators = []
        
        for contrib in agent_contributions:
            for idx, finding in enumerate(contrib.key_findings):
                # Determine severity based on contribution
                if contrib.weighted_contribution >= 0.30:
                    severity = "CRITICAL"
                elif contrib.weighted_contribution >= 0.15:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                
                indicators.append({
                    "source": contrib.agent_name,
                    "severity": severity,
                    "description": finding,
                    "certainty": contrib.certainty_level,
                    "contribution": contrib.weighted_contribution
                })
        
        # Sort by contribution (highest first)
        indicators.sort(key=lambda x: x["contribution"], reverse=True)
        
        # Return top 5
        return indicators[:5]
