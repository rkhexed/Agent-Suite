from typing import Dict, Any, List, Optional, Type
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import logging
from datetime import datetime
import asyncio

from app.Helper.helper_preprocessing import EmailPreprocessor
from app.Helper.helper_constant import (
    THREAT_SCORE_WEIGHTS,
    RECOMMENDATION_TEMPLATES,
)
from app.Helper.helper_pydantic import (
    EmailContent,
    ThreatIndicator,
    ThreatLevel,
    AnalysisResult,
    EmailAnalysisInput
)
from app.ML.semantic_analysis import SemanticAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailContentAnalysisTool(BaseTool):
    name: str = "Advanced Email Analysis Tool"
    description: str = "Enterprise-grade email analysis using ML models and semantic analysis. Analyzes email content for phishing attempts, social engineering, and security threats."
    args_schema: Type[BaseModel] = EmailAnalysisInput

    def __init__(self, **data):
        """Initialize analysis components"""
        super().__init__(**data)
        # Initialize components as private attributes
        object.__setattr__(self, '_preprocessor', EmailPreprocessor())
        object.__setattr__(self, '_semantic_analyzer', SemanticAnalyzer())
        
    def _run(self, email_data: Dict[str, Any]) -> str:
        """
        Performs comprehensive email analysis using ML models and semantic analysis.
        
        Args:
            email_data: Preprocessed email content from n8n
                {
                    "subject": str,
                    "body": str (markdown format),
                    "sender": str,
                    "recipients": List[str],
                    "date": str,
                    "headers": Dict[str, str]
                }
                
        Returns:
            JSON string containing analysis results
        """
        try:
            # Standardize input
            email_content = self._preprocessor.standardize_content(email_data)
            
            # Normalize text for analysis
            normalized_text = self._preprocessor.normalize_text(
                f"{email_content.subject}\n\n{email_content.body}"
            )
            
            # Perform ML-based analysis synchronously
            # Check if there's a running event loop
            try:
                loop = asyncio.get_running_loop()
                # If there's a running loop, we need to create a task
                import nest_asyncio
                nest_asyncio.apply()
                semantic_indicators = asyncio.run(
                    self._semantic_analyzer.analyze_content(normalized_text)
                )
            except RuntimeError:
                # No running loop, safe to use asyncio.run()
                semantic_indicators = asyncio.run(
                    self._semantic_analyzer.analyze_content(normalized_text)
                )
            
            # Calculate overall threat level
            threat_level, confidence = self._calculate_threat_metrics(semantic_indicators)
            
            # Generate comprehensive recommendations
            recommendations = self._generate_recommendations(
                semantic_indicators,
                email_content
            )
            
            # Create result
            result = AnalysisResult(
                threat_level=threat_level,
                confidence_score=confidence,
                indicators=semantic_indicators,
                recommendations=recommendations,
                metadata={
                    "analysis_timestamp": datetime.utcnow().isoformat(),
                    "tool_version": "2.0.0"
                },
                timestamp=datetime.utcnow()
            )
            
            # Return as JSON string per CrewAI best practices
            import json
            return json.dumps(result.dict(), default=str)
            
        except Exception as e:
            logger.error(f"Error in email analysis: {str(e)}", exc_info=True)
            error_result = {
                "error": str(e),
                "threat_level": "unknown",
                "confidence_score": 0.0
            }
            import json
            return json.dumps(error_result)

    def _calculate_threat_metrics(
        self,
        indicators: List[ThreatIndicator]
    ) -> tuple[ThreatLevel, float]:
        """
        Calculate overall threat level and confidence score
        """
        
        # Define severity ordering
        severity_order = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        
        # Get highest severity indicator from ML models
        if indicators:
            max_severity = max(
                (ind.severity for ind in indicators),
                key=lambda x: severity_order.get(x, 0)
            )
        else:
            max_severity = ThreatLevel.LOW
        
        # Calculate confidence based on ML model consensus
        confidence_scores = [ind.confidence for ind in indicators]
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.5
            
        return max_severity, avg_confidence

    def _generate_recommendations(
        self,
        indicators: List[ThreatIndicator],
        email_content: EmailContent
    ) -> List[str]:
        """
        Generate context-aware recommendations based on ML-detected threat types.
        
        Maps ML model detections to actionable security recommendations.
        """
        recommendations = set()
        
        # Add recommendations based on ML-detected threat types
        for indicator in indicators:
            if indicator.type in RECOMMENDATION_TEMPLATES:
                recommendations.update(RECOMMENDATION_TEMPLATES[indicator.type])
                
        return sorted(list(recommendations))
