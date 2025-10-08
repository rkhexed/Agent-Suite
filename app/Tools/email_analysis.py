from typing import Dict, Any, List, Optional
from crewai.tools import BaseTool
import logging
from datetime import datetime
import asyncio
from functools import wraps
from app.Helper.helper_preprocessing import EmailPreprocessor
from app.Helper.helper_constant import (
    THREAT_SCORE_WEIGHTS,
    RECOMMENDATION_TEMPLATES,
)
from app.Helper.helper_pydantic import (
    EmailContent,
    ThreatIndicator,
    ThreatLevel,
    AnalysisResult
)
from app.ML.semantic_analysis import SemanticAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from pydantic import Field

class EmailContentAnalysisTool(BaseTool):
    name: str = Field(default="Advanced Email Analysis Tool")
    description: str = Field(default="Enterprise-grade email analysis using ML models and semantic analysis")
    preprocessor: Optional[EmailPreprocessor] = Field(default=None, exclude=True)
    semantic_analyzer: Optional[SemanticAnalyzer] = Field(default=None, exclude=True)

    def __init__(self, **data):
        """Initialize analysis components"""
        super().__init__(**data)
        object.__setattr__(self, 'preprocessor', EmailPreprocessor())
        object.__setattr__(self, 'semantic_analyzer', SemanticAnalyzer())
        
    def _run(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
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
            AnalysisResult containing:
            - Threat level assessment
            - Confidence scores
            - Detailed threat indicators
            - ML-based analysis results
            - Actionable recommendations
        """
        try:
            # Standardize input
            email_content = self.preprocessor.standardize_content(email_data)
            
            # Extract URLs from markdown content
            urls = self.preprocessor.extract_markdown_links(email_content.body)
            url_analysis = self.preprocessor.analyze_urls(urls)
            
            # Normalize text for analysis
            normalized_text = self.preprocessor.normalize_text(
                f"{email_content.subject}\n\n{email_content.body}"
            )
            
            # Perform ML-based analysis
            try:
                # Try to get the running loop
                loop = asyncio.get_running_loop()
            except RuntimeError:
                # If no loop is running, create a new one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                semantic_indicators = loop.run_until_complete(
                    self.semantic_analyzer.analyze_content(normalized_text)
                )
            else:
                # If a loop is already running, create a task
                semantic_indicators = loop.create_task(
                    self.semantic_analyzer.analyze_content(normalized_text)
                ).result()
            
            # Calculate overall threat level
            threat_level, confidence = self._calculate_threat_metrics(
                semantic_indicators,
                url_analysis
            )
            
            # Generate comprehensive recommendations
            recommendations = self._generate_recommendations(
                semantic_indicators,
                url_analysis,
                email_content
            )
            
            # Create result
            result = AnalysisResult(
                threat_level=threat_level,
                confidence_score=confidence,
                indicators=semantic_indicators,
                recommendations=recommendations,
                metadata={
                    "url_analysis": url_analysis,
                    "analysis_timestamp": datetime.utcnow().isoformat(),
                    "tool_version": "2.0.0"
                },
                timestamp=datetime.utcnow()
            )
            
            return result.dict()
            
        except Exception as e:
            logger.error(f"Error in email analysis: {str(e)}", exc_info=True)
            raise

    def _calculate_threat_metrics(
        self,
        indicators: List[ThreatIndicator],
        url_analysis: Dict[str, Any]
    ) -> tuple[ThreatLevel, float]:
        """Calculate overall threat level and confidence score"""
        
        # Get highest severity indicator
        max_severity = max(
            (ind.severity for ind in indicators),
            default=ThreatLevel.LOW
        )
        
        # Calculate confidence based on indicator consensus
        confidence_scores = [ind.confidence for ind in indicators]
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.5
        
        # Adjust for URL analysis
        if url_analysis["shortened_urls"] or url_analysis["suspicious_domains"]:
            max_severity = max(max_severity, ThreatLevel.MEDIUM)
            avg_confidence = min(1.0, avg_confidence + 0.1)
            
        return max_severity, avg_confidence

    def _generate_recommendations(
        self,
        indicators: List[ThreatIndicator],
        url_analysis: Dict[str, Any],
        email_content: EmailContent
    ) -> List[str]:
        """Generate context-aware recommendations"""
        recommendations = set()
        
        # Add recommendations based on threat types
        for indicator in indicators:
            if indicator.type in RECOMMENDATION_TEMPLATES:
                recommendations.update(RECOMMENDATION_TEMPLATES[indicator.type])
        
        # Add URL-specific recommendations
        if url_analysis["shortened_urls"]:
            recommendations.add(
                "Avoid clicking shortened URLs. Request the full, original URL from the sender."
            )
                
        return sorted(list(recommendations))
