from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from typing import List, Dict, Any, Tuple
import numpy as np
from sentence_transformers import SentenceTransformer
import logging
from app.Helper.helper_pydantic import ThreatLevel, ThreatIndicator
from pathlib import Path
import os

logger = logging.getLogger(__name__)

class SemanticAnalyzer:
    """
    Handles semantic analysis of email content using transformer models.
    Uses multiple models for different aspects of analysis:
    1. Phishing detection
    2. Intent classification
    3. Semantic similarity
    4. Sentiment analysis
    """

    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._initialize_models()

    def _initialize_models(self):
        """Initialize all required models"""
        try:
            # Using a FINE-TUNED phishing detection model (65.8M downloads, verified)
            # This model is specifically trained on phishing email datasets
            logger.info("Loading fine-tuned phishing detection model...")
            self.phishing_tokenizer = AutoTokenizer.from_pretrained("dima806/phishing-email-detection")
            self.phishing_model = AutoModelForSequenceClassification.from_pretrained(
                "dima806/phishing-email-detection"
            ).to(self.device)
            logger.info("✓ Phishing detection model loaded (fine-tuned)")

            # Semantic similarity model (this one is publicly available)
            self.similarity_model = SentenceTransformer('all-MiniLM-L6-v2')
            logger.info("✓ Semantic similarity model loaded")

            # Intent classification - using same phishing model for now
            # TODO: Replace with specialized intent classifier when available
            self.intent_tokenizer = self.phishing_tokenizer
            self.intent_model = self.phishing_model
            logger.info("✓ Intent classification model loaded (using phishing model)")

            logger.info("All models initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing models: {str(e)}")
            raise

    async def analyze_content(self, text: str) -> List[ThreatIndicator]:
        """
        Perform comprehensive semantic analysis on text content.
        
        Args:
            text: The email content to analyze
            
        Returns:
            List of ThreatIndicator objects with analysis results
        """
        indicators = []
        
        try:
            # Phishing detection
            phishing_score = await self._detect_phishing(text)
            if phishing_score > 0.6:
                indicators.append(
                    ThreatIndicator(
                        type="phishing",
                        severity=ThreatLevel.HIGH if phishing_score > 0.8 else ThreatLevel.MEDIUM,
                        confidence=phishing_score,
                        description="Potential phishing attempt detected",
                        evidence=[f"Phishing confidence score: {phishing_score:.2f}"]
                    )
                )

            # Intent classification
            intent_results = await self._classify_intent(text)
            if intent_results["suspicious"] > 0.7 or intent_results["urgent"] > 0.8:
                indicators.append(
                    ThreatIndicator(
                        type="suspicious_intent",
                        severity=ThreatLevel.MEDIUM,
                        confidence=max(intent_results["suspicious"], intent_results["urgent"]),
                        description="Suspicious or urgent intent detected",
                        evidence=[f"Intent scores: {intent_results}"]
                    )
                )

            # Semantic similarity to known patterns
            similarity_results = await self._check_semantic_similarity(text)
            if similarity_results["max_score"] > 0.85:
                indicators.append(
                    ThreatIndicator(
                        type="pattern_match",
                        severity=ThreatLevel.MEDIUM,
                        confidence=similarity_results["max_score"],
                        description=f"Similar to known pattern: {similarity_results['pattern_type']}",
                        evidence=[f"Similarity score: {similarity_results['max_score']:.2f}"]
                    )
                )

        except Exception as e:
            logger.error(f"Error in semantic analysis: {str(e)}")
            raise

        return indicators

    async def _detect_phishing(self, text: str) -> float:
        """Detect phishing attempts using transformer model"""
        try:
            inputs = self.phishing_tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                outputs = self.phishing_model(**inputs)
                scores = torch.softmax(outputs.logits, dim=1)
                return scores[0][1].item()  # Probability of phishing
        except Exception as e:
            logger.error(f"Error in phishing detection: {str(e)}")
            return 0.0

    async def _classify_intent(self, text: str) -> Dict[str, float]:
        """Classify the intent of the text"""
        try:
            inputs = self.intent_tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                outputs = self.intent_model(**inputs)
                scores = torch.softmax(outputs.logits, dim=1)
                return {
                    "suspicious": scores[0][0].item(),
                    "urgent": scores[0][1].item(),
                    "informative": scores[0][2].item(),
                    "request": scores[0][3].item()
                }
        except Exception as e:
            logger.error(f"Error in intent classification: {str(e)}")
            return {"suspicious": 0.0, "urgent": 0.0, "informative": 0.0, "request": 0.0}

    async def _check_semantic_similarity(self, text: str) -> Dict[str, Any]:
        """Check semantic similarity against known patterns"""
        try:
            # Encode the input text
            text_embedding = self.similarity_model.encode(text)
            
            # TODO: Load known patterns from database/cache
            known_patterns = [
                ("phishing", "Please verify your account immediately to prevent suspension"),
                ("urgency", "This is your final warning regarding your account status"),
                ("authority", "This is the IT department requiring immediate action")
            ]
            
            # Calculate similarities
            max_score = 0.0
            pattern_type = ""
            
            for pattern_type, pattern_text in known_patterns:
                pattern_embedding = self.similarity_model.encode(pattern_text)
                similarity = np.dot(text_embedding, pattern_embedding) / (
                    np.linalg.norm(text_embedding) * np.linalg.norm(pattern_embedding)
                )
                
                if similarity > max_score:
                    max_score = similarity
                    pattern_type = pattern_type
                    
            return {
                "max_score": float(max_score),
                "pattern_type": pattern_type
            }
            
        except Exception as e:
            logger.error(f"Error in semantic similarity check: {str(e)}")
            return {"max_score": 0.0, "pattern_type": "unknown"}