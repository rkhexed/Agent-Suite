from typing import Dict, Any, List, Optional
import re
import logging
from urllib.parse import urlparse
from datetime import datetime
from app.Helper.helper_pydantic import EmailContent

logger = logging.getLogger(__name__)

class EmailPreprocessor:
    """
    Handles email preprocessing tasks including:
    - URL extraction and analysis
    - Text normalization
    - Content standardization
    
    Note: HTML to Markdown conversion is handled by n8n automation
    """
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract and normalize URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return list(set(re.findall(url_pattern, text)))

    @staticmethod
    def normalize_text(text: str) -> str:
        """Normalize text content"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Replace multiple punctuation with single
        text = re.sub(r'([!?.]){2,}', r'\1', text)
        
        # Remove special characters
        text = re.sub(r'[^\w\s!?.,@-]', '', text)
        
        return text

    @staticmethod
    def standardize_content(content: Dict[str, Any]) -> EmailContent:
        """
        Standardize the n8n-processed email content into EmailContent model
        
        Args:
            content: Dictionary containing email data processed by n8n
                    (already converted from HTML to Markdown)
        """
        try:
            return EmailContent(
                subject=content.get('subject', ''),
                body=content.get('body', ''),  # Already in Markdown format from n8n
                sender=content.get('sender', ''),  # Updated from 'from' to 'sender'
                recipients=content.get('recipients', []),  # Updated from 'to' to 'recipients'
                date=content.get('date', datetime.utcnow()),
                headers=content.get('headers', {})
            )
        except Exception as e:
            logger.error(f"Error standardizing content: {str(e)}")
            raise

    @staticmethod
    def analyze_urls(urls: List[str]) -> Dict[str, Any]:
        """Analyze URLs for suspicious patterns"""
        results = {
            "shortened_urls": [],
            "suspicious_domains": [],
            "non_standard_ports": [],
            "analysis": {}
        }
        
        url_shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check for URL shorteners
                if any(shortener in domain for shortener in url_shorteners):
                    results["shortened_urls"].append(url)
                
                # Check for non-standard ports
                if parsed.port and parsed.port not in (80, 443):
                    results["non_standard_ports"].append(url)
                
                # Analyze domain
                results["analysis"][url] = {
                    "domain": domain,
                    "path": parsed.path,
                    "query": parsed.query,
                    "scheme": parsed.scheme
                }
                
            except Exception as e:
                logger.warning(f"Error analyzing URL {url}: {str(e)}")
                continue
        
        return results

    @staticmethod
    def extract_markdown_links(markdown: str) -> List[str]:
        """Extract URLs from Markdown formatted text"""
        # Match both [text](url) and plain http(s):// URLs
        markdown_link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        raw_url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
        urls = []
        
        # Extract URLs from Markdown links
        markdown_links = re.findall(markdown_link_pattern, markdown)
        urls.extend([url for _, url in markdown_links])
        
        # Extract raw URLs
        raw_urls = re.findall(raw_url_pattern, markdown)
        urls.extend(raw_urls)
        
        return list(set(urls))  # Remove duplicates