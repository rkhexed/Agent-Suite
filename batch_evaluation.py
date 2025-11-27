"""
Batch Evaluation Script for Multi-Agent Phishing Detection System

Processes emails from CSV with ground truth labels and saves detailed results.
Designed for IEEE conference paper evaluation with 5,000 email dataset.

Usage:
    python batch_evaluation.py --input athena_evaluation.csv --output results.csv
    python batch_evaluation.py --resume results.csv  # Resume interrupted run
"""

import pandas as pd
import argparse
import time
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
import sys
import os
from tqdm import tqdm
from functools import wraps

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.Agents.coordination_agent import CoordinationCrew
from app.Agents.linguistic_agent import LinguisticAnalysisCrew
from app.Agents.technical_validation_agent import TechnicalValidationCrew
from app.Agents.threat_intel_agent import ThreatIntelligenceCrew
from app.Helper.helper_pydantic import CoordinationInput

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('batch_evaluation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def retry_with_backoff(max_retries=5, initial_wait=1):
    """
    Decorator to retry async functions with exponential backoff on rate limits/timeouts
    
    Args:
        max_retries: Maximum number of retry attempts
        initial_wait: Initial wait time in seconds (doubles each retry)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            wait_time = initial_wait
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    error_msg = str(e)
                    
                    # Check if it's a rate limit or timeout error
                    is_retryable = (
                        'RateLimitError' in error_msg or 
                        'Timeout' in error_msg or
                        'capacity exceeded' in error_msg or
                        'timed out' in error_msg
                    )
                    
                    if not is_retryable or attempt == max_retries - 1:
                        # Not retryable or last attempt - raise immediately
                        raise
                    
                    # Log and wait before retry
                    logger.warning(
                        f"Attempt {attempt + 1}/{max_retries} failed: {error_msg[:100]}. "
                        f"Retrying in {wait_time}s..."
                    )
                    await asyncio.sleep(wait_time)
                    wait_time *= 2  # Exponential backoff
            
            # Should never reach here, but just in case
            raise last_exception
        return wrapper
    return decorator


class BatchEvaluator:
    """
    Batch email evaluation processor for research validation
    """
    
    def __init__(self, input_csv: str, output_csv: str, save_frequency: int = 10):
        """
        Initialize batch evaluator
        
        Args:
            input_csv: Path to input CSV with ground truth
            output_csv: Path to save results
            save_frequency: Save results every N emails
        """
        self.input_csv = input_csv
        self.output_csv = output_csv
        self.save_frequency = save_frequency
        
        # Initialize coordination agent
        logger.info("Initializing agents...")
        self.linguistic_crew = LinguisticAnalysisCrew()
        self.technical_crew = TechnicalValidationCrew()
        self.threat_intel_crew = ThreatIntelligenceCrew()
        self.coordination_crew = CoordinationCrew()
        logger.info("✅ All agents ready")
        
        # Load dataset - merge input with existing results if output exists
        import os
        logger.info(f"Loading dataset from {input_csv}...")
        self.df = pd.read_csv(input_csv)
        logger.info(f"✅ Loaded {len(self.df)} emails from input CSV")
        
        # If output exists, merge in the results
        if os.path.exists(output_csv):
            logger.info(f"📂 Found existing results at {output_csv}, merging...")
            existing_results = pd.read_csv(output_csv)
            
            # Get result columns (everything except the input columns)
            input_cols = {'Sender', 'Subject', 'Body', 'Label'}
            result_cols = [col for col in existing_results.columns if col not in input_cols]
            
            # Merge results into input data by index
            for col in result_cols:
                if col in existing_results.columns:
                    self.df[col] = existing_results[col]
            
            completed = self.df['status'].value_counts().get('success', 0) if 'status' in self.df.columns else 0
            logger.info(f"✅ Merged existing results - Already completed: {completed} emails")
        
        # Add result columns if not present
        self._initialize_result_columns()
        
    def _initialize_result_columns(self):
        """Add result columns to dataframe if not present"""
        result_columns = [
            'predicted_risk_level',           # LOW/MEDIUM/HIGH/CRITICAL
            'predicted_risk_score',           # 0.0-1.0 numeric score
            'certainty_level',                # DEFINITIVE/HIGH/MEDIUM/LOW/INCONCLUSIVE
            'coordination_explanation',       # Full narrative explanation
            'linguistic_risk_score',          # Individual agent scores
            'linguistic_certainty',
            'technical_risk_score',
            'technical_certainty',
            'threat_intel_risk_score',
            'threat_intel_certainty',
            'processing_time_seconds',        # Performance metrics
            'processed_timestamp',
            'sender_missing',                 # Data quality tracking
            'status'                          # success/error
        ]
        
        for col in result_columns:
            if col not in self.df.columns:
                self.df[col] = None
    
    def _prepare_email_data(self, row: pd.Series) -> Dict[str, Any]:
        """
        Convert CSV row to email_data dict for coordination agent
        
        Args:
            row: Pandas series from CSV
            
        Returns:
            Email data dictionary
        """
        # Handle missing sender (50% of dataset - Enron corpus)
        sender_missing = pd.isna(row['Sender']) or str(row['Sender']).strip() == ''
        sender = 'internal@company.local' if sender_missing else str(row['Sender'])
        
        email_data = {
            'subject': str(row['Subject']) if pd.notna(row['Subject']) else '',
            'body': str(row['Body']) if pd.notna(row['Body']) else '',
            'sender': sender,
            'recipients': ['user@example.com'],  # Not in dataset
            'date': datetime.now().isoformat(),
            'headers': {
                'Return-Path': f'<{sender}>',
                'X-Originating-IP': '192.168.1.1'  # Not in dataset
            }
        }
        
        return email_data, sender_missing
    
    @retry_with_backoff(max_retries=5, initial_wait=1)
    async def _run_agent_with_retry(self, agent_crew, request: Dict, agent_name: str):
        """
        Run an agent with retry logic for rate limits/timeouts
        
        Args:
            agent_crew: The agent crew instance
            request: Request dictionary for the agent
            agent_name: Name of the agent for logging
            
        Returns:
            Agent result
            
        Raises:
            Exception: If result indicates rate limit error (triggers retry)
        """
        result = await agent_crew.process_request(request)
        
        # Check if the result indicates a rate limit error
        # CrewAI catches exceptions internally, so we need to check the result
        if hasattr(result, 'status') and result.status == 'error':
            error_msg = result.analysis_reasoning
            if any(keyword in error_msg.lower() for keyword in ['rate limit', 'capacity exceeded', '3505']):
                # Raise exception to trigger retry
                raise Exception(f"RateLimitError in {agent_name}: {error_msg}")
        
        return result
    
    def _map_risk_level(self, risk_score: float) -> str:
        """
        Map numeric risk score to categorical risk level
        
        Args:
            risk_score: 0.0-1.0 risk score
            
        Returns:
            Risk level: LOW/MEDIUM/HIGH/CRITICAL
        """
        if risk_score >= 0.90:
            return 'CRITICAL'
        elif risk_score >= 0.70:
            return 'HIGH'
        elif risk_score >= 0.40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _extract_agent_results(self, coordination_result: Any) -> Dict[str, Any]:
        """
        Extract individual agent results from coordination output
        
        Args:
            coordination_result: CoordinationResult from agent
            
        Returns:
            Dictionary with agent-level results
        """
        agent_results = {}
        
        # Extract individual agent contributions
        for contrib in coordination_result.agent_contributions:
            agent_name = contrib.agent_name.lower().replace(' ', '_')
            
            if 'linguistic' in agent_name:
                agent_results['linguistic_risk_score'] = contrib.risk_score
                agent_results['linguistic_certainty'] = contrib.certainty_level
            elif 'technical' in agent_name:
                agent_results['technical_risk_score'] = contrib.risk_score
                agent_results['technical_certainty'] = contrib.certainty_level
            elif 'threat' in agent_name:
                agent_results['threat_intel_risk_score'] = contrib.risk_score
                agent_results['threat_intel_certainty'] = contrib.certainty_level
        
        return agent_results
    
    def process_email(self, idx: int, row: pd.Series) -> Dict[str, Any]:
        """
        Process single email through coordination agent
        
        Args:
            idx: Row index
            row: Email data from CSV
            
        Returns:
            Results dictionary
        """
        start_time = time.time()
        
        try:
            # Prepare email data
            email_data, sender_missing = self._prepare_email_data(row)
            
            # Create event loop for async calls
            loop = asyncio.get_event_loop()
            
            # Run individual agents with retry logic
            logger.debug(f"Processing email {idx}: Running Linguistic Agent...")
            linguistic_request = {'email_data': email_data, 'metadata': {'email_id': idx}}
            linguistic_result = loop.run_until_complete(
                self._run_agent_with_retry(self.linguistic_crew, linguistic_request, 'Linguistic')
            )
            
            logger.debug(f"Processing email {idx}: Running Technical Agent...")
            technical_request = {'email_data': email_data, 'metadata': {'email_id': idx}}
            technical_result = loop.run_until_complete(
                self._run_agent_with_retry(self.technical_crew, technical_request, 'Technical')
            )
            
            logger.debug(f"Processing email {idx}: Running Threat Intel Agent...")
            threat_intel_request = {'email_data': email_data, 'metadata': {'email_id': idx}}
            threat_intel_result = loop.run_until_complete(
                self._run_agent_with_retry(self.threat_intel_crew, threat_intel_request, 'ThreatIntel')
            )
            
            # Prepare coordination data (dict format for analyze method)
            linguistic_dict = {
                'risk_score': linguistic_result.risk_score,
                'certainty_level': linguistic_result.certainty_level,
                'findings': linguistic_result.findings,
                'analysis_reasoning': linguistic_result.analysis_reasoning
            }
            technical_dict = {
                'risk_score': technical_result.risk_score,
                'certainty_level': technical_result.certainty_level,
                'findings': technical_result.findings,
                'analysis_reasoning': technical_result.analysis_reasoning
            }
            threat_intel_dict = {
                'risk_score': threat_intel_result.risk_score,
                'certainty_level': threat_intel_result.certainty_level,
                'findings': threat_intel_result.findings,
                'analysis_reasoning': threat_intel_result.analysis_reasoning
            }
            
            # Process through coordination agent (call analyze() directly - no async needed)
            logger.debug(f"Processing email {idx}: Running Coordination Agent...")
            coordination_result = self.coordination_crew.analyze(
                email_data=email_data,
                linguistic_result=linguistic_dict,
                technical_result=technical_dict,
                threat_intel_result=threat_intel_dict
            )
            
            # Extract results
            processing_time = time.time() - start_time
            
            # Extract explanation narrative from coordination result
            explanation = "No explanation available"
            if hasattr(coordination_result, 'explanation') and coordination_result.explanation:
                explanation = coordination_result.explanation.narrative
            elif isinstance(coordination_result, dict) and 'explanation' in coordination_result:
                expl = coordination_result['explanation']
                if isinstance(expl, dict) and 'narrative' in expl:
                    explanation = expl['narrative']
                elif hasattr(expl, 'narrative'):
                    explanation = expl.narrative
            
            # Build agent results for output
            agent_results = {
                'linguistic_risk_score': linguistic_result.risk_score,
                'linguistic_certainty': linguistic_result.certainty_level,
                'technical_risk_score': technical_result.risk_score,
                'technical_certainty': technical_result.certainty_level,
                'threat_intel_risk_score': threat_intel_result.risk_score,
                'threat_intel_certainty': threat_intel_result.certainty_level,
            }
            
            # Build results dictionary
            results = {
                'predicted_risk_level': self._map_risk_level(coordination_result.final_risk_score),
                'predicted_risk_score': coordination_result.final_risk_score,
                'certainty_level': coordination_result.aggregated_certainty,
                'coordination_explanation': explanation,
                'processing_time_seconds': round(processing_time, 2),
                'processed_timestamp': datetime.now().isoformat(),
                'sender_missing': sender_missing,
                'status': 'success',
                **agent_results
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing email {idx}: {str(e)}", exc_info=True)
            processing_time = time.time() - start_time
            
            return {
                'predicted_risk_level': 'ERROR',
                'predicted_risk_score': None,
                'certainty_level': 'INCONCLUSIVE',
                'coordination_explanation': f"Processing error: {str(e)}",
                'processing_time_seconds': round(processing_time, 2),
                'processed_timestamp': datetime.now().isoformat(),
                'sender_missing': False,
                'status': f'error: {str(e)[:100]}'
            }
    
    def run(self, start_idx: int = 0, limit: Optional[int] = None):
        """
        Run batch evaluation
        
        Args:
            start_idx: Index to start from (for resuming)
            limit: Maximum number of emails to process (None = all)
        """
        # Determine range
        end_idx = min(start_idx + limit, len(self.df)) if limit else len(self.df)
        total_to_process = end_idx - start_idx
        
        logger.info("="*60)
        logger.info("🚀 Starting Batch Evaluation")
        logger.info("="*60)
        logger.info(f"Total emails in dataset: {len(self.df)}")
        logger.info(f"Processing range: {start_idx} to {end_idx}")
        logger.info(f"Emails to process: {total_to_process}")
        logger.info(f"Save frequency: every {self.save_frequency} emails")
        logger.info("="*60)
        
        # Progress tracking
        processed_count = 0
        error_count = 0
        start_time = time.time()
        
        # Process with progress bar
        with tqdm(total=total_to_process, desc="Processing emails", unit="email") as pbar:
            for idx in range(start_idx, end_idx):
                row = self.df.iloc[idx]
                
                # Skip if already processed
                if pd.notna(row.get('status')) and row['status'] == 'success':
                    logger.info(f"Skipping email {idx} (already processed)")
                    pbar.update(1)
                    continue
                
                # Process email
                results = self.process_email(idx, row)
                
                # Update dataframe
                for key, value in results.items():
                    self.df.at[idx, key] = value
                
                # Track stats
                processed_count += 1
                if results['status'] != 'success':
                    error_count += 1
                
                # Update progress bar
                elapsed = time.time() - start_time
                avg_time = elapsed / processed_count if processed_count > 0 else 0
                remaining = (total_to_process - processed_count) * avg_time
                
                pbar.set_postfix({
                    'errors': error_count,
                    'avg_time': f'{avg_time:.1f}s',
                    'eta': f'{remaining/60:.1f}m'
                })
                pbar.update(1)
                
                # Incremental save
                if processed_count % self.save_frequency == 0:
                    self._save_results()
                    logger.info(f"💾 Saved checkpoint at {processed_count}/{total_to_process} emails")
                
                # Add delay between emails to avoid rate limits (if not last email)
                if idx < end_idx - 1:  # Don't delay after the last email
                    time.sleep(15)  # 15 second delay to stay under Mistral's rate limits
        
        # Final save
        self._save_results()
        
        # Print summary
        total_time = time.time() - start_time
        self._print_summary(processed_count, error_count, total_time)
    
    def _save_results(self):
        """Save current results to CSV (excluding Body column to reduce file size)"""
        try:
            # Remove Body column from output to reduce file size from ~2GB to ~200MB
            # Body can be retrieved from input CSV using row index if needed
            output_cols = [col for col in self.df.columns if col != 'Body']
            output_df = self.df[output_cols]
            output_df.to_csv(self.output_csv, index=False)
            logger.info(f"✅ Results saved to {self.output_csv}")
        except Exception as e:
            logger.error(f"❌ Failed to save results: {str(e)}")
    
    def _print_summary(self, processed: int, errors: int, total_time: float):
        """Print evaluation summary"""
        logger.info("\n" + "="*60)
        logger.info("📊 Batch Evaluation Complete")
        logger.info("="*60)
        logger.info(f"Total processed: {processed}")
        logger.info(f"Successful: {processed - errors}")
        logger.info(f"Errors: {errors}")
        logger.info(f"Success rate: {(processed-errors)/processed*100:.1f}%")
        logger.info(f"Total time: {total_time/3600:.2f} hours")
        logger.info(f"Average per email: {total_time/processed:.2f} seconds")
        logger.info(f"Results saved to: {self.output_csv}")
        logger.info("="*60)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Batch email evaluation for phishing detection research')
    parser.add_argument('--input', default='cyber_evaluation.csv', help='Input CSV with ground truth')
    parser.add_argument('--output', default='cyber_evaluation_results.csv', help='Output CSV with results')
    parser.add_argument('--start', type=int, default=0, help='Start index (for resuming)')
    parser.add_argument('--limit', type=int, default=None, help='Maximum emails to process (default: all)')
    parser.add_argument('--save-freq', type=int, default=10, help='Save frequency (default: every 10 emails)')
    parser.add_argument('--resume', action='store_true', help='Resume from existing output file')
    
    args = parser.parse_args()
    
    # Determine start index if resuming
    start_idx = args.start
    if args.resume and os.path.exists(args.output):
        logger.info(f"Resuming from {args.output}")
        df = pd.read_csv(args.output)
        processed = df['status'].notna().sum()
        start_idx = processed
        logger.info(f"Found {processed} already processed emails, starting from index {start_idx}")
    
    # Create evaluator
    evaluator = BatchEvaluator(
        input_csv=args.input,
        output_csv=args.output,
        save_frequency=args.save_freq
    )
    
    # Run evaluation
    evaluator.run(start_idx=start_idx, limit=args.limit)


if __name__ == '__main__':
    main()
