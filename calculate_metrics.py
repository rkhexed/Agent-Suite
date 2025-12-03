"""
Evaluation Metrics Calculator

Calculates comprehensive metrics from batch evaluation results for IEEE paper.
Generates confusion matrix, precision, recall, F1, and per-agent analysis.

Usage:
    python calculate_metrics.py --results athena_evaluation_results.csv
"""

import pandas as pd
import numpy as np
import argparse
from sklearn.metrics import (
    confusion_matrix, classification_report, 
    accuracy_score, precision_recall_fscore_support,
    roc_auc_score, matthews_corrcoef
)
import sys


class MetricsCalculator:
    """Calculate evaluation metrics for phishing detection system"""
    
    def __init__(self, results_csv: str):
        """
        Initialize metrics calculator
        
        Args:
            results_csv: Path to results CSV from batch evaluation
        """
        self.df = pd.read_csv(results_csv)
        
        # Filter only successfully processed emails
        self.df_success = self.df[self.df['status'] == 'success'].copy()
        
        print(f"📊 Loaded {len(self.df)} emails")
        print(f"✅ Successfully processed: {len(self.df_success)}")
        print(f"❌ Errors: {len(self.df) - len(self.df_success)}")
        print()
        
        # Map risk levels to binary predictions
        self._prepare_predictions()
    
    def _prepare_predictions(self):
        """Convert risk levels to binary predictions"""
        # Map ground truth: 0 = legitimate, 1 = phishing
        self.df_success['y_true'] = self.df_success['Label']
        
        # Map predictions: HIGH/CRITICAL = phishing (1), LOW/MEDIUM = legitimate (0)
        risk_to_binary = {
            'CRITICAL': 1,
            'HIGH': 1,
            'MEDIUM': 0,  # Conservative: only flag HIGH+ as phishing
            'LOW': 0
        }
        self.df_success['y_pred'] = self.df_success['predicted_risk_level'].map(risk_to_binary)
        
        # Alternative: Use numeric threshold
        self.df_success['y_pred_score'] = self.df_success['predicted_risk_score'] >= 0.70
    
    def calculate_overall_metrics(self):
        """Calculate overall system performance metrics"""
        print("="*60)
        print("📈 OVERALL SYSTEM PERFORMANCE")
        print("="*60)
        
        y_true = self.df_success['y_true']
        y_pred = self.df_success['y_pred']
        
        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        print("\n🔢 Confusion Matrix:")
        print(f"                  Predicted Legitimate  Predicted Phishing")
        print(f"Actual Legitimate        {tn:4d}                {fp:4d}")
        print(f"Actual Phishing          {fn:4d}                {tp:4d}")
        print()
        
        # Core Metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary')
        mcc = matthews_corrcoef(y_true, y_pred)
        
        # AUC (if we have probability scores)
        try:
            auc = roc_auc_score(y_true, self.df_success['predicted_risk_score'])
        except:
            auc = None
        
        print("📊 Classification Metrics:")
        print(f"Accuracy:     {accuracy*100:.2f}%")
        print(f"Precision:    {precision*100:.2f}%  (of predicted phishing, how many were correct)")
        print(f"Recall:       {recall*100:.2f}%  (of actual phishing, how many we caught)")
        print(f"F1-Score:     {f1*100:.2f}%  (harmonic mean of precision & recall)")
        print(f"MCC:          {mcc:.3f}   (Matthews Correlation: -1 to +1, higher better)")
        if auc:
            print(f"AUC-ROC:      {auc:.3f}   (Area Under Curve)")
        print()
        
        # Detailed breakdown
        print("📋 Per-Class Performance:")
        print(classification_report(y_true, y_pred, 
                                   target_names=['Legitimate', 'Phishing'],
                                   digits=3))
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'mcc': mcc,
            'auc': auc,
            'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn
        }
    
    def calculate_per_agent_metrics(self):
        """Calculate individual agent performance"""
        print("="*60)
        print("🤖 PER-AGENT PERFORMANCE ANALYSIS")
        print("="*60)
        print()
        
        y_true = self.df_success['y_true']
        
        agents = [
            ('Linguistic Agent', 'linguistic_risk_score'),
            ('Technical Validation', 'technical_risk_score'),
            ('Threat Intelligence', 'threat_intel_risk_score')
        ]
        
        agent_metrics = {}
        
        for agent_name, score_col in agents:
            if score_col not in self.df_success.columns:
                continue
            
            # Binary predictions using threshold 0.70
            y_pred_agent = (self.df_success[score_col] >= 0.70).astype(int)
            
            accuracy = accuracy_score(y_true, y_pred_agent)
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_true, y_pred_agent, average='binary', zero_division=0
            )
            
            print(f"📊 {agent_name}:")
            print(f"   Accuracy:  {accuracy*100:.2f}%")
            print(f"   Precision: {precision*100:.2f}%")
            print(f"   Recall:    {recall*100:.2f}%")
            print(f"   F1-Score:  {f1*100:.2f}%")
            print()
            
            agent_metrics[agent_name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            }
        
        return agent_metrics
    
    def analyze_certainty_levels(self):
        """Analyze prediction certainty distribution"""
        print("="*60)
        print("🎯 CERTAINTY LEVEL ANALYSIS")
        print("="*60)
        print()
        
        certainty_dist = self.df_success['certainty_level'].value_counts()
        total = len(self.df_success)
        
        print("Certainty Distribution:")
        for level in ['DEFINITIVE', 'HIGH', 'MEDIUM', 'LOW', 'INCONCLUSIVE']:
            count = certainty_dist.get(level, 0)
            pct = count / total * 100
            print(f"  {level:12s}: {count:4d} ({pct:5.1f}%)")
        print()
        
        # Accuracy by certainty level
        print("Accuracy by Certainty Level:")
        for level in ['DEFINITIVE', 'HIGH', 'MEDIUM', 'LOW']:
            subset = self.df_success[self.df_success['certainty_level'] == level]
            if len(subset) > 0:
                acc = accuracy_score(subset['y_true'], subset['y_pred'])
                print(f"  {level:12s}: {acc*100:.2f}% ({len(subset)} emails)")
        print()
    
    def analyze_processing_time(self):
        """Analyze processing time statistics"""
        print("="*60)
        print("⏱️  PROCESSING TIME ANALYSIS")
        print("="*60)
        print()
        
        times = self.df_success['processing_time_seconds']
        
        print("Processing Time Statistics:")
        print(f"  Mean:    {times.mean():.2f} seconds")
        print(f"  Median:  {times.median():.2f} seconds")
        print(f"  Min:     {times.min():.2f} seconds")
        print(f"  Max:     {times.max():.2f} seconds")
        print(f"  Std Dev: {times.std():.2f} seconds")
        print()
        
        total_time = times.sum()
        print(f"Total Processing Time: {total_time/3600:.2f} hours")
        print(f"Throughput: {len(self.df_success)/total_time*3600:.0f} emails/hour")
        print()
    
    def analyze_missing_sender_impact(self):
        """Analyze impact of missing sender data"""
        print("="*60)
        print("📧 MISSING SENDER IMPACT ANALYSIS")
        print("="*60)
        print()
        
        if 'sender_missing' not in self.df_success.columns:
            print("No sender_missing data available")
            return
        
        # Split by sender availability
        with_sender = self.df_success[self.df_success['sender_missing'] == False]
        without_sender = self.df_success[self.df_success['sender_missing'] == True]
        
        print(f"Emails with sender:    {len(with_sender):4d}")
        print(f"Emails without sender: {len(without_sender):4d}")
        print()
        
        if len(with_sender) > 0:
            acc_with = accuracy_score(with_sender['y_true'], with_sender['y_pred'])
            print(f"Accuracy WITH sender:    {acc_with*100:.2f}%")
        
        if len(without_sender) > 0:
            acc_without = accuracy_score(without_sender['y_true'], without_sender['y_pred'])
            print(f"Accuracy WITHOUT sender: {acc_without*100:.2f}%")
        print()
    
    def error_analysis(self, n_examples: int = 10):
        """Analyze misclassified examples"""
        print("="*60)
        print("❌ ERROR ANALYSIS")
        print("="*60)
        print()
        
        # False Positives (predicted phishing, actually legitimate)
        fp = self.df_success[(self.df_success['y_true'] == 0) & (self.df_success['y_pred'] == 1)]
        print(f"False Positives (legitimate flagged as phishing): {len(fp)}")
        if len(fp) > 0:
            print(f"  Average risk score: {fp['predicted_risk_score'].mean():.3f}")
            print(f"  Sample subjects:")
            for subj in fp['Subject'].head(n_examples):
                print(f"    - {str(subj)[:80]}")
        print()
        
        # False Negatives (predicted legitimate, actually phishing)
        fn = self.df_success[(self.df_success['y_true'] == 1) & (self.df_success['y_pred'] == 0)]
        print(f"False Negatives (phishing missed): {len(fn)}")
        if len(fn) > 0:
            print(f"  Average risk score: {fn['predicted_risk_score'].mean():.3f}")
            print(f"  Sample subjects:")
            for subj in fn['Subject'].head(n_examples):
                print(f"    - {str(subj)[:80]}")
        print()
    
    def generate_full_report(self):
        """Generate complete evaluation report"""
        print("\n" + "🔬 COMPREHENSIVE EVALUATION REPORT" + "\n")
        print("Dataset: Enron (legitimate) + Nazario (phishing)")
        print(f"Total Emails Evaluated: {len(self.df_success)}")
        print(f"Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        overall = self.calculate_overall_metrics()
        agent_metrics = self.calculate_per_agent_metrics()
        self.analyze_certainty_levels()
        self.analyze_processing_time()
        self.analyze_missing_sender_impact()
        self.error_analysis()
        
        print("="*60)
        print("✅ EVALUATION COMPLETE")
        print("="*60)
        
        return overall, agent_metrics


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Calculate evaluation metrics for phishing detection')
    parser.add_argument('--results', default='athena_evaluation_results.csv', 
                       help='Results CSV from batch evaluation')
    
    args = parser.parse_args()
    
    calculator = MetricsCalculator(args.results)
    calculator.generate_full_report()


if __name__ == '__main__':
    main()
