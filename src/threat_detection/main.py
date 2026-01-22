#!/usr/bin/env python3
"""
Threat Detection Module for Advanced LLMs Cybersecurity
Implements pattern recognition and anomaly analysis for zero-day attacks.
"""

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers import pipeline
import pandas as pd
import numpy as np
from pathlib import Path
import json
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatDetectionResult:
    """Result of threat detection analysis."""
    threat_score: float
    threat_type: str
    confidence: float
    indicators: List[str]
    raw_text: str
    metadata: Dict

class ThreatDetector:
    """Advanced threat detection using LLMs."""
    
    def __init__(self, model_name: str = "microsoft/DialoGPT-medium"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.classifier = None
        self.threat_patterns = self._load_threat_patterns()
        
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load threat detection patterns."""
        return {
            "malware": [
                r"backdoor", r"trojan", r"ransomware", r"keylogger",
                r"botnet", r"rootkit", r"spyware", r"adware"
            ],
            "network_attack": [
                r"ddos", r"dos attack", r"port scan", r"brute force",
                r"sql injection", r"xss", r"csrf", r"mitm"
            ],
            "data_exfiltration": [
                r"data theft", r"credential dump", r"password harvest",
                r"sensitive data", r"exfiltration", r"data breach"
            ],
            "social_engineering": [
                r"phishing", r"spear phishing", r"pretexting",
                r"baiting", r"quid pro quo", r"tailgating"
            ],
            "zero_day": [
                r"unknown exploit", r"0day", r"zero-day", r"novel attack",
                r"previously unseen", r"new vulnerability"
            ]
        }
    
    def initialize_model(self) -> None:
        """Initialize the LLM for threat detection."""
        try:
            logger.info(f"Loading model: {self.model_name}")
            
            # For demonstration, using a classification pipeline
            self.classifier = pipeline(
                "text-classification",
                model="unitary/toxic-bert",  # Using toxic-bert as proxy for threat detection
                device=0 if torch.cuda.is_available() else -1
            )
            
            logger.info("Model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def preprocess_text(self, text: str) -> str:
        """Preprocess text for threat analysis."""
        # Convert to lowercase
        text = text.lower()
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove special characters but keep important punctuation
        text = re.sub(r'[^\w\s\.\,\!\?\-\@\#\$\%\&\*\(\)]', '', text)
        
        return text.strip()
    
    def extract_indicators(self, text: str) -> Dict[str, List[str]]:
        """Extract threat indicators from text."""
        indicators = {}
        
        for threat_type, patterns in self.threat_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, text, re.IGNORECASE)
                matches.extend(found)
            
            if matches:
                indicators[threat_type] = list(set(matches))
        
        return indicators
    
    def calculate_threat_score(self, text: str, indicators: Dict) -> Tuple[float, str]:
        """Calculate threat score and determine primary threat type."""
        base_score = 0.0
        threat_weights = {
            "zero_day": 1.0,
            "malware": 0.8,
            "data_exfiltration": 0.7,
            "network_attack": 0.6,
            "social_engineering": 0.5
        }
        
        threat_scores = {}
        
        for threat_type, matches in indicators.items():
            if matches:
                weight = threat_weights.get(threat_type, 0.3)
                score = len(matches) * weight * 0.2
                threat_scores[threat_type] = score
                base_score += score
        
        # Use classifier for additional scoring
        if self.classifier:
            try:
                result = self.classifier(text[:512])  # Limit text length
                if result[0]['label'] == 'TOXIC':
                    base_score += result[0]['score'] * 0.3
            except Exception as e:
                logger.warning(f"Classifier error: {e}")
        
        # Determine primary threat type
        primary_threat = "unknown"
        if threat_scores:
            primary_threat = max(threat_scores.items(), key=lambda x: x[1])[0]
        
        # Normalize score to 0-1 range
        normalized_score = min(base_score, 1.0)
        
        return normalized_score, primary_threat
    
    def analyze_threat(self, text: str, metadata: Optional[Dict] = None) -> ThreatDetectionResult:
        """Analyze text for threats."""
        if not self.classifier:
            self.initialize_model()
        
        # Preprocess text
        processed_text = self.preprocess_text(text)
        
        # Extract indicators
        indicators = self.extract_indicators(processed_text)
        
        # Calculate threat score
        threat_score, threat_type = self.calculate_threat_score(processed_text, indicators)
        
        # Calculate confidence based on number of indicators
        total_indicators = sum(len(matches) for matches in indicators.values())
        confidence = min(total_indicators * 0.1 + 0.5, 1.0)
        
        # Flatten indicators for result
        flat_indicators = []
        for threat_cat, matches in indicators.items():
            flat_indicators.extend([f"{threat_cat}: {match}" for match in matches])
        
        return ThreatDetectionResult(
            threat_score=threat_score,
            threat_type=threat_type,
            confidence=confidence,
            indicators=flat_indicators,
            raw_text=text,
            metadata=metadata or {}
        )
    
    def batch_analyze(self, texts: List[str]) -> List[ThreatDetectionResult]:
        """Analyze multiple texts for threats."""
        results = []
        
        for i, text in enumerate(texts):
            logger.info(f"Analyzing text {i+1}/{len(texts)}")
            result = self.analyze_threat(text, {"batch_index": i})
            results.append(result)
        
        return results
    
    def generate_report(self, results: List[ThreatDetectionResult]) -> Dict:
        """Generate threat detection report."""
        if not results:
            return {"error": "No results to analyze"}
        
        # Calculate statistics
        threat_scores = [r.threat_score for r in results]
        threat_types = [r.threat_type for r in results]
        
        report = {
            "summary": {
                "total_analyzed": len(results),
                "high_threat_count": sum(1 for score in threat_scores if score > 0.7),
                "medium_threat_count": sum(1 for score in threat_scores if 0.3 < score <= 0.7),
                "low_threat_count": sum(1 for score in threat_scores if score <= 0.3),
                "average_threat_score": np.mean(threat_scores),
                "max_threat_score": max(threat_scores),
                "min_threat_score": min(threat_scores)
            },
            "threat_distribution": {
                threat_type: threat_types.count(threat_type) 
                for threat_type in set(threat_types)
            },
            "high_risk_items": [
                {
                    "index": i,
                    "threat_score": result.threat_score,
                    "threat_type": result.threat_type,
                    "indicators": result.indicators[:5],  # Top 5 indicators
                    "text_preview": result.raw_text[:200] + "..." if len(result.raw_text) > 200 else result.raw_text
                }
                for i, result in enumerate(results) 
                if result.threat_score > 0.7
            ]
        }
        
        return report

def main():
    """Main function for threat detection."""
    logger.info("Starting Advanced Threat Detection System")
    
    # Initialize detector
    detector = ThreatDetector()
    
    # Sample threat intelligence data
    sample_texts = [
        "New ransomware variant detected targeting healthcare systems with advanced encryption",
        "Suspicious network activity observed: multiple failed login attempts from foreign IP addresses",
        "Zero-day exploit discovered in popular web framework, immediate patching required",
        "Phishing campaign using COVID-19 themes to steal banking credentials",
        "Regular system maintenance scheduled for this weekend",
        "Botnet command and control server identified, initiating takedown procedures",
        "Data exfiltration attempt blocked by DLP system, investigating source",
        "Social engineering attack targeting executives with fake vendor invoices"
    ]
    
    # Analyze threats
    logger.info("Analyzing threat intelligence data...")
    results = detector.batch_analyze(sample_texts)
    
    # Generate report
    report = detector.generate_report(results)
    
    # Display results
    print("\n" + "="*60)
    print("THREAT DETECTION REPORT")
    print("="*60)
    
    print(f"\nSUMMARY:")
    print(f"Total Analyzed: {report['summary']['total_analyzed']}")
    print(f"High Threat: {report['summary']['high_threat_count']}")
    print(f"Medium Threat: {report['summary']['medium_threat_count']}")
    print(f"Low Threat: {report['summary']['low_threat_count']}")
    print(f"Average Threat Score: {report['summary']['average_threat_score']:.3f}")
    
    print(f"\nTHREAT DISTRIBUTION:")
    for threat_type, count in report['threat_distribution'].items():
        print(f"  {threat_type}: {count}")
    
    print(f"\nHIGH RISK ITEMS:")
    for item in report['high_risk_items']:
        print(f"\n  Item {item['index']}:")
        print(f"    Threat Score: {item['threat_score']:.3f}")
        print(f"    Threat Type: {item['threat_type']}")
        print(f"    Indicators: {', '.join(item['indicators'])}")
        print(f"    Text: {item['text_preview']}")
    
    # Save results
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    
    with open(output_dir / "threat_detection_report.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Report saved to {output_dir / 'threat_detection_report.json'}")

if __name__ == "__main__":
    main()