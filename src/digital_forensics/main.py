#!/usr/bin/env python3
"""
Digital Forensics Module for Advanced LLMs Cybersecurity
Implements evidence correlation, timeline reconstruction, and memory forensics.
"""

import torch
from transformers import AutoTokenizer, AutoModel
import pandas as pd
import numpy as np
from pathlib import Path
import json
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import hashlib
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ForensicEvidence:
    """Represents a piece of digital forensic evidence."""
    evidence_id: str
    timestamp: datetime
    source: str
    evidence_type: str
    content: str
    hash_value: str
    metadata: Dict[str, Any]
    confidence_score: float = 0.0
    related_evidence: List[str] = None

    def __post_init__(self):
        if self.related_evidence is None:
            self.related_evidence = []

@dataclass
class ForensicTimeline:
    """Timeline of forensic events."""
    timeline_id: str
    events: List[ForensicEvidence]
    start_time: datetime
    end_time: datetime
    incident_type: str
    summary: str

class ForensicLLM:
    """ForensicLLM implementation for digital forensics analysis."""
    
    def __init__(self, model_name: str = "microsoft/DialoGPT-small"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.evidence_store = []
        self.chain_of_custody = []
        
        # Forensic patterns for different evidence types
        self.forensic_patterns = {
            "file_system": [
                r"file created", r"file modified", r"file deleted", r"file accessed",
                r"directory created", r"permission changed", r"ownership changed"
            ],
            "network": [
                r"connection established", r"data transfer", r"port scan",
                r"dns query", r"http request", r"tcp connection", r"udp packet"
            ],
            "process": [
                r"process started", r"process terminated", r"dll loaded",
                r"registry modified", r"service started", r"service stopped"
            ],
            "memory": [
                r"memory allocation", r"heap corruption", r"stack overflow",
                r"buffer overflow", r"code injection", r"dll injection"
            ],
            "user_activity": [
                r"user login", r"user logout", r"password change",
                r"privilege escalation", r"account created", r"account disabled"
            ]
        }
    
    def initialize_model(self) -> None:
        """Initialize the ForensicLLM model."""
        try:
            logger.info(f"Loading ForensicLLM model: {self.model_name}")
            
            # For demonstration, using a general language model
            # In practice, this would be a specialized forensics model
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModel.from_pretrained(self.model_name)
            
            # Add padding token if not present
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            logger.info("ForensicLLM model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def calculate_evidence_hash(self, content: str) -> str:
        """Calculate hash for evidence integrity."""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def add_evidence(self, evidence: ForensicEvidence) -> None:
        """Add evidence to the store with chain of custody."""
        # Calculate hash if not provided
        if not evidence.hash_value:
            evidence.hash_value = self.calculate_evidence_hash(evidence.content)
        
        # Add to evidence store
        self.evidence_store.append(evidence)
        
        # Update chain of custody
        custody_entry = {
            "evidence_id": evidence.evidence_id,
            "timestamp": datetime.now(),
            "action": "evidence_added",
            "handler": "ForensicLLM_System",
            "hash": evidence.hash_value
        }
        self.chain_of_custody.append(custody_entry)
        
        logger.info(f"Evidence {evidence.evidence_id} added to store")
    
    def classify_evidence_type(self, content: str) -> Tuple[str, float]:
        """Classify the type of forensic evidence."""
        scores = {}
        
        for evidence_type, patterns in self.forensic_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, content, re.IGNORECASE))
                score += matches
            
            if score > 0:
                scores[evidence_type] = score / len(patterns)
        
        if not scores:
            return "unknown", 0.0
        
        best_type = max(scores.items(), key=lambda x: x[1])
        return best_type[0], best_type[1]
    
    def correlate_evidence(self, evidence_list: List[ForensicEvidence]) -> Dict[str, List[str]]:
        """Correlate related evidence pieces."""
        correlations = {}
        
        for i, evidence1 in enumerate(evidence_list):
            correlations[evidence1.evidence_id] = []
            
            for j, evidence2 in enumerate(evidence_list):
                if i != j:
                    # Time-based correlation (within 1 hour)
                    time_diff = abs((evidence1.timestamp - evidence2.timestamp).total_seconds())
                    if time_diff <= 3600:  # 1 hour
                        correlations[evidence1.evidence_id].append(evidence2.evidence_id)
                        continue
                    
                    # Content-based correlation (simple keyword matching)
                    common_keywords = self._find_common_keywords(
                        evidence1.content, evidence2.content
                    )
                    if len(common_keywords) >= 2:
                        correlations[evidence1.evidence_id].append(evidence2.evidence_id)
        
        return correlations
    
    def _find_common_keywords(self, text1: str, text2: str) -> List[str]:
        """Find common keywords between two texts."""
        # Simple keyword extraction (in practice, would use more sophisticated NLP)
        words1 = set(re.findall(r'\b\w{4,}\b', text1.lower()))
        words2 = set(re.findall(r'\b\w{4,}\b', text2.lower()))
        
        # Filter out common words
        stop_words = {'this', 'that', 'with', 'have', 'will', 'from', 'they', 'been', 'were'}
        words1 -= stop_words
        words2 -= stop_words
        
        return list(words1.intersection(words2))
    
    def reconstruct_timeline(self, evidence_list: List[ForensicEvidence]) -> ForensicTimeline:
        """Reconstruct timeline from evidence."""
        if not evidence_list:
            raise ValueError("No evidence provided for timeline reconstruction")
        
        # Sort evidence by timestamp
        sorted_evidence = sorted(evidence_list, key=lambda x: x.timestamp)
        
        # Determine incident type based on evidence
        incident_types = [ev.evidence_type for ev in sorted_evidence]
        most_common_type = max(set(incident_types), key=incident_types.count)
        
        # Generate summary
        summary = self._generate_timeline_summary(sorted_evidence)
        
        timeline = ForensicTimeline(
            timeline_id=f"timeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            events=sorted_evidence,
            start_time=sorted_evidence[0].timestamp,
            end_time=sorted_evidence[-1].timestamp,
            incident_type=most_common_type,
            summary=summary
        )
        
        return timeline
    
    def _generate_timeline_summary(self, evidence_list: List[ForensicEvidence]) -> str:
        """Generate a summary of the timeline."""
        if not evidence_list:
            return "No evidence available"
        
        duration = evidence_list[-1].timestamp - evidence_list[0].timestamp
        evidence_types = list(set(ev.evidence_type for ev in evidence_list))
        
        summary = f"Incident timeline spanning {duration} with {len(evidence_list)} pieces of evidence. "
        summary += f"Evidence types: {', '.join(evidence_types)}. "
        
        # Add key events
        key_events = evidence_list[:3]  # First 3 events
        if key_events:
            summary += "Key events: "
            for event in key_events:
                summary += f"{event.timestamp.strftime('%H:%M:%S')} - {event.source}; "
        
        return summary.strip()
    
    def analyze_memory_dump(self, memory_data: str) -> Dict[str, Any]:
        """Analyze memory dump for forensic artifacts."""
        analysis = {
            "processes": [],
            "network_connections": [],
            "loaded_modules": [],
            "suspicious_patterns": [],
            "confidence_score": 0.0
        }
        
        # Process analysis patterns
        process_patterns = [
            r"process:\s*(\w+\.exe)",
            r"pid:\s*(\d+)",
            r"parent_pid:\s*(\d+)"
        ]
        
        for pattern in process_patterns:
            matches = re.findall(pattern, memory_data, re.IGNORECASE)
            if matches:
                analysis["processes"].extend(matches)
        
        # Network connection patterns
        network_patterns = [
            r"tcp:\s*(\d+\.\d+\.\d+\.\d+:\d+)",
            r"udp:\s*(\d+\.\d+\.\d+\.\d+:\d+)",
            r"connection:\s*(\w+)"
        ]
        
        for pattern in network_patterns:
            matches = re.findall(pattern, memory_data, re.IGNORECASE)
            if matches:
                analysis["network_connections"].extend(matches)
        
        # Suspicious pattern detection
        suspicious_patterns = [
            r"shellcode", r"injection", r"hook", r"rootkit",
            r"malware", r"backdoor", r"trojan"
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, memory_data, re.IGNORECASE):
                analysis["suspicious_patterns"].append(pattern)
        
        # Calculate confidence score
        total_artifacts = (len(analysis["processes"]) + 
                          len(analysis["network_connections"]) + 
                          len(analysis["suspicious_patterns"]))
        analysis["confidence_score"] = min(total_artifacts * 0.1, 1.0)
        
        return analysis
    
    def generate_forensic_report(self, timeline: ForensicTimeline) -> Dict[str, Any]:
        """Generate comprehensive forensic report."""
        report = {
            "case_info": {
                "timeline_id": timeline.timeline_id,
                "incident_type": timeline.incident_type,
                "start_time": timeline.start_time.isoformat(),
                "end_time": timeline.end_time.isoformat(),
                "duration": str(timeline.end_time - timeline.start_time),
                "total_evidence": len(timeline.events)
            },
            "executive_summary": timeline.summary,
            "evidence_analysis": {
                "by_type": {},
                "by_source": {},
                "confidence_distribution": {}
            },
            "timeline_events": [],
            "correlations": {},
            "chain_of_custody": self.chain_of_custody,
            "recommendations": []
        }
        
        # Analyze evidence by type and source
        for evidence in timeline.events:
            # By type
            if evidence.evidence_type not in report["evidence_analysis"]["by_type"]:
                report["evidence_analysis"]["by_type"][evidence.evidence_type] = 0
            report["evidence_analysis"]["by_type"][evidence.evidence_type] += 1
            
            # By source
            if evidence.source not in report["evidence_analysis"]["by_source"]:
                report["evidence_analysis"]["by_source"][evidence.source] = 0
            report["evidence_analysis"]["by_source"][evidence.source] += 1
            
            # Timeline events
            report["timeline_events"].append({
                "timestamp": evidence.timestamp.isoformat(),
                "evidence_id": evidence.evidence_id,
                "source": evidence.source,
                "type": evidence.evidence_type,
                "summary": evidence.content[:100] + "..." if len(evidence.content) > 100 else evidence.content,
                "confidence": evidence.confidence_score
            })
        
        # Generate correlations
        report["correlations"] = self.correlate_evidence(timeline.events)
        
        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(timeline)
        
        return report
    
    def _generate_recommendations(self, timeline: ForensicTimeline) -> List[str]:
        """Generate forensic recommendations based on timeline analysis."""
        recommendations = []
        
        # Based on incident type
        if timeline.incident_type == "network":
            recommendations.append("Review firewall logs for additional network activity")
            recommendations.append("Analyze network traffic captures for data exfiltration")
        elif timeline.incident_type == "file_system":
            recommendations.append("Perform file integrity checks on critical system files")
            recommendations.append("Review backup systems for file recovery options")
        elif timeline.incident_type == "process":
            recommendations.append("Analyze process memory dumps for malicious code")
            recommendations.append("Review system startup programs and services")
        
        # General recommendations
        recommendations.append("Preserve all evidence with proper chain of custody")
        recommendations.append("Document all analysis steps and findings")
        recommendations.append("Consider additional data sources for comprehensive analysis")
        
        return recommendations

def main():
    """Main function for digital forensics analysis."""
    logger.info("Starting Digital Forensics Analysis System")
    
    # Initialize ForensicLLM
    forensic_llm = ForensicLLM()
    forensic_llm.initialize_model()
    
    # Sample forensic evidence
    sample_evidence = [
        ForensicEvidence(
            evidence_id="EV001",
            timestamp=datetime.now() - timedelta(hours=2),
            source="system_log",
            evidence_type="process",
            content="Process malware.exe started with PID 1234 at 14:30:15",
            hash_value="",
            metadata={"log_level": "warning", "system": "workstation-01"}
        ),
        ForensicEvidence(
            evidence_id="EV002",
            timestamp=datetime.now() - timedelta(hours=1, minutes=45),
            source="network_log",
            evidence_type="network",
            content="Outbound connection to suspicious IP 192.168.1.100:8080",
            hash_value="",
            metadata={"protocol": "tcp", "bytes_transferred": 1024}
        ),
        ForensicEvidence(
            evidence_id="EV003",
            timestamp=datetime.now() - timedelta(hours=1, minutes=30),
            source="file_system",
            evidence_type="file_system",
            content="File C:\\temp\\sensitive_data.txt accessed and modified",
            hash_value="",
            metadata={"file_size": 2048, "permissions": "read_write"}
        ),
        ForensicEvidence(
            evidence_id="EV004",
            timestamp=datetime.now() - timedelta(hours=1),
            source="system_log",
            evidence_type="process",
            content="Process malware.exe terminated with exit code 0",
            hash_value="",
            metadata={"duration": "30 minutes", "cpu_usage": "high"}
        )
    ]
    
    # Add evidence to store
    for evidence in sample_evidence:
        forensic_llm.add_evidence(evidence)
    
    # Reconstruct timeline
    logger.info("Reconstructing forensic timeline...")
    timeline = forensic_llm.reconstruct_timeline(sample_evidence)
    
    # Generate forensic report
    logger.info("Generating forensic report...")
    report = forensic_llm.generate_forensic_report(timeline)
    
    # Display results
    print("\n" + "="*60)
    print("DIGITAL FORENSICS ANALYSIS REPORT")
    print("="*60)
    
    print(f"\nCASE INFORMATION:")
    print(f"Timeline ID: {report['case_info']['timeline_id']}")
    print(f"Incident Type: {report['case_info']['incident_type']}")
    print(f"Duration: {report['case_info']['duration']}")
    print(f"Total Evidence: {report['case_info']['total_evidence']}")
    
    print(f"\nEXECUTIVE SUMMARY:")
    print(f"{report['executive_summary']}")
    
    print(f"\nTIMELINE EVENTS:")
    for event in report['timeline_events']:
        print(f"  {event['timestamp']} - {event['source']}: {event['summary']}")
    
    print(f"\nEVIDENCE ANALYSIS:")
    print(f"By Type: {report['evidence_analysis']['by_type']}")
    print(f"By Source: {report['evidence_analysis']['by_source']}")
    
    print(f"\nRECOMMENDATIONS:")
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"  {i}. {rec}")
    
    # Sample memory analysis
    print(f"\nMEMORY ANALYSIS SAMPLE:")
    sample_memory = """
    process: malware.exe pid: 1234 parent_pid: 567
    tcp: 192.168.1.100:8080 connection: established
    shellcode detected at address 0x7fff1234
    injection technique identified
    """
    
    memory_analysis = forensic_llm.analyze_memory_dump(sample_memory)
    print(f"Processes: {memory_analysis['processes']}")
    print(f"Network Connections: {memory_analysis['network_connections']}")
    print(f"Suspicious Patterns: {memory_analysis['suspicious_patterns']}")
    print(f"Confidence Score: {memory_analysis['confidence_score']:.3f}")
    
    # Save results
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    
    with open(output_dir / "forensic_report.json", 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    logger.info(f"Forensic report saved to {output_dir / 'forensic_report.json'}")

if __name__ == "__main__":
    main()