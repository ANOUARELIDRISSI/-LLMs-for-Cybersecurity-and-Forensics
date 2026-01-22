#!/usr/bin/env python3
"""
SOC Automation Module for Advanced LLMs Cybersecurity
Implements log analysis, triage, and automated incident response.
"""

import torch
from transformers import pipeline
import pandas as pd
import numpy as np
from pathlib import Path
import json
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ResponseAction(Enum):
    """Automated response actions."""
    MONITOR = "monitor"
    ALERT = "alert"
    ISOLATE = "isolate"
    BLOCK = "block"
    ESCALATE = "escalate"

@dataclass
class SecurityEvent:
    """Represents a security event from logs."""
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: ThreatLevel
    description: str
    raw_log: str
    indicators: List[str]
    confidence: float
    metadata: Dict[str, Any]

@dataclass
class IncidentResponse:
    """Automated incident response result."""
    incident_id: str
    events: List[SecurityEvent]
    threat_level: ThreatLevel
    recommended_actions: List[ResponseAction]
    automated_actions: List[str]
    analyst_notes: str
    status: str

class SOCAutomation:
    """SOC Automation system using LLMs."""
    
    def __init__(self):
        self.classifier = None
        self.event_store = []
        self.incident_counter = 0
        
        # Log patterns for different event types
        self.log_patterns = {
            "authentication": [
                r"login failed", r"authentication failed", r"invalid credentials",
                r"account locked", r"password expired", r"login successful"
            ],
            "network": [
                r"connection refused", r"port scan", r"unusual traffic",
                r"bandwidth spike", r"ddos", r"firewall block"
            ],
            "malware": [
                r"virus detected", r"malware found", r"suspicious file",
                r"quarantine", r"trojan", r"ransomware"
            ],
            "data_access": [
                r"unauthorized access", r"data breach", r"file accessed",
                r"permission denied", r"privilege escalation"
            ],
            "system": [
                r"service stopped", r"system crash", r"disk full",
                r"memory usage", r"cpu spike", r"process terminated"
            ]
        }
        
        # Severity keywords
        self.severity_keywords = {
            ThreatLevel.CRITICAL: ["critical", "emergency", "breach", "compromise"],
            ThreatLevel.HIGH: ["high", "alert", "attack", "malware", "intrusion"],
            ThreatLevel.MEDIUM: ["medium", "warning", "suspicious", "anomaly"],
            ThreatLevel.LOW: ["low", "info", "notice", "routine"]
        }
    
    def initialize_models(self) -> None:
        """Initialize ML models for SOC automation."""
        try:
            logger.info("Loading SOC automation models...")
            
            # Use sentiment analysis as proxy for threat classification
            self.classifier = pipeline(
                "sentiment-analysis",
                model="cardiffnlp/twitter-roberta-base-sentiment-latest",
                device=0 if torch.cuda.is_available() else -1
            )
            
            logger.info("SOC models loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            raise
    
    def parse_log_entry(self, log_line: str, source: str = "unknown") -> Optional[SecurityEvent]:
        """Parse a single log entry into a SecurityEvent."""
        if not log_line.strip():
            return None
        
        # Extract timestamp (simplified pattern)
        timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', log_line)
        if timestamp_match:
            try:
                timestamp = datetime.strptime(timestamp_match.group(), '%Y-%m-%d %H:%M:%S')
            except ValueError:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        # Classify event type
        event_type, confidence = self._classify_event_type(log_line)
        
        # Determine severity
        severity = self._determine_severity(log_line)
        
        # Extract indicators
        indicators = self._extract_indicators(log_line)
        
        # Generate event ID
        event_id = f"EVT_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self.event_store)}"
        
        event = SecurityEvent(
            event_id=event_id,
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            description=self._generate_description(log_line, event_type),
            raw_log=log_line,
            indicators=indicators,
            confidence=confidence,
            metadata={"processed_at": datetime.now()}
        )
        
        return event
    
    def _classify_event_type(self, log_line: str) -> Tuple[str, float]:
        """Classify the type of security event."""
        scores = {}
        
        for event_type, patterns in self.log_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, log_line, re.IGNORECASE):
                    score += 1
            
            if score > 0:
                scores[event_type] = score / len(patterns)
        
        if not scores:
            return "unknown", 0.0
        
        best_type = max(scores.items(), key=lambda x: x[1])
        return best_type[0], best_type[1]
    
    def _determine_severity(self, log_line: str) -> ThreatLevel:
        """Determine severity level of the event."""
        log_lower = log_line.lower()
        
        # Check for severity keywords
        for level, keywords in self.severity_keywords.items():
            for keyword in keywords:
                if keyword in log_lower:
                    return level
        
        # Use ML classifier as additional input
        if self.classifier:
            try:
                result = self.classifier(log_line[:512])
                if result[0]['label'] == 'NEGATIVE' and result[0]['score'] > 0.8:
                    return ThreatLevel.HIGH
                elif result[0]['label'] == 'NEGATIVE':
                    return ThreatLevel.MEDIUM
            except Exception as e:
                logger.warning(f"Classifier error: {e}")
        
        return ThreatLevel.LOW
    
    def _extract_indicators(self, log_line: str) -> List[str]:
        """Extract security indicators from log line."""
        indicators = []
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, log_line)
        indicators.extend([f"IP: {ip}" for ip in ips])
        
        # File paths
        file_pattern = r'[A-Za-z]:\\[^\s]+'
        files = re.findall(file_pattern, log_line)
        indicators.extend([f"File: {file}" for file in files])
        
        # URLs
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, log_line)
        indicators.extend([f"URL: {url}" for url in urls])
        
        # Process names
        process_pattern = r'\b\w+\.exe\b'
        processes = re.findall(process_pattern, log_line, re.IGNORECASE)
        indicators.extend([f"Process: {proc}" for proc in processes])
        
        return indicators
    
    def _generate_description(self, log_line: str, event_type: str) -> str:
        """Generate human-readable description of the event."""
        descriptions = {
            "authentication": "Authentication-related security event",
            "network": "Network security event detected",
            "malware": "Malware or suspicious file activity",
            "data_access": "Data access or permission event",
            "system": "System-level security event",
            "unknown": "Unclassified security event"
        }
        
        base_desc = descriptions.get(event_type, "Security event")
        
        # Add key details from log
        if "failed" in log_line.lower():
            base_desc += " - Failed operation detected"
        elif "blocked" in log_line.lower():
            base_desc += " - Blocked activity"
        elif "denied" in log_line.lower():
            base_desc += " - Access denied"
        
        return base_desc
    
    def analyze_logs(self, log_lines: List[str], source: str = "system") -> List[SecurityEvent]:
        """Analyze multiple log lines and return security events."""
        if not self.classifier:
            self.initialize_models()
        
        events = []
        
        for i, log_line in enumerate(log_lines):
            logger.info(f"Processing log {i+1}/{len(log_lines)}")
            
            event = self.parse_log_entry(log_line, source)
            if event:
                events.append(event)
                self.event_store.append(event)
        
        return events
    
    def triage_events(self, events: List[SecurityEvent]) -> Dict[ThreatLevel, List[SecurityEvent]]:
        """Triage events by severity level."""
        triaged = {level: [] for level in ThreatLevel}
        
        for event in events:
            triaged[event.severity].append(event)
        
        return triaged
    
    def correlate_events(self, events: List[SecurityEvent], time_window: int = 300) -> List[List[SecurityEvent]]:
        """Correlate related events within time window (seconds)."""
        if not events:
            return []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        clusters = []
        current_cluster = [sorted_events[0]]
        
        for event in sorted_events[1:]:
            # Check if event is within time window of current cluster
            time_diff = (event.timestamp - current_cluster[-1].timestamp).total_seconds()
            
            if time_diff <= time_window:
                current_cluster.append(event)
            else:
                clusters.append(current_cluster)
                current_cluster = [event]
        
        # Add the last cluster
        if current_cluster:
            clusters.append(current_cluster)
        
        # Filter clusters with multiple events
        return [cluster for cluster in clusters if len(cluster) > 1]
    
    def generate_incident_response(self, event_cluster: List[SecurityEvent]) -> IncidentResponse:
        """Generate automated incident response for event cluster."""
        if not event_cluster:
            raise ValueError("No events provided for incident response")
        
        self.incident_counter += 1
        incident_id = f"INC_{datetime.now().strftime('%Y%m%d')}_{self.incident_counter:04d}"
        
        # Determine overall threat level
        severities = [event.severity for event in event_cluster]
        max_severity = max(severities, key=lambda x: x.value)
        
        # Generate recommended actions
        recommended_actions = self._determine_response_actions(max_severity, event_cluster)
        
        # Generate automated actions
        automated_actions = self._execute_automated_response(max_severity, event_cluster)
        
        # Generate analyst notes
        analyst_notes = self._generate_analyst_notes(event_cluster)
        
        incident = IncidentResponse(
            incident_id=incident_id,
            events=event_cluster,
            threat_level=max_severity,
            recommended_actions=recommended_actions,
            automated_actions=automated_actions,
            analyst_notes=analyst_notes,
            status="open"
        )
        
        return incident
    
    def _determine_response_actions(self, threat_level: ThreatLevel, events: List[SecurityEvent]) -> List[ResponseAction]:
        """Determine appropriate response actions based on threat level."""
        actions = []
        
        if threat_level == ThreatLevel.CRITICAL:
            actions.extend([ResponseAction.ISOLATE, ResponseAction.ESCALATE, ResponseAction.BLOCK])
        elif threat_level == ThreatLevel.HIGH:
            actions.extend([ResponseAction.ALERT, ResponseAction.BLOCK, ResponseAction.ESCALATE])
        elif threat_level == ThreatLevel.MEDIUM:
            actions.extend([ResponseAction.ALERT, ResponseAction.MONITOR])
        else:
            actions.append(ResponseAction.MONITOR)
        
        # Add specific actions based on event types
        event_types = [event.event_type for event in events]
        
        if "malware" in event_types:
            actions.append(ResponseAction.ISOLATE)
        if "network" in event_types:
            actions.append(ResponseAction.BLOCK)
        if "authentication" in event_types and len([e for e in events if "failed" in e.raw_log.lower()]) > 3:
            actions.append(ResponseAction.BLOCK)
        
        return list(set(actions))  # Remove duplicates
    
    def _execute_automated_response(self, threat_level: ThreatLevel, events: List[SecurityEvent]) -> List[str]:
        """Execute automated response actions."""
        executed_actions = []
        
        # Simulate automated actions
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            executed_actions.append("Automated alert sent to SOC team")
            executed_actions.append("Incident ticket created in ITSM system")
            
            # Check for specific indicators requiring blocking
            for event in events:
                for indicator in event.indicators:
                    if indicator.startswith("IP:"):
                        ip = indicator.split(": ")[1]
                        executed_actions.append(f"IP {ip} added to firewall block list")
                    elif indicator.startswith("Process:") and "malware" in event.event_type:
                        process = indicator.split(": ")[1]
                        executed_actions.append(f"Process {process} terminated on affected systems")
        
        if threat_level == ThreatLevel.CRITICAL:
            executed_actions.append("Emergency response team notified")
            executed_actions.append("Affected systems isolated from network")
        
        return executed_actions
    
    def _generate_analyst_notes(self, events: List[SecurityEvent]) -> str:
        """Generate notes for security analysts."""
        notes = []
        
        # Summary
        notes.append(f"Incident involves {len(events)} correlated events")
        
        # Event types
        event_types = list(set(event.event_type for event in events))
        notes.append(f"Event types: {', '.join(event_types)}")
        
        # Time span
        if len(events) > 1:
            time_span = max(event.timestamp for event in events) - min(event.timestamp for event in events)
            notes.append(f"Events occurred over {time_span}")
        
        # Key indicators
        all_indicators = []
        for event in events:
            all_indicators.extend(event.indicators)
        
        unique_indicators = list(set(all_indicators))[:5]  # Top 5
        if unique_indicators:
            notes.append(f"Key indicators: {', '.join(unique_indicators)}")
        
        # Recommendations
        notes.append("Recommended: Review full logs, validate automated actions, investigate root cause")
        
        return ". ".join(notes)
    
    def generate_soc_report(self, incidents: List[IncidentResponse]) -> Dict[str, Any]:
        """Generate comprehensive SOC automation report."""
        if not incidents:
            return {"error": "No incidents to analyze"}
        
        # Calculate metrics
        total_events = sum(len(incident.events) for incident in incidents)
        threat_distribution = {}
        
        for incident in incidents:
            level = incident.threat_level.name
            threat_distribution[level] = threat_distribution.get(level, 0) + 1
        
        # Automation effectiveness
        automated_actions = sum(len(incident.automated_actions) for incident in incidents)
        manual_actions = sum(len(incident.recommended_actions) for incident in incidents)
        automation_rate = automated_actions / (automated_actions + manual_actions) if (automated_actions + manual_actions) > 0 else 0
        
        report = {
            "summary": {
                "total_incidents": len(incidents),
                "total_events": total_events,
                "automation_rate": automation_rate,
                "avg_events_per_incident": total_events / len(incidents) if incidents else 0
            },
            "threat_distribution": threat_distribution,
            "automation_metrics": {
                "automated_actions": automated_actions,
                "manual_actions": manual_actions,
                "workload_reduction": f"{automation_rate * 100:.1f}%"
            },
            "incidents": [
                {
                    "incident_id": incident.incident_id,
                    "threat_level": incident.threat_level.name,
                    "event_count": len(incident.events),
                    "automated_actions": len(incident.automated_actions),
                    "status": incident.status,
                    "analyst_notes": incident.analyst_notes
                }
                for incident in incidents
            ],
            "recommendations": [
                "Continue monitoring automated response effectiveness",
                "Review false positive rates and adjust thresholds",
                "Enhance correlation rules based on incident patterns",
                "Provide analyst training on new automation features"
            ]
        }
        
        return report

def main():
    """Main function for SOC automation."""
    logger.info("Starting SOC Automation System")
    
    # Initialize SOC automation
    soc = SOCAutomation()
    
    # Sample log entries
    sample_logs = [
        "2024-01-22 14:30:15 [WARNING] Authentication failed for user admin from IP 192.168.1.100",
        "2024-01-22 14:30:45 [ALERT] Multiple failed login attempts detected from IP 192.168.1.100",
        "2024-01-22 14:31:00 [CRITICAL] Account admin locked due to excessive failed attempts",
        "2024-01-22 14:32:15 [HIGH] Suspicious network traffic detected to external IP 10.0.0.50",
        "2024-01-22 14:33:00 [WARNING] Malware signature detected in file C:\\temp\\malicious.exe",
        "2024-01-22 14:33:30 [CRITICAL] Process malicious.exe terminated by antivirus",
        "2024-01-22 14:35:00 [INFO] System backup completed successfully",
        "2024-01-22 14:36:15 [MEDIUM] Unusual data access pattern detected for user john.doe"
    ]
    
    # Analyze logs
    logger.info("Analyzing security logs...")
    events = soc.analyze_logs(sample_logs, "security_system")
    
    # Triage events
    logger.info("Triaging security events...")
    triaged_events = soc.triage_events(events)
    
    # Correlate events
    logger.info("Correlating related events...")
    event_clusters = soc.correlate_events(events, time_window=600)  # 10 minutes
    
    # Generate incident responses
    logger.info("Generating incident responses...")
    incidents = []
    for cluster in event_clusters:
        incident = soc.generate_incident_response(cluster)
        incidents.append(incident)
    
    # Generate SOC report
    report = soc.generate_soc_report(incidents)
    
    # Display results
    print("\n" + "="*60)
    print("SOC AUTOMATION REPORT")
    print("="*60)
    
    print(f"\nSUMMARY:")
    print(f"Total Incidents: {report['summary']['total_incidents']}")
    print(f"Total Events: {report['summary']['total_events']}")
    print(f"Automation Rate: {report['automation_metrics']['workload_reduction']}")
    print(f"Average Events per Incident: {report['summary']['avg_events_per_incident']:.1f}")
    
    print(f"\nTHREAT DISTRIBUTION:")
    for level, count in report['threat_distribution'].items():
        print(f"  {level}: {count}")
    
    print(f"\nTRIAGE RESULTS:")
    for level, events_list in triaged_events.items():
        print(f"  {level.name}: {len(events_list)} events")
    
    print(f"\nINCIDENT DETAILS:")
    for incident_info in report['incidents']:
        print(f"\n  {incident_info['incident_id']}:")
        print(f"    Threat Level: {incident_info['threat_level']}")
        print(f"    Events: {incident_info['event_count']}")
        print(f"    Automated Actions: {incident_info['automated_actions']}")
        print(f"    Notes: {incident_info['analyst_notes'][:100]}...")
    
    print(f"\nAUTOMATION METRICS:")
    print(f"Automated Actions: {report['automation_metrics']['automated_actions']}")
    print(f"Manual Actions: {report['automation_metrics']['manual_actions']}")
    print(f"Workload Reduction: {report['automation_metrics']['workload_reduction']}")
    
    # Save results
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    
    with open(output_dir / "soc_automation_report.json", 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    logger.info(f"SOC report saved to {output_dir / 'soc_automation_report.json'}")

if __name__ == "__main__":
    main()