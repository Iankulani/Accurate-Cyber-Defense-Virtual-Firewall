#!/usr/bin/env python3
"""
Advanced Threat Detection Modules
Implements sophisticated algorithms for detecting various cybersecurity threats
"""

import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)

@dataclass
class ThreatEvent:
    """Data class for threat events"""
    timestamp: datetime
    source_ip: str
    threat_type: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    confidence: float

class PortScanDetector:
    """Advanced port scanning detection using multiple algorithms"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scan_threshold = config.get('port_scan', 100)
        self.time_window = config.get('time_window', 300)  # 5 minutes
        self.connection_history = defaultdict(lambda: deque(maxlen=1000))
        self.port_sequences = defaultdict(lambda: deque(maxlen=100))
        self.suspicious_ips = set()
        
    def analyze_packet(self, packet_info: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Analyze packet for port scanning indicators"""
        try:
            if not self._is_valid_packet(packet_info):
                return None
            
            src_ip = packet_info.get('src_ip')
            dst_port = packet_info.get('dst_port')
            timestamp = packet_info.get('timestamp')
            
            if not all([src_ip, dst_port, timestamp]):
                return None
            
            # Update connection history
            self.connection_history[src_ip].append({
                'port': dst_port,
                'timestamp': timestamp,
                'protocol': packet_info.get('protocol', 'unknown')
            })
            
            # Check for various port scanning patterns
            threats = []
            
            # 1. Sequential port scanning
            if self._detect_sequential_scanning(src_ip):
                threats.append(('sequential_scan', 'high', 0.9))
            
            # 2. Random port scanning
            if self._detect_random_scanning(src_ip):
                threats.append(('random_scan', 'medium', 0.8))
            
            # 3. Rapid port scanning
            if self._detect_rapid_scanning(src_ip):
                threats.append(('rapid_scan', 'high', 0.85))
            
            # 4. Stealth port scanning
            if self._detect_stealth_scanning(src_ip):
                threats.append(('stealth_scan', 'medium', 0.75))
            
            # 5. Port range scanning
            if self._detect_range_scanning(src_ip):
                threats.append(('range_scan', 'medium', 0.8))
            
            # Return the highest confidence threat
            if threats:
                threats.sort(key=lambda x: x[2], reverse=True)
                threat_type, severity, confidence = threats[0]
                
                return ThreatEvent(
                    timestamp=timestamp,
                    source_ip=src_ip,
                    threat_type=f"port_scanning_{threat_type}",
                    severity=severity,
                    description=f"Port scanning detected: {threat_type} from {src_ip}",
                    evidence={
                        'scan_type': threat_type,
                        'ports_scanned': len(self.connection_history[src_ip]),
                        'time_window': self.time_window,
                        'confidence': confidence
                    },
                    confidence=confidence
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in port scan detection: {e}")
            return None
    
    def _is_valid_packet(self, packet_info: Dict[str, Any]) -> bool:
        """Check if packet is valid for analysis"""
        return (
            packet_info.get('src_ip') and
            packet_info.get('dst_port') and
            packet_info.get('timestamp') and
            packet_info.get('protocol') in ['tcp', 'udp']
        )
    
    def _detect_sequential_scanning(self, src_ip: str) -> bool:
        """Detect sequential port scanning patterns"""
        try:
            connections = list(self.connection_history[src_ip])
            if len(connections) < 10:
                return False
            
            # Get recent connections within time window
            recent_connections = self._get_recent_connections(connections)
            if len(recent_connections) < 5:
                return False
            
            ports = [conn['port'] for conn in recent_connections]
            
            # Check for sequential patterns
            sequential_count = 0
            for i in range(len(ports) - 1):
                if abs(ports[i+1] - ports[i]) == 1:
                    sequential_count += 1
            
            # If more than 70% of connections are sequential
            return (sequential_count / (len(ports) - 1)) > 0.7
            
        except Exception as e:
            logger.error(f"Error detecting sequential scanning: {e}")
            return False
    
    def _detect_random_scanning(self, src_ip: str) -> bool:
        """Detect random port scanning patterns"""
        try:
            connections = list(self.connection_history[src_ip])
            if len(connections) < 20:
                return False
            
            recent_connections = self._get_recent_connections(connections)
            if len(recent_connections) < 10:
                return False
            
            ports = [conn['port'] for conn in recent_connections]
            
            # Calculate port distribution
            port_ranges = self._get_port_ranges(ports)
            
            # Random scanning typically hits many different port ranges
            return len(port_ranges) > 8
            
        except Exception as e:
            logger.error(f"Error detecting random scanning: {e}")
            return False
    
    def _detect_rapid_scanning(self, src_ip: str) -> bool:
        """Detect rapid port scanning (high frequency)"""
        try:
            connections = list(self.connection_history[src_ip])
            if len(connections) < 5:
                return False
            
            recent_connections = self._get_recent_connections(connections)
            if len(recent_connections) < 5:
                return False
            
            # Calculate connection rate
            time_span = (recent_connections[-1]['timestamp'] - recent_connections[0]['timestamp']).total_seconds()
            if time_span == 0:
                return False
            
            connection_rate = len(recent_connections) / time_span
            
            # High rate indicates rapid scanning
            return connection_rate > 10  # More than 10 connections per second
            
        except Exception as e:
            logger.error(f"Error detecting rapid scanning: {e}")
            return False
    
    def _detect_stealth_scanning(self, src_ip: str) -> bool:
        """Detect stealth port scanning (slow, distributed)"""
        try:
            connections = list(self.connection_history[src_ip])
            if len(connections) < 15:
                return False
            
            # Check for slow, distributed scanning
            time_span = (connections[-1]['timestamp'] - connections[0]['timestamp']).total_seconds()
            if time_span < 60:  # Less than 1 minute
                return False
            
            # Calculate average time between connections
            intervals = []
            for i in range(1, len(connections)):
                interval = (connections[i]['timestamp'] - connections[i-1]['timestamp']).total_seconds()
                intervals.append(interval)
            
            avg_interval = np.mean(intervals)
            
            # Stealth scanning has longer intervals
            return avg_interval > 5  # More than 5 seconds between connections
            
        except Exception as e:
            logger.error(f"Error detecting stealth scanning: {e}")
            return False
    
    def _detect_range_scanning(self, src_ip: str) -> bool:
        """Detect port range scanning"""
        try:
            connections = list(self.connection_history[src_ip])
            if len(connections) < 10:
                return False
            
            recent_connections = self._get_recent_connections(connections)
            if len(recent_connections) < 10:
                return False
            
            ports = [conn['port'] for conn in recent_connections]
            ports.sort()
            
            # Check if ports cover a large range
            port_range = max(ports) - min(ports)
            return port_range > 1000  # Ports spread over 1000+ range
            
        except Exception as e:
            logger.error(f"Error detecting range scanning: {e}")
            return False
    
    def _get_recent_connections(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get connections within the time window"""
        if not connections:
            return []
        
        cutoff_time = datetime.now() - timedelta(seconds=self.time_window)
        return [conn for conn in connections if conn['timestamp'] > cutoff_time]
    
    def _get_port_ranges(self, ports: List[int]) -> List[Tuple[int, int]]:
        """Get port ranges from list of ports"""
        if not ports:
            return []
        
        ports = sorted(set(ports))
        ranges = []
        start = end = ports[0]
        
        for port in ports[1:]:
            if port == end + 1:
                end = port
            else:
                ranges.append((start, end))
                start = end = port
        
        ranges.append((start, end))
        return ranges

class DoSDDoSDetector:
    """Advanced DoS/DDoS detection using multiple algorithms"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.syn_threshold = config.get('syn_flood', 1000)
        self.udp_threshold = config.get('udp_flood', 500)
        self.http_threshold = config.get('http_flood', 200)
        self.icmp_threshold = config.get('icmp_flood', 300)
        
        # Traffic analysis windows
        self.short_window = 10  # 10 seconds
        self.medium_window = 60  # 1 minute
        self.long_window = 300   # 5 minutes
        
        # Traffic history
        self.traffic_history = defaultdict(lambda: {
            'short': deque(maxlen=100),
            'medium': deque(maxlen=600),
            'long': deque(maxlen=3000)
        })
        
        # Baseline traffic patterns
        self.baseline = defaultdict(lambda: {
            'packet_rate': 0,
            'byte_rate': 0,
            'connection_rate': 0
        })
        
        # Suspicious IPs
        self.suspicious_ips = set()
        self.blocked_ips = set()
    
    def analyze_packet(self, packet_info: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Analyze packet for DoS/DDoS indicators"""
        try:
            if not self._is_valid_packet(packet_info):
                return None
            
            src_ip = packet_info.get('src_ip')
            timestamp = packet_info.get('timestamp')
            packet_length = packet_info.get('length', 0)
            protocol = packet_info.get('protocol', 'unknown')
            
            # Update traffic history
            self._update_traffic_history(src_ip, timestamp, packet_length, protocol)
            
            # Check for various attack patterns
            threats = []
            
            # 1. SYN Flood detection
            if self._detect_syn_flood(src_ip):
                threats.append(('syn_flood', 'high', 0.95))
            
            # 2. UDP Flood detection
            if self._detect_udp_flood(src_ip):
                threats.append(('udp_flood', 'high', 0.9))
            
            # 3. HTTP Flood detection
            if self._detect_http_flood(src_ip):
                threats.append(('http_flood', 'medium', 0.85))
            
            # 4. ICMP Flood detection
            if self._detect_icmp_flood(src_ip):
                threats.append(('icmp_flood', 'medium', 0.8))
            
            # 5. General DoS detection
            if self._detect_general_dos(src_ip):
                threats.append(('general_dos', 'high', 0.9))
            
            # 6. DDoS detection
            if self._detect_ddos():
                threats.append(('ddos', 'critical', 0.95))
            
            # Return the highest severity threat
            if threats:
                threats.sort(key=lambda x: (self._severity_to_numeric(x[1]), x[2]), reverse=True)
                threat_type, severity, confidence = threats[0]
                
                return ThreatEvent(
                    timestamp=timestamp,
                    source_ip=src_ip,
                    threat_type=threat_type,
                    severity=severity,
                    description=f"{threat_type.replace('_', ' ').title()} attack detected from {src_ip}",
                    evidence={
                        'attack_type': threat_type,
                        'traffic_analysis': self._get_traffic_analysis(src_ip),
                        'baseline_comparison': self._compare_to_baseline(src_ip),
                        'confidence': confidence
                    },
                    confidence=confidence
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in DoS/DDoS detection: {e}")
            return None
    
    def _is_valid_packet(self, packet_info: Dict[str, Any]) -> bool:
        """Check if packet is valid for analysis"""
        return (
            packet_info.get('src_ip') and
            packet_info.get('timestamp') and
            packet_info.get('length', 0) > 0
        )
    
    def _update_traffic_history(self, src_ip: str, timestamp: datetime, length: int, protocol: str):
        """Update traffic history for analysis"""
        try:
            traffic_record = {
                'timestamp': timestamp,
                'length': length,
                'protocol': protocol
            }
            
            # Update all time windows
            for window_name in ['short', 'medium', 'long']:
                self.traffic_history[src_ip][window_name].append(traffic_record)
            
            # Update baseline if enough data
            if len(self.traffic_history[src_ip]['long']) >= 100:
                self._update_baseline(src_ip)
                
        except Exception as e:
            logger.error(f"Error updating traffic history: {e}")
    
    def _update_baseline(self, src_ip: str):
        """Update baseline traffic patterns"""
        try:
            long_history = self.traffic_history[src_ip]['long']
            
            if len(long_history) < 100:
                return
            
            # Calculate baseline metrics
            packet_rate = len(long_history) / self.long_window
            byte_rate = sum(record['length'] for record in long_history) / self.long_window
            connection_rate = len(set(record['timestamp'] for record in long_history)) / self.long_window
            
            self.baseline[src_ip].update({
                'packet_rate': packet_rate,
                'byte_rate': byte_rate,
                'connection_rate': connection_rate
            })
            
        except Exception as e:
            logger.error(f"Error updating baseline: {e}")
    
    def _detect_syn_flood(self, src_ip: str) -> bool:
        """Detect SYN flood attacks"""
        try:
            short_history = self.traffic_history[src_ip]['short']
            if len(short_history) < 10:
                return False
            
            # Count SYN packets in short window
            syn_count = sum(1 for record in short_history if record.get('protocol') == 'tcp')
            
            # Check against threshold
            return syn_count > self.syn_threshold
            
        except Exception as e:
            logger.error(f"Error detecting SYN flood: {e}")
            return False
    
    def _detect_udp_flood(self, src_ip: str) -> bool:
        """Detect UDP flood attacks"""
        try:
            short_history = self.traffic_history[src_ip]['short']
            if len(short_history) < 10:
                return False
            
            # Count UDP packets in short window
            udp_count = sum(1 for record in short_history if record.get('protocol') == 'udp')
            
            # Check against threshold
            return udp_count > self.udp_threshold
            
        except Exception as e:
            logger.error(f"Error detecting UDP flood: {e}")
            return False
    
    def _detect_http_flood(self, src_ip: str) -> bool:
        """Detect HTTP flood attacks"""
        try:
            short_history = self.traffic_history[src_ip]['short']
            if len(short_history) < 10:
                return False
            
            # Count HTTP-related packets (port 80/443)
            http_count = sum(1 for record in short_history 
                           if record.get('protocol') == 'tcp' and 
                           record.get('dst_port') in [80, 443])
            
            # Check against threshold
            return http_count > self.http_threshold
            
        except Exception as e:
            logger.error(f"Error detecting HTTP flood: {e}")
            return False
    
    def _detect_icmp_flood(self, src_ip: str) -> bool:
        """Detect ICMP flood attacks"""
        try:
            short_history = self.traffic_history[src_ip]['short']
            if len(short_history) < 10:
                return False
            
            # Count ICMP packets in short window
            icmp_count = sum(1 for record in short_history if record.get('protocol') == 'icmp')
            
            # Check against threshold
            return icmp_count > self.icmp_threshold
            
        except Exception as e:
            logger.error(f"Error detecting ICMP flood: {e}")
            return False
    
    def _detect_general_dos(self, src_ip: str) -> bool:
        """Detect general DoS attacks using traffic analysis"""
        try:
            if src_ip not in self.baseline:
                return False
            
            current_traffic = self._get_current_traffic_metrics(src_ip)
            baseline = self.baseline[src_ip]
            
            # Check for significant deviations from baseline
            packet_rate_ratio = current_traffic['packet_rate'] / (baseline['packet_rate'] + 1)
            byte_rate_ratio = current_traffic['byte_rate'] / (baseline['byte_rate'] + 1)
            
            # If traffic is 10x above baseline, likely DoS
            return packet_rate_ratio > 10 or byte_rate_ratio > 10
            
        except Exception as e:
            logger.error(f"Error detecting general DoS: {e}")
            return False
    
    def _detect_ddos(self) -> bool:
        """Detect distributed DoS attacks"""
        try:
            # Check if multiple IPs are attacking simultaneously
            attacking_ips = []
            
            for src_ip in self.traffic_history:
                if self._is_attacking(src_ip):
                    attacking_ips.append(src_ip)
            
            # If more than 5 IPs are attacking, likely DDoS
            return len(attacking_ips) > 5
            
        except Exception as e:
            logger.error(f"Error detecting DDoS: {e}")
            return False
    
    def _is_attacking(self, src_ip: str) -> bool:
        """Check if an IP is currently attacking"""
        try:
            short_history = self.traffic_history[src_ip]['short']
            if len(short_history) < 5:
                return False
            
            # Check if traffic is above normal levels
            current_rate = len(short_history) / self.short_window
            baseline_rate = self.baseline.get(src_ip, {}).get('packet_rate', 1)
            
            return current_rate > (baseline_rate * 5)
            
        except Exception as e:
            logger.error(f"Error checking attack status: {e}")
            return False
    
    def _get_current_traffic_metrics(self, src_ip: str) -> Dict[str, float]:
        """Get current traffic metrics for an IP"""
        try:
            short_history = self.traffic_history[src_ip]['short']
            
            if len(short_history) < 5:
                return {'packet_rate': 0, 'byte_rate': 0, 'connection_rate': 0}
            
            packet_rate = len(short_history) / self.short_window
            byte_rate = sum(record['length'] for record in short_history) / self.short_window
            connection_rate = len(set(record['timestamp'] for record in short_history)) / self.short_window
            
            return {
                'packet_rate': packet_rate,
                'byte_rate': byte_rate,
                'connection_rate': connection_rate
            }
            
        except Exception as e:
            logger.error(f"Error getting traffic metrics: {e}")
            return {'packet_rate': 0, 'byte_rate': 0, 'connection_rate': 0}
    
    def _compare_to_baseline(self, src_ip: str) -> Dict[str, Any]:
        """Compare current traffic to baseline"""
        try:
            if src_ip not in self.baseline:
                return {'status': 'no_baseline'}
            
            current = self._get_current_traffic_metrics(src_ip)
            baseline = self.baseline[src_ip]
            
            return {
                'status': 'comparison',
                'packet_rate_ratio': current['packet_rate'] / (baseline['packet_rate'] + 1),
                'byte_rate_ratio': current['byte_rate'] / (baseline['byte_rate'] + 1),
                'connection_rate_ratio': current['connection_rate'] / (baseline['connection_rate'] + 1)
            }
            
        except Exception as e:
            logger.error(f"Error comparing to baseline: {e}")
            return {'status': 'error'}
    
    def _get_traffic_analysis(self, src_ip: str) -> Dict[str, Any]:
        """Get comprehensive traffic analysis for an IP"""
        try:
            return {
                'short_window': len(self.traffic_history[src_ip]['short']),
                'medium_window': len(self.traffic_history[src_ip]['medium']),
                'long_window': len(self.traffic_history[src_ip]['long']),
                'current_metrics': self._get_current_traffic_metrics(src_ip),
                'baseline': self.baseline.get(src_ip, {})
            }
            
        except Exception as e:
            logger.error(f"Error getting traffic analysis: {e}")
            return {}
    
    def _severity_to_numeric(self, severity: str) -> int:
        """Convert severity string to numeric value for sorting"""
        severity_map = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return severity_map.get(severity, 0)

class AdvancedThreatAnalyzer:
    """Advanced threat analysis combining multiple detection methods"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.port_scan_detector = PortScanDetector(config)
        self.dos_ddos_detector = DoSDDoSDetector(config)
        
        # Threat correlation
        self.threat_correlation = defaultdict(list)
        self.threat_timeline = deque(maxlen=10000)
        
        # Machine learning features
        self.feature_extractor = ThreatFeatureExtractor()
        self.anomaly_detector = MLAnomalyDetector()
    
    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[ThreatEvent]:
        """Comprehensive packet analysis for all threat types"""
        threats = []
        
        try:
            # Port scanning detection
            port_scan_threat = self.port_scan_detector.analyze_packet(packet_info)
            if port_scan_threat:
                threats.append(port_scan_threat)
            
            # DoS/DDoS detection
            dos_threat = self.dos_ddos_detector.analyze_packet(packet_info)
            if dos_threat:
                threats.append(dos_threat)
            
            # Advanced threat correlation
            if threats:
                self._correlate_threats(threats)
                
                # Update threat timeline
                for threat in threats:
                    self.threat_timeline.append(threat)
                
                # Machine learning analysis
                ml_threats = self._analyze_with_ml(packet_info, threats)
                threats.extend(ml_threats)
            
            return threats
            
        except Exception as e:
            logger.error(f"Error in advanced threat analysis: {e}")
            return []
    
    def _correlate_threats(self, threats: List[ThreatEvent]):
        """Correlate related threats for better analysis"""
        try:
            for threat in threats:
                src_ip = threat.source_ip
                threat_type = threat.threat_type
                
                # Group threats by source IP
                self.threat_correlation[src_ip].append({
                    'type': threat_type,
                    'timestamp': threat.timestamp,
                    'severity': threat.severity,
                    'confidence': threat.confidence
                })
                
                # Check for threat patterns
                self._analyze_threat_patterns(src_ip)
                
        except Exception as e:
            logger.error(f"Error correlating threats: {e}")
    
    def _analyze_threat_patterns(self, src_ip: str):
        """Analyze threat patterns for an IP"""
        try:
            if src_ip not in self.threat_correlation:
                return
            
            threats = self.threat_correlation[src_ip]
            if len(threats) < 3:
                return
            
            # Check for escalation patterns
            recent_threats = [t for t in threats if 
                            (datetime.now() - t['timestamp']).total_seconds() < 300]
            
            if len(recent_threats) >= 3:
                # Multiple threats in short time - potential attack escalation
                logger.warning(f"Attack escalation detected from {src_ip}: {len(recent_threats)} threats in 5 minutes")
                
                # Check for severity escalation
                severities = [t['severity'] for t in recent_threats]
                if 'critical' in severities and 'low' in severities:
                    logger.critical(f"Severity escalation detected from {src_ip}")
                    
        except Exception as e:
            logger.error(f"Error analyzing threat patterns: {e}")
    
    def _analyze_with_ml(self, packet_info: Dict[str, Any], existing_threats: List[ThreatEvent]) -> List[ThreatEvent]:
        """Analyze threats using machine learning"""
        try:
            # Extract features
            features = self.feature_extractor.extract_features(packet_info, existing_threats)
            
            # Get ML predictions
            ml_threats = self.anomaly_detector.predict_threats(features)
            
            return ml_threats
            
        except Exception as e:
            logger.error(f"Error in ML analysis: {e}")
            return []
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get comprehensive threat summary"""
        try:
            summary = {
                'total_threats': len(self.threat_timeline),
                'threats_by_type': defaultdict(int),
                'threats_by_severity': defaultdict(int),
                'threats_by_ip': defaultdict(int),
                'recent_threats': [],
                'correlation_insights': []
            }
            
            # Analyze threat timeline
            for threat in self.threat_timeline:
                summary['threats_by_type'][threat.threat_type] += 1
                summary['threats_by_severity'][threat.severity] += 1
                summary['threats_by_ip'][threat.source_ip] += 1
            
            # Get recent threats
            recent_cutoff = datetime.now() - timedelta(hours=1)
            summary['recent_threats'] = [
                {
                    'type': t.threat_type,
                    'source': t.source_ip,
                    'severity': t.severity,
                    'timestamp': t.timestamp
                }
                for t in self.threat_timeline
                if t.timestamp > recent_cutoff
            ]
            
            # Get correlation insights
            for src_ip, threats in self.threat_correlation.items():
                if len(threats) >= 3:
                    summary['correlation_insights'].append({
                        'ip': src_ip,
                        'threat_count': len(threats),
                        'threat_types': list(set(t['type'] for t in threats)),
                        'severity_levels': list(set(t['severity'] for t in threats))
                    })
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting threat summary: {e}")
            return {}

class ThreatFeatureExtractor:
    """Extract features for machine learning analysis"""
    
    def __init__(self):
        self.feature_names = [
            'packet_length', 'protocol_type', 'port_number', 'ip_hash',
            'timestamp_hour', 'timestamp_minute', 'day_of_week',
            'threat_count', 'severity_score', 'confidence_score'
        ]
    
    def extract_features(self, packet_info: Dict[str, Any], threats: List[ThreatEvent]) -> List[float]:
        """Extract numerical features from packet and threat data"""
        try:
            features = []
            
            # Packet features
            features.append(packet_info.get('length', 0))
            features.append(self._protocol_to_numeric(packet_info.get('protocol', 'unknown')))
            features.append(packet_info.get('dst_port', 0))
            features.append(hash(packet_info.get('src_ip', '')) % 1000)
            
            # Temporal features
            timestamp = packet_info.get('timestamp', datetime.now())
            features.append(timestamp.hour)
            features.append(timestamp.minute)
            features.append(timestamp.weekday())
            
            # Threat features
            features.append(len(threats))
            features.append(self._calculate_severity_score(threats))
            features.append(self._calculate_confidence_score(threats))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return [0.0] * len(self.feature_names)
    
    def _protocol_to_numeric(self, protocol: str) -> int:
        """Convert protocol string to numeric value"""
        protocol_map = {
            'tcp': 1, 'udp': 2, 'icmp': 3, 'http': 4, 'https': 5
        }
        return protocol_map.get(protocol.lower(), 0)
    
    def _calculate_severity_score(self, threats: List[ThreatEvent]) -> float:
        """Calculate overall severity score"""
        if not threats:
            return 0.0
        
        severity_values = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        scores = [severity_values.get(t.severity, 0) for t in threats]
        return np.mean(scores)
    
    def _calculate_confidence_score(self, threats: List[ThreatEvent]) -> float:
        """Calculate overall confidence score"""
        if not threats:
            return 0.0
        
        confidences = [t.confidence for t in threats]
        return np.mean(confidences)

class MLAnomalyDetector:
    """Machine learning based anomaly detection for threats"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.training_data = deque(maxlen=10000)
    
    def predict_threats(self, features: List[float]) -> List[ThreatEvent]:
        """Predict threats using ML model"""
        try:
            if not self.is_trained or len(self.training_data) < 100:
                return []
            
            # Normalize features
            features_array = np.array(features).reshape(1, -1)
            normalized_features = self.scaler.transform(features_array)
            
            # Get prediction
            prediction = self.model.predict(normalized_features)[0]
            anomaly_score = self.model.decision_function(normalized_features)[0]
            
            # If anomaly detected, create threat event
            if prediction == -1 and anomaly_score < -0.5:
                return [ThreatEvent(
                    timestamp=datetime.now(),
                    source_ip='ml_detected',
                    threat_type='ml_anomaly',
                    severity='medium',
                    description=f'Machine learning anomaly detected (score: {anomaly_score:.3f})',
                    evidence={
                        'anomaly_score': anomaly_score,
                        'features': features,
                        'prediction': prediction
                    },
                    confidence=abs(anomaly_score)
                )]
            
            return []
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return []
    
    def update_model(self, features: List[float], is_threat: bool):
        """Update the ML model with new data"""
        try:
            self.training_data.append({
                'features': features,
                'label': -1 if is_threat else 1
            })
            
            # Retrain model periodically
            if len(self.training_data) >= 100 and len(self.training_data) % 100 == 0:
                self._retrain_model()
                
        except Exception as e:
            logger.error(f"Error updating ML model: {e}")
    
    def _retrain_model(self):
        """Retrain the machine learning model"""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            
            # Prepare training data
            X = np.array([item['features'] for item in self.training_data])
            y = np.array([item['label'] for item in self.training_data])
            
            # Scale features
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Train model
            self.model = IsolationForest(contamination=0.1, random_state=42)
            self.model.fit(X_scaled)
            
            self.is_trained = True
            logger.info("ML anomaly detection model retrained successfully")
            
        except Exception as e:
            logger.error(f"Error retraining ML model: {e}")

# Export main classes
__all__ = [
    'ThreatEvent',
    'PortScanDetector',
    'DoSDDoSDetector',
    'AdvancedThreatAnalyzer',
    'ThreatFeatureExtractor',
    'MLAnomalyDetector'
]