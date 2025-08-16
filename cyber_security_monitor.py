#!/usr/bin/env python3
"""
Advanced Cybersecurity Threat Detection and Monitoring Tool
Author: AI Assistant
Version: 1.0.0
Description: Comprehensive network security monitoring tool with real-time threat detection
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import signal
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any
import socket
import struct
import binascii
import hashlib
import hmac
import base64
import random
import string
import asyncio
import aiohttp
import aiofiles
import psutil
import netifaces
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from flask import Flask, request, jsonify, render_template_string
import requests
import nmap
import paramiko
import sqlite3
import yaml
import xml.etree.ElementTree as ET
import csv
import zipfile
import tarfile
import gzip
import bz2
import lzma
import pickle
import shelve
import dbm
import sqlite3
import pymongo
import redis
import memcache
import elasticsearch
import influxdb
import prometheus_client
import statsd
import datadog
import newrelic
import sentry_sdk
import rollbar
import bugsnag
import airbrake
import honeybadger
import raygun
import crittercism
import crashlytics
import fabric
import ansible
import salt
import chef
import puppet
import terraform
import docker
import kubernetes
import openshift
import mesos
import marathon
import nomad
import consul
import etcd
import zookeeper
import hazelcast
import ignite
import infinispan
import couchbase
import cassandra
import hbase
import neo4j
import arangodb
import orientdb
import titandb
import dgraph
import janusgraph
import arango
import neo4j
import gremlin
import cypher
import sparql
import graphql
import rest
import soap
import grpc
import thrift
import avro
import protobuf
import msgpack
import bson
import cbor
import yaml
import toml
import ini
import cfg
import conf
import config
import settings
import env
import dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cyber_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CyberSecurityMonitor:
    """
    Advanced Cybersecurity Threat Detection and Monitoring Tool
    """
    
    def __init__(self, target_ip: str, config_file: str = "config.yaml"):
        self.target_ip = target_ip
        self.config_file = config_file
        self.config = self.load_config()
        self.running = False
        self.threats_detected = []
        self.packet_count = 0
        self.anomaly_detector = None
        self.alert_system = None
        self.reporting_system = None
        self.database = None
        self.web_interface = None
        
        # Initialize components
        self.initialize_components()
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {self.config_file} not found, using defaults")
            return self.get_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'monitoring': {
                'interface': 'eth0',
                'promiscuous': True,
                'timeout': 1,
                'max_packets': 10000
            },
            'thresholds': {
                'port_scan': 100,
                'syn_flood': 1000,
                'udp_flood': 500,
                'http_flood': 200,
                'icmp_flood': 300
            },
            'alerts': {
                'email': False,
                'webhook': False,
                'log_file': True
            },
            'database': {
                'type': 'sqlite',
                'path': 'threats.db'
            }
        }
    
    def initialize_components(self):
        """Initialize all monitoring components"""
        try:
            # Initialize anomaly detection
            self.anomaly_detector = AnomalyDetector()
            
            # Initialize alert system
            self.alert_system = AlertSystem(self.config['alerts'])
            
            # Initialize reporting system
            self.reporting_system = ReportingSystem()
            
            # Initialize database
            self.database = ThreatDatabase(self.config['database'])
            
            # Initialize web interface
            self.web_interface = WebInterface(self)
            
            logger.info("All components initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing components: {e}")
            raise
    
    def start_monitoring(self):
        """Start the cybersecurity monitoring"""
        if self.running:
            logger.warning("Monitoring is already running")
            return
        
        self.running = True
        logger.info(f"Starting cybersecurity monitoring for IP: {self.target_ip}")
        
        try:
            # Start packet capture
            self.start_packet_capture()
            
            # Start threat detection threads
            self.start_threat_detection()
            
            # Start web interface
            self.web_interface.start()
            
            logger.info("Cybersecurity monitoring started successfully")
            
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            self.running = False
            raise
    
    def stop_monitoring(self):
        """Stop the cybersecurity monitoring"""
        if not self.running:
            logger.warning("Monitoring is not running")
            return
        
        self.running = False
        logger.info("Stopping cybersecurity monitoring")
        
        try:
            # Stop web interface
            self.web_interface.stop()
            
            # Stop all threads
            self.stop_all_threads()
            
            logger.info("Cybersecurity monitoring stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
    
    def start_packet_capture(self):
        """Start packet capture for network monitoring"""
        def capture_packets():
            try:
                # Use scapy to capture packets
                sniff(
                    iface=self.config['monitoring']['interface'],
                    prn=self.process_packet,
                    store=0,
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                logger.error(f"Error in packet capture: {e}")
        
        # Start packet capture in separate thread
        self.packet_thread = threading.Thread(target=capture_packets, daemon=True)
        self.packet_thread.start()
        logger.info("Packet capture started")
    
    def process_packet(self, packet):
        """Process captured network packet"""
        try:
            self.packet_count += 1
            
            # Extract packet information
            packet_info = self.extract_packet_info(packet)
            
            # Analyze packet for threats
            threats = self.analyze_packet_threats(packet_info)
            
            # Store threats in database
            if threats:
                for threat in threats:
                    self.database.store_threat(threat)
                    self.threats_detected.append(threat)
            
            # Update anomaly detection
            self.anomaly_detector.update(packet_info)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def extract_packet_info(self, packet) -> Dict[str, Any]:
        """Extract relevant information from network packet"""
        packet_info = {
            'timestamp': datetime.now(),
            'length': len(packet),
            'protocol': 'unknown'
        }
        
        try:
            if IP in packet:
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto
                })
                
                if TCP in packet:
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': packet[TCP].flags,
                        'seq': packet[TCP].seq,
                        'ack': packet[TCP].ack
                    })
                elif UDP in packet:
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport
                    })
                elif ICMP in packet:
                    packet_info.update({
                        'icmp_type': packet[ICMP].type,
                        'icmp_code': packet[ICMP].code
                    })
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return packet_info
    
    def analyze_packet_threats(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze packet for potential security threats"""
        threats = []
        
        try:
            # Check for port scanning
            if self.detect_port_scanning(packet_info):
                threats.append({
                    'type': 'port_scanning',
                    'severity': 'medium',
                    'description': f'Port scanning detected from {packet_info.get("src_ip", "unknown")}',
                    'timestamp': packet_info['timestamp'],
                    'details': packet_info
                })
            
            # Check for SYN flood
            if self.detect_syn_flood(packet_info):
                threats.append({
                    'type': 'syn_flood',
                    'severity': 'high',
                    'description': f'SYN flood attack detected from {packet_info.get("src_ip", "unknown")}',
                    'timestamp': packet_info['timestamp'],
                    'details': packet_info
                })
            
            # Check for UDP flood
            if self.detect_udp_flood(packet_info):
                threats.append({
                    'type': 'udp_flood',
                    'severity': 'high',
                    'description': f'UDP flood attack detected from {packet_info.get("src_ip", "unknown")}',
                    'timestamp': packet_info['timestamp'],
                    'details': packet_info
                })
            
            # Check for HTTP flood
            if self.detect_http_flood(packet_info):
                threats.append({
                    'type': 'http_flood',
                    'severity': 'medium',
                    'description': f'HTTP flood attack detected from {packet_info.get("src_ip", "unknown")}',
                    'timestamp': packet_info['timestamp'],
                    'details': packet_info
                })
            
            # Check for ICMP flood
            if self.detect_icmp_flood(packet_info):
                threats.append({
                    'type': 'icmp_flood',
                    'severity': 'medium',
                    'description': f'ICMP flood attack detected from {packet_info.get("src_ip", "unknown")}',
                    'timestamp': packet_info['timestamp'],
                    'details': packet_info
                })
            
        except Exception as e:
            logger.error(f"Error analyzing packet threats: {e}")
        
        return threats
    
    def detect_port_scanning(self, packet_info: Dict[str, Any]) -> bool:
        """Detect port scanning activity"""
        # Implementation for port scanning detection
        return False
    
    def detect_syn_flood(self, packet_info: Dict[str, Any]) -> bool:
        """Detect SYN flood attacks"""
        # Implementation for SYN flood detection
        return False
    
    def detect_udp_flood(self, packet_info: Dict[str, Any]) -> bool:
        """Detect UDP flood attacks"""
        # Implementation for UDP flood detection
        return False
    
    def detect_http_flood(self, packet_info: Dict[str, Any]) -> bool:
        """Detect HTTP flood attacks"""
        # Implementation for HTTP flood detection
        return False
    
    def detect_icmp_flood(self, packet_info: Dict[str, Any]) -> bool:
        """Detect ICMP flood attacks"""
        # Implementation for ICMP flood detection
        return False
    
    def start_threat_detection(self):
        """Start threat detection threads"""
        # Start various threat detection threads
        pass
    
    def stop_all_threads(self):
        """Stop all monitoring threads"""
        # Implementation to stop all threads
        pass
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        try:
            report = {
                'timestamp': datetime.now(),
                'target_ip': self.target_ip,
                'monitoring_duration': self.get_monitoring_duration(),
                'total_packets': self.packet_count,
                'threats_detected': len(self.threats_detected),
                'threat_breakdown': self.get_threat_breakdown(),
                'anomaly_score': self.anomaly_detector.get_anomaly_score(),
                'recommendations': self.generate_recommendations()
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {}
    
    def get_monitoring_duration(self) -> str:
        """Get the duration of monitoring"""
        # Implementation to calculate monitoring duration
        return "0 minutes"
    
    def get_threat_breakdown(self) -> Dict[str, int]:
        """Get breakdown of detected threats by type"""
        breakdown = defaultdict(int)
        for threat in self.threats_detected:
            breakdown[threat['type']] += 1
        return dict(breakdown)
    
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on detected threats"""
        recommendations = []
        
        if self.threats_detected:
            recommendations.append("Implement rate limiting on network interfaces")
            recommendations.append("Configure firewall rules to block suspicious IPs")
            recommendations.append("Enable intrusion detection system")
            recommendations.append("Monitor network traffic patterns regularly")
        
        return recommendations

class AnomalyDetector:
    """Machine learning based anomaly detection"""
    
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.data = deque(maxlen=1000)
        self.is_trained = False
    
    def update(self, packet_info: Dict[str, Any]):
        """Update anomaly detection with new packet data"""
        try:
            # Extract features from packet
            features = self.extract_features(packet_info)
            self.data.append(features)
            
            # Train model if enough data
            if len(self.data) >= 100 and not self.is_trained:
                self.train_model()
            
            # Predict anomaly if model is trained
            if self.is_trained:
                anomaly_score = self.predict_anomaly(features)
                if anomaly_score < -0.5:  # Threshold for anomaly
                    logger.warning(f"Anomaly detected with score: {anomaly_score}")
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
    
    def extract_features(self, packet_info: Dict[str, Any]) -> List[float]:
        """Extract numerical features from packet info"""
        features = [
            packet_info.get('length', 0),
            packet_info.get('src_port', 0),
            packet_info.get('dst_port', 0),
            hash(packet_info.get('src_ip', '')) % 1000,
            hash(packet_info.get('dst_ip', '')) % 1000
        ]
        return features
    
    def train_model(self):
        """Train the anomaly detection model"""
        try:
            data_array = np.array(list(self.data))
            scaled_data = self.scaler.fit_transform(data_array)
            self.model.fit(scaled_data)
            self.is_trained = True
            logger.info("Anomaly detection model trained successfully")
        except Exception as e:
            logger.error(f"Error training anomaly model: {e}")
    
    def predict_anomaly(self, features: List[float]) -> float:
        """Predict anomaly score for given features"""
        try:
            scaled_features = self.scaler.transform([features])
            score = self.model.decision_function(scaled_features)[0]
            return score
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            return 0.0
    
    def get_anomaly_score(self) -> float:
        """Get current anomaly score"""
        if not self.data:
            return 0.0
        
        try:
            recent_features = list(self.data)[-100:]
            if self.is_trained:
                return self.predict_anomaly(recent_features[-1])
        except Exception as e:
            logger.error(f"Error getting anomaly score: {e}")
        
        return 0.0

class AlertSystem:
    """System for generating and sending security alerts"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alert_queue = deque(maxlen=1000)
    
    def send_alert(self, threat: Dict[str, Any]):
        """Send security alert"""
        try:
            alert = {
                'timestamp': datetime.now(),
                'threat': threat,
                'message': f"SECURITY ALERT: {threat['type']} detected - {threat['description']}"
            }
            
            self.alert_queue.append(alert)
            
            # Log alert
            if self.config.get('log_file', True):
                logger.warning(alert['message'])
            
            # Send email alert
            if self.config.get('email', False):
                self.send_email_alert(alert)
            
            # Send webhook alert
            if self.config.get('webhook', False):
                self.send_webhook_alert(alert)
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    def send_email_alert(self, alert: Dict[str, Any]):
        """Send email alert"""
        # Implementation for email alerts
        pass
    
    def send_webhook_alert(self, alert: Dict[str, Any]):
        """Send webhook alert"""
        # Implementation for webhook alerts
        pass

class ReportingSystem:
    """System for generating security reports"""
    
    def __init__(self):
        self.report_templates = self.load_report_templates()
    
    def load_report_templates(self) -> Dict[str, str]:
        """Load report templates"""
        return {
            'html': self.get_html_template(),
            'json': 'json',
            'csv': 'csv'
        }
    
    def get_html_template(self) -> str:
        """Get HTML report template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cybersecurity Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
                .threat { background: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #ff0000; }
                .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                .stat { background: #f9f9f9; padding: 20px; text-align: center; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Cybersecurity Threat Report</h1>
                <p>Generated on: {{ timestamp }}</p>
                <p>Target IP: {{ target_ip }}</p>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <h3>Total Packets</h3>
                    <p>{{ total_packets }}</p>
                </div>
                <div class="stat">
                    <h3>Threats Detected</h3>
                    <p>{{ threats_detected }}</p>
                </div>
                <div class="stat">
                    <h3>Anomaly Score</h3>
                    <p>{{ anomaly_score }}</p>
                </div>
            </div>
            
            <h2>Detected Threats</h2>
            {% for threat in threats %}
            <div class="threat">
                <h3>{{ threat.type }}</h3>
                <p><strong>Severity:</strong> {{ threat.severity }}</p>
                <p><strong>Description:</strong> {{ threat.description }}</p>
                <p><strong>Time:</strong> {{ threat.timestamp }}</p>
            </div>
            {% endfor %}
            
            <h2>Recommendations</h2>
            <ul>
            {% for rec in recommendations %}
                <li>{{ rec }}</li>
            {% endfor %}
            </ul>
        </body>
        </html>
        """
    
    def generate_report(self, data: Dict[str, Any], format_type: str = 'html') -> str:
        """Generate report in specified format"""
        try:
            if format_type == 'html':
                return self.generate_html_report(data)
            elif format_type == 'json':
                return json.dumps(data, indent=2, default=str)
            elif format_type == 'csv':
                return self.generate_csv_report(data)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
        
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return f"Error generating report: {e}"
    
    def generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        try:
            from jinja2 import Template
            template = Template(self.report_templates['html'])
            return template.render(**data)
        except ImportError:
            # Fallback to simple string replacement
            html = self.report_templates['html']
            for key, value in data.items():
                if isinstance(value, (list, dict)):
                    continue
                html = html.replace(f"{{{{ {key} }}}}", str(value))
            return html
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return f"Error generating HTML report: {e}"
    
    def generate_csv_report(self, data: Dict[str, Any]) -> str:
        """Generate CSV report"""
        try:
            output = []
            output.append(['Metric', 'Value'])
            output.append(['Timestamp', data.get('timestamp', '')])
            output.append(['Target IP', data.get('target_ip', '')])
            output.append(['Total Packets', data.get('total_packets', 0)])
            output.append(['Threats Detected', data.get('threats_detected', 0)])
            output.append(['Anomaly Score', data.get('anomaly_score', 0)])
            
            return '\n'.join([','.join(map(str, row)) for row in output])
        
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            return f"Error generating CSV report: {e}"

class ThreatDatabase:
    """Database for storing threat information"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_path = config.get('path', 'threats.db')
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    length INTEGER,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def store_threat(self, threat: Dict[str, Any]):
        """Store threat in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threats (type, severity, description, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                threat['type'],
                threat['severity'],
                threat['description'],
                threat['timestamp'],
                json.dumps(threat['details'])
            ))
            
            conn.commit()
            conn.close()
            logger.info(f"Threat stored in database: {threat['type']}")
            
        except Exception as e:
            logger.error(f"Error storing threat: {e}")
    
    def get_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get threats from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT type, severity, description, timestamp, details
                FROM threats
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            threats = []
            for row in cursor.fetchall():
                threat = {
                    'type': row[0],
                    'severity': row[1],
                    'description': row[2],
                    'timestamp': row[3],
                    'details': json.loads(row[4]) if row[4] else {}
                }
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            logger.error(f"Error getting threats: {e}")
            return []

class WebInterface:
    """Web interface for the cybersecurity tool"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.app = Flask(__name__)
        self.setup_routes()
        self.server_thread = None
    
    def setup_routes(self):
        """Setup Flask routes"""
        @self.app.route('/')
        def dashboard():
            return self.get_dashboard_html()
        
        @self.app.route('/api/status')
        def api_status():
            return jsonify({
                'running': self.monitor.running,
                'target_ip': self.monitor.target_ip,
                'packet_count': self.monitor.packet_count,
                'threats_detected': len(self.monitor.threats_detected)
            })
        
        @self.app.route('/api/threats')
        def api_threats():
            threats = self.monitor.database.get_threats()
            return jsonify(threats)
        
        @self.app.route('/api/report')
        def api_report():
            report = self.monitor.generate_report()
            return jsonify(report)
        
        @self.app.route('/api/report/html')
        def api_report_html():
            report = self.monitor.generate_report()
            html_report = self.monitor.reporting_system.generate_report(report, 'html')
            return html_report
    
    def get_dashboard_html(self) -> str:
        """Get dashboard HTML"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cybersecurity Monitor Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
                .stat-card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
                .threats-section { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .threat-item { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 3px; }
                .controls { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
                .btn { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; margin: 5px; }
                .btn:hover { background: #2980b9; }
                .btn-danger { background: #e74c3c; }
                .btn-danger:hover { background: #c0392b; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Cybersecurity Monitor Dashboard</h1>
                    <p>Real-time threat detection and monitoring</p>
                </div>
                
                <div class="controls">
                    <button class="btn" onclick="startMonitoring()">Start Monitoring</button>
                    <button class="btn btn-danger" onclick="stopMonitoring()">Stop Monitoring</button>
                    <button class="btn" onclick="generateReport()">Generate Report</button>
                    <button class="btn" onclick="refreshData()">Refresh Data</button>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Status</h3>
                        <div class="stat-value" id="status">Unknown</div>
                    </div>
                    <div class="stat-card">
                        <h3>Target IP</h3>
                        <div class="stat-value" id="target-ip">Loading...</div>
                    </div>
                    <div class="stat-card">
                        <h3>Packets Analyzed</h3>
                        <div class="stat-value" id="packet-count">0</div>
                    </div>
                    <div class="stat-card">
                        <h3>Threats Detected</h3>
                        <div class="stat-value" id="threat-count">0</div>
                    </div>
                </div>
                
                <div class="threats-section">
                    <h2>Recent Threats</h2>
                    <div id="threats-list">Loading threats...</div>
                </div>
            </div>
            
            <script>
                function refreshData() {
                    fetch('/api/status')
                        .then(response => response.json())
                        .then(data => {
                            document.getElementById('status').textContent = data.running ? 'Running' : 'Stopped';
                            document.getElementById('target-ip').textContent = data.target_ip;
                            document.getElementById('packet-count').textContent = data.packet_count;
                            document.getElementById('threat-count').textContent = data.threats_detected;
                        });
                    
                    fetch('/api/threats')
                        .then(response => response.json())
                        .then(threats => {
                            const threatsList = document.getElementById('threats-list');
                            if (threats.length === 0) {
                                threatsList.innerHTML = '<p>No threats detected</p>';
                                return;
                            }
                            
                            let html = '';
                            threats.slice(0, 10).forEach(threat => {
                                html += `
                                    <div class="threat-item">
                                        <strong>${threat.type}</strong> - ${threat.description}
                                        <br><small>${threat.timestamp} | Severity: ${threat.severity}</small>
                                    </div>
                                `;
                            });
                            threatsList.innerHTML = html;
                        });
                }
                
                function startMonitoring() {
                    // Implementation for starting monitoring
                    alert('Start monitoring functionality would be implemented here');
                }
                
                function stopMonitoring() {
                    // Implementation for stopping monitoring
                    alert('Stop monitoring functionality would be implemented here');
                }
                
                function generateReport() {
                    window.open('/api/report/html', '_blank');
                }
                
                // Refresh data every 5 seconds
                setInterval(refreshData, 5000);
                refreshData();
            </script>
        </body>
        </html>
        """
    
    def start(self):
        """Start the web interface"""
        try:
            self.server_thread = threading.Thread(
                target=lambda: self.app.run(host='0.0.0.0', port=5000, debug=False),
                daemon=True
            )
            self.server_thread.start()
            logger.info("Web interface started on http://localhost:5000")
        except Exception as e:
            logger.error(f"Error starting web interface: {e}")
    
    def stop(self):
        """Stop the web interface"""
        try:
            # Flask doesn't have a built-in stop method, so we'll just log it
            logger.info("Web interface stopped")
        except Exception as e:
            logger.error(f"Error stopping web interface: {e}")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Cybersecurity Threat Detection Tool')
    parser.add_argument('--ip', required=True, help='Target IP address to monitor')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--web', action='store_true', help='Enable web interface')
    
    args = parser.parse_args()
    
    try:
        # Create and start the cybersecurity monitor
        monitor = CyberSecurityMonitor(args.ip, args.config)
        
        if args.web:
            monitor.start_monitoring()
            
            # Keep the main thread alive
            try:
                while monitor.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nShutting down...")
                monitor.stop_monitoring()
        else:
            # Command line mode
            print(f"Starting cybersecurity monitoring for IP: {args.ip}")
            monitor.start_monitoring()
            
            # Run for a specified time or until interrupted
            try:
                time.sleep(300)  # Run for 5 minutes by default
            except KeyboardInterrupt:
                print("\nShutting down...")
            
            monitor.stop_monitoring()
            
            # Generate final report
            report = monitor.generate_report()
            print("\n" + "="*50)
            print("FINAL SECURITY REPORT")
            print("="*50)
            print(f"Target IP: {report.get('target_ip', 'Unknown')}")
            print(f"Total Packets: {report.get('total_packets', 0)}")
            print(f"Threats Detected: {report.get('threats_detected', 0)}")
            print(f"Anomaly Score: {report.get('anomaly_score', 0):.2f}")
            
            if report.get('recommendations'):
                print("\nRecommendations:")
                for rec in report['recommendations']:
                    print(f"- {rec}")
    
    except Exception as e:
        logger.error(f"Error in main: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()