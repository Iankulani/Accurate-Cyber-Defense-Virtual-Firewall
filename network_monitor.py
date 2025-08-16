#!/usr/bin/env python3
"""
Network Monitoring and Packet Capture Module
Handles real-time network traffic analysis and packet processing
"""

import time
import logging
import threading
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

logger = logging.getLogger(__name__)

class NetworkMonitor:
    """Advanced network monitoring and packet capture system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = None
        
        # Network interfaces
        self.interfaces = self._get_network_interfaces()
        self.monitored_interface = config.get('interface', 'eth0')
        
        # Packet analysis
        self.packet_analyzer = PacketAnalyzer(config)
        self.traffic_analyzer = TrafficAnalyzer(config)
        self.protocol_analyzer = ProtocolAnalyzer(config)
        
        # Statistics and metrics
        self.statistics = NetworkStatistics()
        self.metrics = NetworkMetrics()
        
        # Threading
        self.capture_threads = []
        self.analysis_threads = []
        
        # Packet queues
        self.packet_queue = deque(maxlen=10000)
        self.analysis_queue = deque(maxlen=10000)
        
        # Configuration
        self.promiscuous_mode = config.get('promiscuous', True)
        self.timeout = config.get('timeout', 1)
        self.max_packets = config.get('max_packets', 10000)
        
    def _get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        try:
            interfaces = netifaces.interfaces()
            logger.info(f"Available network interfaces: {interfaces}")
            return interfaces
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return ['eth0', 'lo']
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.running:
            logger.warning("Network monitoring is already running")
            return
        
        self.running = True
        self.start_time = datetime.now()
        logger.info("Starting network monitoring")
        
        try:
            # Start packet capture threads
            self._start_capture_threads()
            
            # Start analysis threads
            self._start_analysis_threads()
            
            # Start statistics collection
            self._start_statistics_collection()
            
            logger.info("Network monitoring started successfully")
            
        except Exception as e:
            logger.error(f"Error starting network monitoring: {e}")
            self.running = False
            raise
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        if not self.running:
            logger.warning("Network monitoring is not running")
            return
        
        self.running = False
        logger.info("Stopping network monitoring")
        
        try:
            # Stop all threads
            self._stop_all_threads()
            
            # Generate final statistics
            self._generate_final_statistics()
            
            logger.info("Network monitoring stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping network monitoring: {e}")
    
    def _start_capture_threads(self):
        """Start packet capture threads for each interface"""
        try:
            for interface in self.interfaces:
                if interface == 'lo':  # Skip loopback
                    continue
                
                thread = threading.Thread(
                    target=self._capture_packets,
                    args=(interface,),
                    daemon=True,
                    name=f"capture_{interface}"
                )
                thread.start()
                self.capture_threads.append(thread)
                logger.info(f"Started packet capture thread for interface: {interface}")
                
        except Exception as e:
            logger.error(f"Error starting capture threads: {e}")
    
    def _start_analysis_threads(self):
        """Start packet analysis threads"""
        try:
            # Packet analysis thread
            analysis_thread = threading.Thread(
                target=self._analyze_packets,
                daemon=True,
                name="packet_analysis"
            )
            analysis_thread.start()
            self.analysis_threads.append(analysis_thread)
            
            # Traffic analysis thread
            traffic_thread = threading.Thread(
                target=self._analyze_traffic,
                daemon=True,
                name="traffic_analysis"
            )
            traffic_thread.start()
            self.analysis_threads.append(traffic_thread)
            
            logger.info("Started analysis threads")
            
        except Exception as e:
            logger.error(f"Error starting analysis threads: {e}")
    
    def _start_statistics_collection(self):
        """Start statistics collection thread"""
        try:
            stats_thread = threading.Thread(
                target=self._collect_statistics,
                daemon=True,
                name="statistics_collection"
            )
            stats_thread.start()
            self.analysis_threads.append(stats_thread)
            
            logger.info("Started statistics collection thread")
            
        except Exception as e:
            logger.error(f"Error starting statistics collection: {e}")
    
    def _capture_packets(self, interface: str):
        """Capture packets from a specific network interface"""
        try:
            logger.info(f"Starting packet capture on interface: {interface}")
            
            # Use scapy to capture packets
            scapy.sniff(
                iface=interface,
                prn=self._process_captured_packet,
                store=0,
                stop_filter=lambda x: not self.running,
                timeout=self.timeout
            )
            
        except Exception as e:
            logger.error(f"Error in packet capture on {interface}: {e}")
    
    def _process_captured_packet(self, packet):
        """Process a captured network packet"""
        try:
            if not self.running:
                return
            
            # Extract basic packet information
            packet_info = self._extract_packet_info(packet)
            
            # Add to packet queue for analysis
            self.packet_queue.append(packet_info)
            
            # Update basic statistics
            self.packet_count += 1
            self.byte_count += packet_info.get('length', 0)
            
            # Limit packet queue size
            if len(self.packet_queue) > self.max_packets:
                self.packet_queue.popleft()
            
        except Exception as e:
            logger.error(f"Error processing captured packet: {e}")
    
    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """Extract relevant information from network packet"""
        packet_info = {
            'timestamp': datetime.now(),
            'length': len(packet),
            'protocol': 'unknown',
            'raw_packet': packet
        }
        
        try:
            # Extract Ethernet layer info
            if Ether in packet:
                packet_info.update({
                    'src_mac': packet[Ether].src,
                    'dst_mac': packet[Ether].dst,
                    'ether_type': packet[Ether].type
                })
            
            # Extract IP layer info
            if IP in packet:
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'ttl': packet[IP].ttl,
                    'tos': packet[IP].tos
                })
                
                # Extract TCP layer info
                if TCP in packet:
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': packet[TCP].flags,
                        'seq': packet[TCP].seq,
                        'ack': packet[TCP].ack,
                        'window': packet[TCP].window,
                        'checksum': packet[TCP].chksum
                    })
                    packet_info['protocol'] = 'tcp'
                
                # Extract UDP layer info
                elif UDP in packet:
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport,
                        'length': packet[UDP].len,
                        'checksum': packet[UDP].chksum
                    })
                    packet_info['protocol'] = 'udp'
                
                # Extract ICMP layer info
                elif ICMP in packet:
                    packet_info.update({
                        'icmp_type': packet[ICMP].type,
                        'icmp_code': packet[ICMP].code,
                        'checksum': packet[ICMP].chksum
                    })
                    packet_info['protocol'] = 'icmp'
                
                # Extract ARP layer info
                elif ARP in packet:
                    packet_info.update({
                        'arp_op': packet[ARP].op,
                        'arp_src_ip': packet[ARP].psrc,
                        'arp_dst_ip': packet[ARP].pdst,
                        'arp_src_mac': packet[ARP].hwsrc,
                        'arp_dst_mac': packet[ARP].hwdst
                    })
                    packet_info['protocol'] = 'arp'
            
            # Add packet hash for identification
            packet_info['hash'] = self._calculate_packet_hash(packet)
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return packet_info
    
    def _calculate_packet_hash(self, packet) -> str:
        """Calculate hash for packet identification"""
        try:
            packet_bytes = bytes(packet)
            return hashlib.md5(packet_bytes).hexdigest()
        except Exception as e:
            logger.error(f"Error calculating packet hash: {e}")
            return "unknown"
    
    def _analyze_packets(self):
        """Analyze packets from the queue"""
        try:
            while self.running:
                if self.packet_queue:
                    packet_info = self.packet_queue.popleft()
                    
                    # Perform packet analysis
                    analysis_result = self.packet_analyzer.analyze(packet_info)
                    
                    # Add to analysis queue
                    self.analysis_queue.append({
                        'packet_info': packet_info,
                        'analysis': analysis_result
                    })
                    
                    # Limit analysis queue size
                    if len(self.analysis_queue) > self.max_packets:
                        self.analysis_queue.popleft()
                
                time.sleep(0.001)  # Small delay to prevent CPU spinning
                
        except Exception as e:
            logger.error(f"Error in packet analysis: {e}")
    
    def _analyze_traffic(self):
        """Analyze traffic patterns"""
        try:
            while self.running:
                if self.analysis_queue:
                    analysis_item = self.analysis_queue.popleft()
                    
                    # Perform traffic analysis
                    traffic_result = self.traffic_analyzer.analyze(analysis_item)
                    
                    # Update metrics
                    self.metrics.update(traffic_result)
                
                time.sleep(0.1)  # Analyze traffic every 100ms
                
        except Exception as e:
            logger.error(f"Error in traffic analysis: {e}")
    
    def _collect_statistics(self):
        """Collect network statistics periodically"""
        try:
            while self.running:
                # Update statistics
                self.statistics.update(
                    packet_count=self.packet_count,
                    byte_count=self.byte_count,
                    interface_stats=self._get_interface_statistics(),
                    protocol_stats=self._get_protocol_statistics()
                )
                
                time.sleep(5)  # Update statistics every 5 seconds
                
        except Exception as e:
            logger.error(f"Error collecting statistics: {e}")
    
    def _get_interface_statistics(self) -> Dict[str, Any]:
        """Get statistics for network interfaces"""
        try:
            interface_stats = {}
            
            for interface in self.interfaces:
                try:
                    # Get interface addresses
                    addrs = netifaces.ifaddresses(interface)
                    
                    # Get interface statistics
                    stats = psutil.net_io_counters(pernic=True).get(interface, None)
                    
                    interface_stats[interface] = {
                        'addresses': addrs,
                        'statistics': {
                            'bytes_sent': stats.bytes_sent if stats else 0,
                            'bytes_recv': stats.bytes_recv if stats else 0,
                            'packets_sent': stats.packets_sent if stats else 0,
                            'packets_recv': stats.packets_recv if stats else 0
                        } if stats else {}
                    }
                    
                except Exception as e:
                    logger.error(f"Error getting statistics for interface {interface}: {e}")
                    interface_stats[interface] = {'error': str(e)}
            
            return interface_stats
            
        except Exception as e:
            logger.error(f"Error getting interface statistics: {e}")
            return {}
    
    def _get_protocol_statistics(self) -> Dict[str, Any]:
        """Get protocol statistics"""
        try:
            return self.protocol_analyzer.get_statistics()
        except Exception as e:
            logger.error(f"Error getting protocol statistics: {e}")
            return {}
    
    def _stop_all_threads(self):
        """Stop all monitoring threads"""
        try:
            # Wait for threads to finish
            for thread in self.capture_threads + self.analysis_threads:
                if thread.is_alive():
                    thread.join(timeout=5)
            
            logger.info("All threads stopped")
            
        except Exception as e:
            logger.error(f"Error stopping threads: {e}")
    
    def _generate_final_statistics(self):
        """Generate final statistics when monitoring stops"""
        try:
            if self.start_time:
                duration = datetime.now() - self.start_time
                
                final_stats = {
                    'monitoring_duration': str(duration),
                    'total_packets': self.packet_count,
                    'total_bytes': self.byte_count,
                    'packet_rate': self.packet_count / duration.total_seconds() if duration.total_seconds() > 0 else 0,
                    'byte_rate': self.byte_count / duration.total_seconds() if duration.total_seconds() > 0 else 0
                }
                
                logger.info(f"Final statistics: {final_stats}")
                
        except Exception as e:
            logger.error(f"Error generating final statistics: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current network statistics"""
        try:
            return {
                'running': self.running,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'packet_count': self.packet_count,
                'byte_count': self.byte_count,
                'queue_sizes': {
                    'packet_queue': len(self.packet_queue),
                    'analysis_queue': len(self.analysis_queue)
                },
                'statistics': self.statistics.get_summary(),
                'metrics': self.metrics.get_summary()
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

class PacketAnalyzer:
    """Analyzes individual network packets"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.analysis_rules = self._load_analysis_rules()
    
    def _load_analysis_rules(self) -> Dict[str, Any]:
        """Load packet analysis rules"""
        return {
            'suspicious_ports': [22, 23, 3389, 5900, 1433, 3306, 5432],
            'suspicious_protocols': ['icmp', 'arp'],
            'large_packet_threshold': 1500,
            'fragmented_packet_threshold': 100
        }
    
    def analyze(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single packet"""
        try:
            analysis_result = {
                'timestamp': packet_info['timestamp'],
                'packet_hash': packet_info['hash'],
                'analysis': {},
                'flags': [],
                'risk_score': 0
            }
            
            # Basic packet analysis
            self._analyze_packet_size(packet_info, analysis_result)
            self._analyze_packet_protocol(packet_info, analysis_result)
            self._analyze_packet_ports(packet_info, analysis_result)
            self._analyze_packet_flags(packet_info, analysis_result)
            self._analyze_packet_content(packet_info, analysis_result)
            
            # Calculate risk score
            analysis_result['risk_score'] = self._calculate_risk_score(analysis_result)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
            return {'error': str(e)}
    
    def _analyze_packet_size(self, packet_info: Dict[str, Any], result: Dict[str, Any]):
        """Analyze packet size characteristics"""
        try:
            length = packet_info.get('length', 0)
            
            if length > self.analysis_rules['large_packet_threshold']:
                result['flags'].append('large_packet')
                result['analysis']['size_analysis'] = {
                    'length': length,
                    'is_large': True,
                    'threshold': self.analysis_rules['large_packet_threshold']
                }
            else:
                result['analysis']['size_analysis'] = {
                    'length': length,
                    'is_large': False
                }
                
        except Exception as e:
            logger.error(f"Error analyzing packet size: {e}")
    
    def _analyze_packet_protocol(self, packet_info: Dict[str, Any], result: Dict[str, Any]):
        """Analyze packet protocol characteristics"""
        try:
            protocol = packet_info.get('protocol', 'unknown')
            
            result['analysis']['protocol_analysis'] = {
                'protocol': protocol,
                'is_suspicious': protocol in self.analysis_rules['suspicious_protocols']
            }
            
            if protocol in self.analysis_rules['suspicious_protocols']:
                result['flags'].append('suspicious_protocol')
                
        except Exception as e:
            logger.error(f"Error analyzing packet protocol: {e}")
    
    def _analyze_packet_ports(self, packet_info: Dict[str, Any], result: Dict[str, Any]):
        """Analyze packet port characteristics"""
        try:
            src_port = packet_info.get('src_port')
            dst_port = packet_info.get('dst_port')
            
            if src_port or dst_port:
                result['analysis']['port_analysis'] = {
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'suspicious_ports': []
                }
                
                # Check for suspicious ports
                for port in [src_port, dst_port]:
                    if port in self.analysis_rules['suspicious_ports']:
                        result['analysis']['port_analysis']['suspicious_ports'].append(port)
                        result['flags'].append('suspicious_port')
                        
        except Exception as e:
            logger.error(f"Error analyzing packet ports: {e}")
    
    def _analyze_packet_flags(self, packet_info: Dict[str, Any], result: Dict[str, Any]):
        """Analyze packet flags (TCP flags, etc.)"""
        try:
            flags = packet_info.get('flags')
            
            if flags:
                result['analysis']['flag_analysis'] = {
                    'flags': flags,
                    'flag_combinations': self._analyze_flag_combinations(flags)
                }
                
        except Exception as e:
            logger.error(f"Error analyzing packet flags: {e}")
    
    def _analyze_packet_content(self, packet_info: Dict[str, Any], result: Dict[str, Any]):
        """Analyze packet content for suspicious patterns"""
        try:
            # Check for potential data exfiltration
            length = packet_info.get('length', 0)
            protocol = packet_info.get('protocol', 'unknown')
            
            if protocol == 'tcp' and length > 1000:
                result['flags'].append('potential_data_exfiltration')
                result['analysis']['content_analysis'] = {
                    'large_tcp_packet': True,
                    'length': length
                }
                
        except Exception as e:
            logger.error(f"Error analyzing packet content: {e}")
    
    def _analyze_flag_combinations(self, flags: int) -> List[str]:
        """Analyze TCP flag combinations"""
        try:
            flag_combinations = []
            
            if flags & 0x01:  # FIN
                flag_combinations.append('FIN')
            if flags & 0x02:  # SYN
                flag_combinations.append('SYN')
            if flags & 0x04:  # RST
                flag_combinations.append('RST')
            if flags & 0x08:  # PSH
                flag_combinations.append('PSH')
            if flags & 0x10:  # ACK
                flag_combinations.append('ACK')
            if flags & 0x20:  # URG
                flag_combinations.append('URG')
            
            return flag_combinations
            
        except Exception as e:
            logger.error(f"Error analyzing flag combinations: {e}")
            return []
    
    def _calculate_risk_score(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate risk score for packet analysis"""
        try:
            risk_score = 0.0
            
            # Add risk for each flag
            for flag in analysis_result.get('flags', []):
                if flag == 'large_packet':
                    risk_score += 0.1
                elif flag == 'suspicious_protocol':
                    risk_score += 0.3
                elif flag == 'suspicious_port':
                    risk_score += 0.2
                elif flag == 'potential_data_exfiltration':
                    risk_score += 0.4
            
            # Normalize risk score to 0-1 range
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 0.0

class TrafficAnalyzer:
    """Analyzes traffic patterns and trends"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.traffic_history = deque(maxlen=10000)
        self.protocol_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.ip_counts = defaultdict(int)
        
    def analyze(self, analysis_item: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze traffic patterns"""
        try:
            packet_info = analysis_item['packet_info']
            analysis = analysis_item['analysis']
            
            # Update traffic history
            self.traffic_history.append({
                'timestamp': packet_info['timestamp'],
                'protocol': packet_info.get('protocol', 'unknown'),
                'src_ip': packet_info.get('src_ip'),
                'dst_ip': packet_info.get('dst_ip'),
                'src_port': packet_info.get('src_port'),
                'dst_port': packet_info.get('dst_port'),
                'length': packet_info.get('length', 0),
                'risk_score': analysis.get('risk_score', 0)
            })
            
            # Update counters
            self.protocol_counts[packet_info.get('protocol', 'unknown')] += 1
            if packet_info.get('src_port'):
                self.port_counts[packet_info.get('src_port')] += 1
            if packet_info.get('src_ip'):
                self.ip_counts[packet_info.get('src_ip')] += 1
            
            # Analyze traffic patterns
            traffic_analysis = {
                'timestamp': packet_info['timestamp'],
                'protocol_distribution': dict(self.protocol_counts),
                'top_ports': self._get_top_ports(),
                'top_ips': self._get_top_ips(),
                'traffic_trends': self._analyze_traffic_trends(),
                'anomaly_detection': self._detect_traffic_anomalies()
            }
            
            return traffic_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing traffic: {e}")
            return {'error': str(e)}
    
    def _get_top_ports(self, limit: int = 10) -> List[Tuple[int, int]]:
        """Get top ports by connection count"""
        try:
            sorted_ports = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ports[:limit]
        except Exception as e:
            logger.error(f"Error getting top ports: {e}")
            return []
    
    def _get_top_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top IPs by connection count"""
        try:
            sorted_ips = sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:limit]
        except Exception as e:
            logger.error(f"Error getting top IPs: {e}")
            return []
    
    def _analyze_traffic_trends(self) -> Dict[str, Any]:
        """Analyze traffic trends over time"""
        try:
            if len(self.traffic_history) < 10:
                return {'status': 'insufficient_data'}
            
            # Calculate traffic rates
            recent_traffic = list(self.traffic_history)[-100:]
            
            if len(recent_traffic) < 2:
                return {'status': 'insufficient_data'}
            
            # Calculate packet rate
            time_span = (recent_traffic[-1]['timestamp'] - recent_traffic[0]['timestamp']).total_seconds()
            if time_span == 0:
                return {'status': 'zero_time_span'}
            
            packet_rate = len(recent_traffic) / time_span
            byte_rate = sum(t['length'] for t in recent_traffic) / time_span
            
            return {
                'status': 'analysis_complete',
                'packet_rate': packet_rate,
                'byte_rate': byte_rate,
                'time_span': time_span,
                'sample_size': len(recent_traffic)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing traffic trends: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _detect_traffic_anomalies(self) -> Dict[str, Any]:
        """Detect traffic anomalies"""
        try:
            if len(self.traffic_history) < 50:
                return {'status': 'insufficient_data'}
            
            # Get recent traffic for anomaly detection
            recent_traffic = list(self.traffic_history)[-100:]
            
            # Calculate baseline metrics
            lengths = [t['length'] for t in recent_traffic]
            risk_scores = [t['risk_score'] for t in recent_traffic]
            
            if not lengths or not risk_scores:
                return {'status': 'no_data'}
            
            # Calculate statistics
            avg_length = np.mean(lengths)
            std_length = np.std(lengths)
            avg_risk = np.mean(risk_scores)
            
            # Detect anomalies
            anomalies = []
            
            # Large packet anomaly
            if std_length > 0:
                for traffic in recent_traffic:
                    if abs(traffic['length'] - avg_length) > 2 * std_length:
                        anomalies.append({
                            'type': 'large_packet',
                            'timestamp': traffic['timestamp'],
                            'length': traffic['length'],
                            'threshold': avg_length + 2 * std_length
                        })
            
            # High risk anomaly
            for traffic in recent_traffic:
                if traffic['risk_score'] > avg_risk + 0.3:
                    anomalies.append({
                        'type': 'high_risk',
                        'timestamp': traffic['timestamp'],
                        'risk_score': traffic['risk_score'],
                        'threshold': avg_risk + 0.3
                    })
            
            return {
                'status': 'analysis_complete',
                'baseline': {
                    'avg_length': avg_length,
                    'std_length': std_length,
                    'avg_risk': avg_risk
                },
                'anomalies': anomalies,
                'anomaly_count': len(anomalies)
            }
            
        except Exception as e:
            logger.error(f"Error detecting traffic anomalies: {e}")
            return {'status': 'error', 'error': str(e)}

class ProtocolAnalyzer:
    """Analyzes protocol-specific characteristics"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.protocol_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'connection_count': 0,
            'error_count': 0
        })
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get protocol statistics"""
        try:
            return dict(self.protocol_stats)
        except Exception as e:
            logger.error(f"Error getting protocol statistics: {e}")
            return {}

class NetworkStatistics:
    """Manages network statistics collection"""
    
    def __init__(self):
        self.stats = {
            'packet_count': 0,
            'byte_count': 0,
            'interface_stats': {},
            'protocol_stats': {},
            'last_update': None
        }
    
    def update(self, **kwargs):
        """Update statistics"""
        try:
            self.stats.update(kwargs)
            self.stats['last_update'] = datetime.now()
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get statistics summary"""
        try:
            return self.stats.copy()
        except Exception as e:
            logger.error(f"Error getting statistics summary: {e}")
            return {}

class NetworkMetrics:
    """Manages network metrics and performance data"""
    
    def __init__(self):
        self.metrics = {
            'traffic_rates': [],
            'anomaly_scores': [],
            'risk_assessments': [],
            'last_update': None
        }
    
    def update(self, traffic_result: Dict[str, Any]):
        """Update metrics with traffic analysis results"""
        try:
            if 'traffic_trends' in traffic_result:
                trends = traffic_result['traffic_trends']
                if trends.get('status') == 'analysis_complete':
                    self.metrics['traffic_rates'].append({
                        'timestamp': traffic_result['timestamp'],
                        'packet_rate': trends.get('packet_rate', 0),
                        'byte_rate': trends.get('byte_rate', 0)
                    })
            
            if 'anomaly_detection' in traffic_result:
                anomalies = traffic_result['anomaly_detection']
                if anomalies.get('status') == 'analysis_complete':
                    self.metrics['anomaly_scores'].append({
                        'timestamp': traffic_result['timestamp'],
                        'anomaly_count': anomalies.get('anomaly_count', 0)
                    })
            
            # Keep only recent metrics
            max_metrics = 1000
            for key in ['traffic_rates', 'anomaly_scores', 'risk_assessments']:
                if len(self.metrics[key]) > max_metrics:
                    self.metrics[key] = self.metrics[key][-max_metrics:]
            
            self.metrics['last_update'] = datetime.now()
            
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        try:
            summary = self.metrics.copy()
            
            # Calculate averages
            if self.metrics['traffic_rates']:
                avg_packet_rate = np.mean([r['packet_rate'] for r in self.metrics['traffic_rates']])
                avg_byte_rate = np.mean([r['byte_rate'] for r in self.metrics['traffic_rates']])
                summary['averages'] = {
                    'packet_rate': avg_packet_rate,
                    'byte_rate': avg_byte_rate
                }
            
            if self.metrics['anomaly_scores']:
                avg_anomaly_count = np.mean([a['anomaly_count'] for a in self.metrics['anomaly_scores']])
                summary['averages']['anomaly_count'] = avg_anomaly_count
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting metrics summary: {e}")
            return {}

# Export main classes
__all__ = [
    'NetworkMonitor',
    'PacketAnalyzer',
    'TrafficAnalyzer',
    'ProtocolAnalyzer',
    'NetworkStatistics',
    'NetworkMetrics'
]