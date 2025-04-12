"""
DDoS Detector Module for the ASC System

This module specializes in detecting Distributed Denial of Service (DDoS) attacks
by analyzing traffic patterns, connection rates, and packet characteristics.
"""

import time
import queue
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
import ipaddress

from .base_detector import BaseDetector
from ..utils.logger import get_logger


class DDoSDetector(BaseDetector):
    """
    Detector for identifying Distributed Denial of Service (DDoS) attacks.
    
    This detector specializes in:
    - Volume-based attack detection (e.g., UDP floods, ICMP floods)
    - Protocol-based attack detection (e.g., SYN floods, fragmentation attacks)
    - Application layer attack detection (e.g., HTTP floods, slowloris)
    - Amplification attack detection (e.g., DNS, NTP amplification)
    """
    
    def __init__(self, event_queue: queue.Queue, config: Dict[str, Any] = None):
        """
        Initialize the DDoS detector.
        
        Args:
            event_queue: Queue for detected security events
            config: Configuration parameters
        """
        super().__init__(event_queue, config)
        
        # Configuration parameters
        self.analysis_interval = self.config.get('analysis_interval', 5)  # seconds
        self.baseline_window = self.config.get('baseline_window', 3600)  # 1 hour
        self.alert_threshold = self.config.get('alert_threshold', 3.0)  # 3x baseline
        self.syn_flood_threshold = self.config.get('syn_flood_threshold', 0.8)  # 80% syn/synack ratio
        self.packet_threshold = self.config.get('packet_threshold', 1000)  # Min packets for detection
        self.ip_diversity_threshold = self.config.get('ip_diversity_threshold', 0.7)  # Source IP diversity
        
        # Traffic statistics
        self.traffic_stats = {
            'last_update': time.time(),
            'packets_per_second': 0,
            'bytes_per_second': 0,
            'connections_per_second': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int),
            'ip_sources': defaultdict(int),
            'ip_destinations': defaultdict(int),
            'packet_sizes': [],
            'syn_count': 0,
            'syn_ack_count': 0,
            'tcp_flags': defaultdict(int),
            'ttl_values': defaultdict(int),
            'fragments': 0
        }
        
        # Historical traffic data for baselines
        self.traffic_history = deque(maxlen=int(self.baseline_window / self.analysis_interval))
        
        # Current baselines
        self.baselines = {
            'packets_per_second': 100,  # Initial conservative values
            'bytes_per_second': 100000,
            'connections_per_second': 50,
            'last_update': 0
        }
        
        # Known attack signatures
        self.attack_signatures = {
            'syn_flood': {
                'description': 'TCP SYN flood attack',
                'tcp_flags': {'syn': 0.8, 'syn_ack': 0.2},  # 80% SYN, 20% SYN-ACK
                'min_packets': 500,
                'min_sources': 10
            },
            'udp_flood': {
                'description': 'UDP flood attack',
                'protocol': 'UDP',
                'min_packets': 1000,
                'ratio_threshold': 0.7  # 70% of traffic is UDP
            },
            'icmp_flood': {
                'description': 'ICMP flood attack',
                'protocol': 'ICMP',
                'min_packets': 500,
                'ratio_threshold': 0.5  # 50% of traffic is ICMP
            },
            'http_flood': {
                'description': 'HTTP flood attack',
                'protocol': 'TCP',
                'ports': [80, 443],
                'min_packets': 300,
                'ratio_threshold': 0.6  # 60% of traffic to HTTP ports
            },
            'dns_amplification': {
                'description': 'DNS amplification attack',
                'protocol': 'UDP',
                'ports': [53],
                'min_packets': 200,
                'avg_packet_size': 512  # Large DNS response packets
            },
            'ntp_amplification': {
                'description': 'NTP amplification attack',
                'protocol': 'UDP',
                'ports': [123],
                'min_packets': 100,
                'avg_packet_size': 400  # Large NTP response packets
            },
            'fragmentation': {
                'description': 'IP fragmentation attack',
                'min_fragments': 100,
                'ratio_threshold': 0.3  # 30% of packets are fragments
            }
        }
        
        # Network detector reference
        self.network_detector = None
        
        # Last analysis time
        self.last_analysis = time.time()
        
        self.logger.info("DDoS Detector initialized")
    
    def on_start(self):
        """Initialize when starting the detector."""
        # Find the network traffic detector to access raw packet data
        self._find_network_detector()
    
    def _find_network_detector(self):
        """Find the network traffic detector to access packet data."""
        try:
            # This is a simplified approach - in production we'd use proper dependency injection
            import sys
            if 'engine' in sys.modules['__main__'].__dict__:
                engine = sys.modules['__main__'].__dict__['engine']
                if hasattr(engine, 'detectors') and 'network' in engine.detectors:
                    self.network_detector = engine.detectors['network']
                    self.logger.info("Found network traffic detector")
        except Exception as e:
            self.logger.error(f"Error finding network detector: {e}")
    
    def detect(self) -> Optional[List[Dict[str, Any]]]:
        """
        Detect DDoS attack patterns in network traffic.
        
        Returns:
            A list of detected DDoS attack events or None
        """
        current_time = time.time()
        
        # Check if it's time for analysis
        if current_time - self.last_analysis < self.analysis_interval:
            return None
        
        self.last_analysis = current_time
        
        # Update traffic statistics
        self._update_traffic_stats()
        
        # Check for attack patterns
        attack_events = self._check_attack_patterns()
        
        # Update baseline periodically
        if current_time - self.baselines['last_update'] > (self.baseline_window / 4):
            self._update_baselines()
        
        return attack_events if attack_events else None
    
    def _update_traffic_stats(self):
        """Update traffic statistics from network detector data."""
        if not self.network_detector:
            return
            
        try:
            # Get statistics from network detector
            network_stats = self.network_detector.get_stats()
            
            # Calculate rates
            now = time.time()
            elapsed = now - self.traffic_stats['last_update']
            
            if elapsed > 0:
                # Update packet rate
                self.traffic_stats['packets_per_second'] = network_stats.get('packet_rate', 0)
                
                # Get protocol distribution
                protocols = network_stats.get('protocols', {})
                for proto, count in protocols.items():
                    self.traffic_stats['protocols'][proto] += count
                
                # Reset timing
                self.traffic_stats['last_update'] = now
                
                # Get packet buffer for detailed analysis
                self._analyze_packet_buffer()
                
                # Add current stats to history
                self.traffic_history.append({
                    'timestamp': now,
                    'packets_per_second': self.traffic_stats['packets_per_second'],
                    'bytes_per_second': self.traffic_stats['bytes_per_second'],
                    'connections_per_second': self.traffic_stats['connections_per_second'],
                    'protocols': dict(self.traffic_stats['protocols']),
                    'syn_ratio': (self.traffic_stats['syn_count'] / max(1, self.traffic_stats['syn_count'] + 
                                                                    self.traffic_stats['syn_ack_count'])),
                    'ip_source_count': len(self.traffic_stats['ip_sources']),
                    'fragments': self.traffic_stats['fragments']
                })
                
                # Reset counters for next interval
                self._reset_interval_counters()
                
        except Exception as e:
            self.logger.error(f"Error updating traffic statistics: {e}")
    
    def _analyze_packet_buffer(self):
        """Analyze packet buffer for DDoS signatures."""
        if not self.network_detector:
            return
            
        try:
            packet_buffer = self.network_detector.get_packet_buffer()
            
            if not packet_buffer:
                return
                
            # Check which packet capture method is being used
            if hasattr(self.network_detector, 'capture_method'):
                if self.network_detector.capture_method == 'pyshark':
                    self._analyze_pyshark_packets(packet_buffer)
                elif self.network_detector.capture_method == 'scapy':
                    self._analyze_scapy_packets(packet_buffer)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing packet buffer: {e}")
    
    def _analyze_pyshark_packets(self, packets):
        """
        Analyze pyshark packets for DDoS indicators.
        
        Args:
            packets: List of pyshark packets
        """
        bytes_total = 0
        connections = set()
        
        for packet in packets:
            # Extract packet size
            if hasattr(packet, 'length'):
                packet_size = int(packet.length)
                bytes_total += packet_size
                self.traffic_stats['packet_sizes'].append(packet_size)
            
            # Extract IP information
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                self.traffic_stats['ip_sources'][src_ip] += 1
                self.traffic_stats['ip_destinations'][dst_ip] += 1
                
                # Check for IP fragments
                if hasattr(packet.ip, 'flags'):
                    if hasattr(packet.ip.flags, 'mf') and int(packet.ip.flags.mf) == 1:
                        self.traffic_stats['fragments'] += 1
                
                # Record TTL
                if hasattr(packet.ip, 'ttl'):
                    self.traffic_stats['ttl_values'][int(packet.ip.ttl)] += 1
                
                # Extract protocol specific information
                if hasattr(packet, 'tcp'):
                    # TCP protocol
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    
                    # Record port information
                    self.traffic_stats['ports'][int(dst_port)] += 1
                    
                    # Record connection
                    conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    connections.add(conn_key)
                    
                    # Analyze TCP flags
                    if hasattr(packet.tcp, 'flags'):
                        flags = packet.tcp.flags
                        
                        if hasattr(flags, 'syn') and int(flags.syn) == 1:
                            if hasattr(flags, 'ack') and int(flags.ack) == 1:
                                self.traffic_stats['tcp_flags']['syn_ack'] += 1
                                self.traffic_stats['syn_ack_count'] += 1
                            else:
                                self.traffic_stats['tcp_flags']['syn'] += 1
                                self.traffic_stats['syn_count'] += 1
                                
                        if hasattr(flags, 'reset') and int(flags.reset) == 1:
                            self.traffic_stats['tcp_flags']['rst'] += 1
                            
                        if hasattr(flags, 'fin') and int(flags.fin) == 1:
                            self.traffic_stats['tcp_flags']['fin'] += 1
                    
                elif hasattr(packet, 'udp'):
                    # UDP protocol
                    dst_port = packet.udp.dstport
                    self.traffic_stats['ports'][int(dst_port)] += 1
                    
                elif hasattr(packet, 'icmp'):
                    # ICMP protocol - no port information
                    pass
        
        # Update bytes per second
        elapsed = time.time() - self.traffic_stats['last_update']
        if elapsed > 0:
            self.traffic_stats['bytes_per_second'] = bytes_total / elapsed
            self.traffic_stats['connections_per_second'] = len(connections) / elapsed
    
    def _analyze_scapy_packets(self, packets):
        """
        Analyze scapy packets for DDoS indicators.
        
        Args:
            packets: List of scapy packets
        """
        from scapy.all import IP, TCP, UDP, ICMP
        
        bytes_total = 0
        connections = set()
        
        for packet in packets:
            # Extract packet size
            if hasattr(packet, 'len'):
                packet_size = packet.len
                bytes_total += packet_size
                self.traffic_stats['packet_sizes'].append(packet_size)
            
            # Extract IP information
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                self.traffic_stats['ip_sources'][src_ip] += 1
                self.traffic_stats['ip_destinations'][dst_ip] += 1
                
                # Check for IP fragments
                if ip_layer.flags & 0x1:  # MF flag
                    self.traffic_stats['fragments'] += 1
                
                # Record TTL
                self.traffic_stats['ttl_values'][ip_layer.ttl] += 1
                
                # Extract protocol specific information
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    
                    # Record port information
                    self.traffic_stats['ports'][dst_port] += 1
                    
                    # Record connection
                    conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    connections.add(conn_key)
                    
                    # Analyze TCP flags
                    flags = tcp_layer.flags
                    
                    if flags & 0x02:  # SYN flag
                        if flags & 0x10:  # ACK flag
                            self.traffic_stats['tcp_flags']['syn_ack'] += 1
                            self.traffic_stats['syn_ack_count'] += 1
                        else:
                            self.traffic_stats['tcp_flags']['syn'] += 1
                            self.traffic_stats['syn_count'] += 1
                            
                    if flags & 0x04:  # RST flag
                        self.traffic_stats['tcp_flags']['rst'] += 1
                        
                    if flags & 0x01:  # FIN flag
                        self.traffic_stats['tcp_flags']['fin'] += 1
                
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    dst_port = udp_layer.dport
                    self.traffic_stats['ports'][dst_port] += 1
                    
                elif ICMP in packet:
                    # ICMP protocol - no port information
                    pass
        
        # Update bytes per second
        elapsed = time.time() - self.traffic_stats['last_update']
        if elapsed > 0:
            self.traffic_stats['bytes_per_second'] = bytes_total / elapsed
            self.traffic_stats['connections_per_second'] = len(connections) / elapsed
    
    def _reset_interval_counters(self):
        """Reset counters that should be measured per interval."""
        # Keep IP and protocol counters for baseline, but reset others
        self.traffic_stats['tcp_flags'] = defaultdict(int)
        self.traffic_stats['packet_sizes'] = []
        self.traffic_stats['fragments'] = 0
        self.traffic_stats['syn_count'] = 0
        self.traffic_stats['syn_ack_count'] = 0
    
    def _update_baselines(self):
        """Update baseline traffic patterns from historical data."""
        if len(self.traffic_history) < 5:  # Need at least some history
            return
            
        # Calculate average values over history, excluding the most recent entries
        # (which might already contain attack traffic)
        exclude_count = min(3, len(self.traffic_history) // 4)
        history_to_analyze = list(self.traffic_history)[:-exclude_count] if exclude_count > 0 else list(self.traffic_history)
        
        if not history_to_analyze:
            return
            
        packets_rates = [entry['packets_per_second'] for entry in history_to_analyze]
        bytes_rates = [entry['bytes_per_second'] for entry in history_to_analyze]
        conn_rates = [entry['connections_per_second'] for entry in history_to_analyze]
        
        # Update baselines
        self.baselines = {
            'packets_per_second': sum(packets_rates) / len(packets_rates),
            'bytes_per_second': sum(bytes_rates) / len(bytes_rates),
            'connections_per_second': sum(conn_rates) / len(conn_rates),
            'last_update': time.time()
        }
        
        self.logger.debug(f"Updated DDoS baselines: {self.baselines}")
    
    def _check_attack_patterns(self) -> List[Dict[str, Any]]:
        """
        Check current traffic patterns against known DDoS attack signatures.
        
        Returns:
            List of detected attack events
        """
        events = []
        
        # Skip if we don't have enough data
        if len(self.traffic_history) == 0:
            return events
            
        # Get current traffic stats
        current = self.traffic_history[-1]
        
        # Volume-based detection
        volume_event = self._check_volume_attack(current)
        if volume_event:
            events.append(volume_event)
        
        # SYN flood detection
        syn_flood_event = self._check_syn_flood(current)
        if syn_flood_event:
            events.append(syn_flood_event)
        
        # Protocol-based detection
        protocol_event = self._check_protocol_attack(current)
        if protocol_event:
            events.append(protocol_event)
        
        # Application-layer detection
        app_event = self._check_application_attack(current)
        if app_event:
            events.append(app_event)
        
        # Amplification attack detection
        amp_event = self._check_amplification_attack(current)
        if amp_event:
            events.append(amp_event)
        
        # Fragmentation attack detection
        frag_event = self._check_fragmentation_attack(current)
        if frag_event:
            events.append(frag_event)
        
        return events
    
    def _check_volume_attack(self, current: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for volume-based DDoS attacks.
        
        Args:
            current: Current traffic statistics
            
        Returns:
            Attack event if detected, None otherwise
        """
        # Calculate ratios against baselines
        packet_ratio = current['packets_per_second'] / max(self.baselines['packets_per_second'], 1)
        byte_ratio = current['bytes_per_second'] / max(self.baselines['bytes_per_second'], 1)
        conn_ratio = current['connections_per_second'] / max(self.baselines['connections_per_second'], 1)
        
        # Check if any ratio exceeds threshold
        if (packet_ratio > self.alert_threshold or 
            byte_ratio > self.alert_threshold or 
            conn_ratio > self.alert_threshold):
            
            # Minimum packet threshold to reduce false positives
            if current['packets_per_second'] < self.packet_threshold:
                return None
            
            # Calculate severity based on the highest ratio
            max_ratio = max(packet_ratio, byte_ratio, conn_ratio)
            severity = 2
            if max_ratio > self.alert_threshold * 3:
                severity = 5
            elif max_ratio > self.alert_threshold * 2:
                severity = 4
            elif max_ratio > self.alert_threshold:
                severity = 3
            
            # Create event
            return {
                'name': 'Volume-Based DDoS Attack',
                'type': 'ddos.volume',
                'severity': severity,
                'score': min(100, int(50 + 50 * (max_ratio / self.alert_threshold))),
                'details': {
                    'packet_ratio': packet_ratio,
                    'byte_ratio': byte_ratio,
                    'connection_ratio': conn_ratio,
                    'packets_per_second': current['packets_per_second'],
                    'bytes_per_second': current['bytes_per_second'],
                    'threshold': self.alert_threshold,
                    'baseline': {
                        'packets_per_second': self.baselines['packets_per_second'],
                        'bytes_per_second': self.baselines['bytes_per_second']
                    },
                    'source_ips': len(self.traffic_stats['ip_sources'])
                }
            }
        
        return None
    
    def _check_syn_flood(self, current: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for SYN flood attacks.
        
        Args:
            current: Current traffic statistics
            
        Returns:
            Attack event if detected, None otherwise
        """
        # Check SYN to SYN-ACK ratio
        syn_ratio = current.get('syn_ratio', 0)
        
        if syn_ratio > self.syn_flood_threshold:
            # Validate there are enough packets to be a real attack
            if self.traffic_stats['syn_count'] < self.attack_signatures['syn_flood']['min_packets']:
                return None
                
            # Check for diverse source IPs
            unique_sources = len(self.traffic_stats['ip_sources'])
            if unique_sources < self.attack_signatures['syn_flood']['min_sources']:
                return None
            
            # Calculate severity based on ratio and volume
            severity = 3
            if syn_ratio > 0.95 and self.traffic_stats['syn_count'] > 1000:
                severity = 5
            elif syn_ratio > 0.9:
                severity = 4
                
            return {
                'name': 'TCP SYN Flood Attack',
                'type': 'ddos.synflood',
                'severity': severity,
                'score': min(100, int(70 + 30 * ((syn_ratio - self.syn_flood_threshold) / 
                                               (1 - self.syn_flood_threshold)))),
                'details': {
                    'syn_ratio': syn_ratio,
                    'syn_count': self.traffic_stats['syn_count'],
                    'syn_ack_count': self.traffic_stats['syn_ack_count'],
                    'threshold': self.syn_flood_threshold,
                    'source_ips': unique_sources
                }
            }
            
        return None
    
    def _check_protocol_attack(self, current: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for protocol-based DDoS attacks (e.g., UDP flood, ICMP flood).
        
        Args:
            current: Current traffic statistics
            
        Returns:
            Attack event if detected, None otherwise
        """
        protocols = current.get('protocols', {})
        total_packets = sum(protocols.values()) if protocols else 1
        
        # Check UDP flood
        udp_packets = protocols.get('UDP', 0)
        udp_ratio = udp_packets / total_packets if total_packets > 0 else 0
        
        if (udp_ratio > self.attack_signatures['udp_flood']['ratio_threshold'] and 
            udp_packets > self.attack_signatures['udp_flood']['min_packets']):
            
            return {
                'name': 'UDP Flood Attack',
                'type': 'ddos.udpflood',
                'severity': 4,
                'score': min(100, int(70 + 30 * udp_ratio)),
                'details': {
                    'udp_ratio': udp_ratio,
                    'udp_packets': udp_packets,
                    'total_packets': total_packets,
                    'threshold': self.attack_signatures['udp_flood']['ratio_threshold'],
                    'source_ips': len(self.traffic_stats['ip_sources'])
                }
            }
        
        # Check ICMP flood
        icmp_packets = protocols.get('ICMP', 0)
        icmp_ratio = icmp_packets / total_packets if total_packets > 0 else 0
        
        if (icmp_ratio > self.attack_signatures['icmp_flood']['ratio_threshold'] and 
            icmp_packets > self.attack_signatures['icmp_flood']['min_packets']):
            
            return {
                'name': 'ICMP Flood Attack',
                'type': 'ddos.icmpflood',
                'severity': 3,
                'score': min(100, int(60 + 40 * icmp_ratio)),
                'details': {
                    'icmp_ratio': icmp_ratio,
                    'icmp_packets': icmp_packets,
                    'total_packets': total_packets,
                    'threshold': self.attack_signatures['icmp_flood']['ratio_threshold'],
                    'source_ips': len(self.traffic_stats['ip_sources'])
                }
            }
            
        return None
    
    def _check_application_attack(self, current: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for application layer DDoS attacks (e.g., HTTP flood).
        
        Args:
            current: Current traffic statistics
            
        Returns:
            Attack event if detected, None otherwise
        """
        # Count packets to HTTP/HTTPS ports
        http_ports = self.attack_signatures['http_flood']['ports']
        http_packets = sum(self.traffic_stats['ports'].get(port, 0) for port in http_ports)
        total_packets = sum(self.traffic_stats['ports'].values()) if self.traffic_stats['ports'] else 1
        
        http_ratio = http_packets / total_packets if total_packets > 0 else 0
        
        if (http_ratio > self.attack_signatures['http_flood']['ratio_threshold'] and 
            http_packets > self.attack_signatures['http_flood']['min_packets']):
            
            # Check connection rate
            conn_ratio = current['connections_per_second'] / max(self.baselines['connections_per_second'], 1)
            
            # Only trigger if connection rate is also elevated
            if conn_ratio > self.alert_threshold:
                return {
                    'name': 'HTTP Flood Attack',
                    'type': 'ddos.httpflood',
                    'severity': 3,
                    'score': min(100, int(60 + 20 * http_ratio + 20 * conn_ratio / self.alert_threshold)),
                    'details': {
                        'http_ratio': http_ratio,
                        'http_packets': http_packets,
                        'connection_ratio': conn_ratio,
                        'connections_per_second': current['connections_per_second'],
                        'threshold': self.attack_signatures['http_flood']['ratio_threshold'],
                        'source_ips': len(self.traffic_stats['ip_sources'])
                    }
                }
        
        return None
    
    def _check_amplification_attack(self, current: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for amplification DDoS attacks (e.g., DNS, NTP amplification).
        
        Args:
            current: Current traffic statistics
            
        Returns:
            Attack event if detected, None otherwise
        """
        # Check DNS amplification
        dns_packets = self.traffic_stats['ports'].get(53, 0)
        
        if dns_packets > self.attack_signatures['dns_amplification']['min_packets']:
            # Check packet sizes
            if self.traffic_stats['packet_sizes']:
                avg_size = sum(self.traffic_stats['packet_sizes']) / len(self.traffic_stats['packet_sizes'])
                
                if avg_size > self.attack_signatures['dns_amplification']['avg_packet_size']:
                    return {
                        'name': 'DNS Amplification Attack',
                        'type': 'ddos.dns_amplification',
                        'severity': 4,
                        'score': 85,
                        'details': {
                            'dns_packets': dns_packets,
                            'avg_packet_size': avg_size,
                            'size_threshold': self.attack_signatures['dns_amplification']['avg_packet_size'],
                            'source_ips': len(self.traffic_stats['ip_sources'])
                        }
                    }
        
        # Check NTP amplification
        ntp_packets = self.traffic_stats['ports'].get(123, 0)
        
        if ntp_packets > self.attack_signatures['ntp_amplification']['min_packets']:
            # Check packet sizes
            if self.traffic_stats['packet_sizes']:
                avg_size = sum(self.traffic_stats['packet_sizes']) / len(self.traffic_stats['packet_sizes'])
                
                if avg_size > self.attack_signatures['ntp_amplification']['avg_packet_size']:
                    return {
                        'name': 'NTP Amplification Attack',
                        'type': 'ddos.ntp_amplification',
                        'severity': 4,
                        'score': 85,
                        'details': {
                            'ntp_packets': ntp_packets,
                            'avg_packet_size': avg_size,
                            'size_threshold': self.attack_signatures['ntp_amplification']['avg_packet_size'],
                            'source_ips': len(self.traffic_stats['ip_sources'])
                        }
                    }
                    
        return None
    
    def _check_fragmentation_attack(self, current: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for IP fragmentation attacks.
        
        Args:
            current: Current traffic statistics
            
        Returns:
            Attack event if detected, None otherwise
        """
        fragments = self.traffic_stats['fragments']
        total_packets = sum(current.get('protocols', {}).values()) if current.get('protocols') else 1
        
        frag_ratio = fragments / total_packets if total_packets > 0 else 0
        
        if (frag_ratio > self.attack_signatures['fragmentation']['ratio_threshold'] and
            fragments > self.attack_signatures['fragmentation']['min_fragments']):
            
            return {
                'name': 'IP Fragmentation Attack',
                'type': 'ddos.fragmentation',
                'severity': 3,
                'score': min(100, int(60 + 40 * frag_ratio)),
                'details': {
                    'fragment_ratio': frag_ratio,
                    'fragment_count': fragments,
                    'total_packets': total_packets,
                    'threshold': self.attack_signatures['fragmentation']['ratio_threshold'],
                    'source_ips': len(self.traffic_stats['ip_sources'])
                }
            }
            
        return None