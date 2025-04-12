"""
Network Traffic Detector Module for the ASC System

This module captures and analyzes network traffic to detect potential security threats.
It serves as the primary source of network data for other detector modules.
"""

import time
import queue
import threading
import socket
import struct
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
import platform
from collections import defaultdict, deque

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .base_detector import BaseDetector
from ..utils.logger import get_logger


class NetworkTrafficDetector(BaseDetector):
    """
    Detector for capturing and analyzing network traffic.
    
    This detector:
    - Captures network packets using pyshark or scapy
    - Performs basic analysis on traffic patterns
    - Identifies common network-based attack signatures
    - Provides packet data to other detectors for specialized analysis
    """
    
    def __init__(self, event_queue: queue.Queue, config: Dict[str, Any] = None):
        """
        Initialize the network traffic detector.
        
        Args:
            event_queue: Queue for detected security events
            config: Configuration parameters
        """
        super().__init__(event_queue, config)
        
        # Configure network interface
        self.interface = self.config.get('interface', 'default')
        if self.interface == 'default':
            self.interface = self._get_default_interface()
            
        # Initialize capture parameters
        self.capture_timeout = self.config.get('capture_timeout', 0.5)  # seconds
        self.max_packets = self.config.get('max_packets_per_cycle', 1000)
        self.bpf_filter = self.config.get('bpf_filter', '')
        
        # Traffic analysis settings
        self.baseline_period = self.config.get('baseline_period', 300)  # 5 minutes
        self.alert_threshold = self.config.get('alert_threshold', 2.0)  # 2x baseline
        
        # Traffic statistics
        self.stats = {
            'total_packets': 0,
            'bytes_received': 0,
            'packets_per_protocol': defaultdict(int),
            'connections': defaultdict(int),
            'unique_ips': set(),
            'packet_rate': 0,
            'last_update': time.time()
        }
        
        # Traffic history for baseline calculation
        self.traffic_history = deque(maxlen=int(self.baseline_period / self.detection_interval))
        
        # Baseline values
        self.baseline = {
            'packet_rate': 0,
            'connection_rate': 0,
            'new_ip_rate': 0,
            'last_update': 0
        }
        
        # Packet buffer for sharing with other detectors
        self.packet_buffer = deque(maxlen=1000)
        self.packet_buffer_lock = threading.Lock()
        
        # Determine which packet capture library to use
        if PYSHARK_AVAILABLE:
            self.capture_method = 'pyshark'
            self.logger.info("Using PyShark for packet capture")
        elif SCAPY_AVAILABLE:
            self.capture_method = 'scapy'
            self.logger.info("Using Scapy for packet capture")
        else:
            self.capture_method = None
            self.logger.error("No packet capture library available - install pyshark or scapy")
        
        self.logger.info(f"Network Traffic Detector initialized on interface '{self.interface}'")
    
    def on_start(self):
        """Set up the packet capture when starting the detector."""
        if self.capture_method is None:
            self.logger.error("Cannot start: no packet capture library available")
            self.is_running = False
            return
            
        self.logger.info(f"Starting network traffic capture on {self.interface}")
        self._setup_capture()
            
    def on_stop(self):
        """Clean up resources when stopping the detector."""
        self.logger.info("Stopping network traffic capture")
        if hasattr(self, 'capture') and self.capture_method == 'pyshark':
            self.capture.close()
    
    def _setup_capture(self):
        """Set up the packet capture based on the selected method."""
        try:
            if self.capture_method == 'pyshark':
                import pyshark
                self.capture = pyshark.LiveCapture(
                    interface=self.interface,
                    display_filter=self.bpf_filter
                )
                self.logger.info("PyShark capture initialized")
                
            elif self.capture_method == 'scapy':
                # Scapy capture is initialized in detect()
                self.logger.info("Scapy capture will be initialized during detection")
                
            else:
                self.logger.error("No capture method available")
                self.is_running = False
                
        except Exception as e:
            self.logger.error(f"Failed to set up packet capture: {e}", exc_info=True)
            self.is_running = False
    
    def detect(self) -> Optional[List[Dict[str, Any]]]:
        """
        Capture and analyze network traffic.
        
        Returns:
            A list of security events if suspicious traffic is detected
        """
        if not self.is_running:
            return None
            
        # Use the appropriate capture method
        if self.capture_method == 'pyshark':
            return self._detect_with_pyshark()
        elif self.capture_method == 'scapy':
            return self._detect_with_scapy()
        else:
            return None
    
    def _detect_with_pyshark(self) -> Optional[List[Dict[str, Any]]]:
        """Capture and analyze packets using PyShark."""
        packets = []
        events = []
        start_time = time.time()
        
        try:
            # Capture packets
            self.capture.sniff(timeout=self.capture_timeout, packet_count=self.max_packets)
            packets = self.capture._packets
            
            # Process captured packets
            if packets:
                self._process_packets_pyshark(packets)
                events = self._analyze_traffic()
                
                # Share packets with other detectors
                with self.packet_buffer_lock:
                    self.packet_buffer.extend(packets)
                    
        except Exception as e:
            self.logger.error(f"Error in PyShark packet capture: {e}", exc_info=True)
        
        return events if events else None
    
    def _detect_with_scapy(self) -> Optional[List[Dict[str, Any]]]:
        """Capture and analyze packets using Scapy."""
        packets = []
        events = []
        
        try:
            # Capture packets
            packets = sniff(
                iface=self.interface,
                count=self.max_packets,
                timeout=self.capture_timeout,
                filter=self.bpf_filter if self.bpf_filter else None
            )
            
            # Process captured packets
            if packets:
                self._process_packets_scapy(packets)
                events = self._analyze_traffic()
                
                # Share packets with other detectors
                with self.packet_buffer_lock:
                    self.packet_buffer.extend(packets)
                    
        except Exception as e:
            self.logger.error(f"Error in Scapy packet capture: {e}", exc_info=True)
        
        return events if events else None
    
    def _process_packets_pyshark(self, packets):
        """
        Process packets captured with PyShark.
        
        Args:
            packets: List of packets from PyShark
        """
        now = time.time()
        packet_count = len(packets)
        bytes_received = 0
        
        new_connections = set()
        new_ips = set()
        
        for packet in packets:
            self.stats['total_packets'] += 1
            
            # Extract protocol
            if hasattr(packet, 'highest_layer'):
                proto = packet.highest_layer
                self.stats['packets_per_protocol'][proto] += 1
            
            # Extract IP information if available
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                # Record unique IPs
                if src_ip not in self.stats['unique_ips']:
                    new_ips.add(src_ip)
                    self.stats['unique_ips'].add(src_ip)
                    
                if dst_ip not in self.stats['unique_ips']:
                    new_ips.add(dst_ip)
                    self.stats['unique_ips'].add(dst_ip)
                
                # Record connection
                if hasattr(packet, 'tcp') or hasattr(packet, 'udp'):
                    src_port = packet.tcp.srcport if hasattr(packet, 'tcp') else packet.udp.srcport
                    dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else packet.udp.dstport
                    conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    
                    if self.stats['connections'][conn_key] == 0:
                        new_connections.add(conn_key)
                        
                    self.stats['connections'][conn_key] += 1
            
            # Count bytes
            if hasattr(packet, 'length'):
                bytes_received += int(packet.length)
        
        # Update statistics
        elapsed = now - self.stats['last_update']
        if elapsed > 0:
            self.stats['packet_rate'] = packet_count / elapsed
            self.stats['bytes_received'] += bytes_received
            self.stats['last_update'] = now
            
            # Add current stats to history for baseline calculation
            self.traffic_history.append({
                'packet_rate': self.stats['packet_rate'],
                'new_connections': len(new_connections),
                'new_ips': len(new_ips),
                'timestamp': now
            })
            
            # Update baseline periodically
            if now - self.baseline['last_update'] > self.baseline_period:
                self._update_baseline()
    
    def _process_packets_scapy(self, packets):
        """
        Process packets captured with Scapy.
        
        Args:
            packets: List of packets from Scapy
        """
        now = time.time()
        packet_count = len(packets)
        bytes_received = 0
        
        new_connections = set()
        new_ips = set()
        
        for packet in packets:
            self.stats['total_packets'] += 1
            
            # Extract protocol and layers
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = "IP"
                
                # Get more specific protocol if available
                if TCP in packet:
                    proto = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    proto = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif ICMP in packet:
                    proto = "ICMP"
                    src_port = 0
                    dst_port = 0
                
                self.stats['packets_per_protocol'][proto] += 1
                
                # Record unique IPs
                if src_ip not in self.stats['unique_ips']:
                    new_ips.add(src_ip)
                    self.stats['unique_ips'].add(src_ip)
                    
                if dst_ip not in self.stats['unique_ips']:
                    new_ips.add(dst_ip)
                    self.stats['unique_ips'].add(dst_ip)
                
                # Record connection for TCP/UDP
                if proto in ["TCP", "UDP"]:
                    conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    
                    if self.stats['connections'][conn_key] == 0:
                        new_connections.add(conn_key)
                        
                    self.stats['connections'][conn_key] += 1
            
            elif ARP in packet:
                self.stats['packets_per_protocol']["ARP"] += 1
            
            # Count bytes
            if hasattr(packet, 'len'):
                bytes_received += packet.len
            
        # Update statistics
        elapsed = now - self.stats['last_update']
        if elapsed > 0:
            self.stats['packet_rate'] = packet_count / elapsed
            self.stats['bytes_received'] += bytes_received
            self.stats['last_update'] = now
            
            # Add current stats to history for baseline calculation
            self.traffic_history.append({
                'packet_rate': self.stats['packet_rate'],
                'new_connections': len(new_connections),
                'new_ips': len(new_ips),
                'timestamp': now
            })
            
            # Update baseline periodically
            if now - self.baseline['last_update'] > self.baseline_period:
                self._update_baseline()
    
    def _analyze_traffic(self) -> List[Dict[str, Any]]:
        """
        Analyze traffic patterns to detect anomalies.
        
        Returns:
            List of security events
        """
        events = []
        
        # Skip analysis if baseline isn't established yet
        if self.baseline['last_update'] == 0:
            if len(self.traffic_history) >= 10:  # Need at least 10 samples for initial baseline
                self._update_baseline()
            return events
        
        # Get current rates
        current_packet_rate = self.stats['packet_rate']
        
        # Calculate current connection rate
        new_connections = 0
        new_ips = 0
        
        if self.traffic_history:
            latest = self.traffic_history[-1]
            new_connections = latest['new_connections']
            new_ips = latest['new_ips']
        
        # Check for traffic anomalies
        packet_ratio = current_packet_rate / max(self.baseline['packet_rate'], 1)
        connection_ratio = new_connections / max(self.baseline['connection_rate'], 1)
        new_ip_ratio = new_ips / max(self.baseline['new_ip_rate'], 1)
        
        # Detect significant increases in traffic (possible DoS)
        if packet_ratio > self.alert_threshold:
            events.append({
                'name': 'Traffic Volume Anomaly',
                'type': 'network.anomaly.traffic_volume',
                'severity': 3,
                'score': min(100, int(50 + 50 * (packet_ratio / self.alert_threshold))),
                'details': {
                    'current_packet_rate': current_packet_rate,
                    'baseline_packet_rate': self.baseline['packet_rate'],
                    'ratio': packet_ratio,
                    'threshold': self.alert_threshold
                }
            })
        
        # Detect significant increase in new connections (possible port scan or C&C activity)
        if connection_ratio > self.alert_threshold and new_connections > 10:
            events.append({
                'name': 'Connection Rate Anomaly',
                'type': 'network.anomaly.connection_spike',
                'severity': 3,
                'score': min(100, int(50 + 50 * (connection_ratio / self.alert_threshold))),
                'details': {
                    'new_connections': new_connections,
                    'baseline_connection_rate': self.baseline['connection_rate'],
                    'ratio': connection_ratio,
                    'threshold': self.alert_threshold
                }
            })
        
        # Detect significant increase in new IPs (possible scan or lateral movement)
        if new_ip_ratio > self.alert_threshold and new_ips > 5:
            events.append({
                'name': 'New IP Address Anomaly',
                'type': 'network.anomaly.new_ip_addresses',
                'severity': 2,
                'score': min(100, int(40 + 60 * (new_ip_ratio / self.alert_threshold))),
                'details': {
                    'new_ips': new_ips,
                    'baseline_new_ip_rate': self.baseline['new_ip_rate'],
                    'ratio': new_ip_ratio,
                    'threshold': self.alert_threshold
                }
            })
        
        return events
    
    def _update_baseline(self):
        """Update traffic baseline using historical data."""
        if not self.traffic_history:
            return
        
        self.logger.debug("Updating traffic baseline")
        
        # Calculate averages
        packet_rates = [entry['packet_rate'] for entry in self.traffic_history]
        connection_rates = [entry['new_connections'] for entry in self.traffic_history]
        ip_rates = [entry['new_ips'] for entry in self.traffic_history]
        
        # Update the baseline
        self.baseline = {
            'packet_rate': sum(packet_rates) / len(packet_rates),
            'connection_rate': sum(connection_rates) / len(connection_rates),
            'new_ip_rate': sum(ip_rates) / len(ip_rates),
            'last_update': time.time()
        }
        
        self.logger.info(f"Updated traffic baseline: "
                       f"packet_rate={self.baseline['packet_rate']:.2f} pps, "
                       f"connection_rate={self.baseline['connection_rate']:.2f}, "
                       f"new_ip_rate={self.baseline['new_ip_rate']:.2f}")
    
    def _get_default_interface(self) -> str:
        """
        Get the default network interface for the current platform.
        
        Returns:
            The name of the default network interface
        """
        system = platform.system()
        
        if system == "Windows":
            # On Windows, return the first available interface
            import netifaces
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return iface
            return "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}"  # Default WinPcap interface
            
        elif system == "Linux":
            # On Linux, try to find the default interface
            try:
                with open('/proc/net/route') as f:
                    for line in f:
                        fields = line.strip().split()
                        if fields[1] == '00000000':  # Default route
                            return fields[0]
                return "eth0"  # Default fallback
            except:
                return "eth0"
                
        elif system == "Darwin":  # macOS
            # On macOS, try to find the default interface
            try:
                import subprocess
                result = subprocess.run(['route', '-n', 'get', 'default'], 
                                       capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'interface:' in line:
                        return line.split(':')[1].strip()
                return "en0"  # Default fallback
            except:
                return "en0"
        
        else:
            # Unknown platform, use a common interface name
            return "eth0"
    
    def get_packet_buffer(self) -> List:
        """
        Get a copy of the current packet buffer.
        
        Returns:
            A list of packets for analysis by other detectors
        """
        with self.packet_buffer_lock:
            return list(self.packet_buffer)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current traffic statistics.
        
        Returns:
            A dictionary of traffic statistics
        """
        return {
            'total_packets': self.stats['total_packets'],
            'bytes_received': self.stats['bytes_received'],
            'packet_rate': self.stats['packet_rate'],
            'protocols': dict(self.stats['packets_per_protocol']),
            'unique_ips': len(self.stats['unique_ips']),
            'active_connections': len(self.stats['connections']),
            'baseline': self.baseline
        }