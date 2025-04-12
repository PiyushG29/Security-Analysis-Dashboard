"""
Port Scan Detector Module for the ASC System

This module detects port scanning activities by analyzing connection patterns
and identifying unusual access to multiple ports.
"""

import time
import queue
from typing import Dict, Any, List, Optional
from collections import defaultdict

from .base_detector import BaseDetector


class PortScanDetector(BaseDetector):
    """
    Detector for identifying port scanning activities.
    
    This detector:
    - Monitors connection attempts to multiple ports
    - Identifies rapid or sequential port access patterns
    - Detects horizontal and vertical scanning behaviors
    """
    
    def __init__(self, event_queue: queue.Queue, config: Dict[str, Any] = None):
        """
        Initialize the port scan detector.
        
        Args:
            event_queue: Queue for detected security events
            config: Configuration parameters
        """
        super().__init__(event_queue, config)
        
        # Configuration parameters
        self.scan_threshold = self.config.get('scan_threshold', 10)  # Minimum ports accessed
        self.time_window = self.config.get('time_window', 60)  # Time window in seconds
        self.alert_threshold = self.config.get('alert_threshold', 5)  # Alerts per source IP
        
        # Connection tracking
        self.connection_log = defaultdict(list)  # {source_ip: [(timestamp, port)]}
        self.alert_log = defaultdict(int)  # {source_ip: alert_count}
        
        self.logger.info("Port Scan Detector initialized")
    
    def detect(self) -> Optional[List[Dict[str, Any]]]:
        """
        Detect port scanning activities.
        
        Returns:
            A list of detected port scan events or None
        """
        current_time = time.time()
        events = []
        
        # Analyze connection logs
        for source_ip, connections in list(self.connection_log.items()):
            # Filter connections within the time window
            recent_connections = [conn for conn in connections if current_time - conn[0] <= self.time_window]
            self.connection_log[source_ip] = recent_connections
            
            # Check if the number of unique ports exceeds the threshold
            unique_ports = {port for _, port in recent_connections}
            if len(unique_ports) >= self.scan_threshold:
                # Generate an alert if not already alerted for this source IP
                if self.alert_log[source_ip] < self.alert_threshold:
                    event = {
                        'name': 'Port Scan Detected',
                        'type': 'scan.port',
                        'severity': 3,
                        'score': min(100, 50 + len(unique_ports) * 5),
                        'details': {
                            'source_ip': source_ip,
                            'unique_ports': len(unique_ports),
                            'time_window': self.time_window,
                            'ports': list(unique_ports)
                        }
                    }
                    events.append(event)
                    self.alert_log[source_ip] += 1
                    self.logger.info(f"Port scan detected from {source_ip} accessing {len(unique_ports)} ports")
        
        return events if events else None
    
    def log_connection(self, source_ip: str, port: int) -> None:
        """
        Log a connection attempt for analysis.
        
        Args:
            source_ip: The source IP address of the connection
            port: The destination port accessed
        """
        current_time = time.time()
        self.connection_log[source_ip].append((current_time, port))
        self.logger.debug(f"Logged connection from {source_ip} to port {port}")