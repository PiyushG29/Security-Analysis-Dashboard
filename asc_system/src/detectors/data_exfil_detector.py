"""
Data Exfiltration Detector Module for the ASC System

This module detects potential data exfiltration attempts by monitoring unusual
outbound traffic patterns and large data transfers.
"""

import time
import queue
from typing import Dict, Any, List, Optional
from collections import defaultdict

from .base_detector import BaseDetector


class DataExfilDetector(BaseDetector):
    """
    Detector for identifying potential data exfiltration attempts.
    
    This detector:
    - Monitors outbound traffic volume
    - Detects unusual data transfer patterns
    - Identifies large file uploads or continuous data streams
    """
    
    def __init__(self, event_queue: queue.Queue, config: Dict[str, Any] = None):
        """
        Initialize the data exfiltration detector.
        
        Args:
            event_queue: Queue for detected security events
            config: Configuration parameters
        """
        super().__init__(event_queue, config)
        
        # Configuration parameters
        self.data_threshold = self.config.get('data_threshold', 100 * 1024 * 1024)  # 100 MB
        self.time_window = self.config.get('time_window', 300)  # 5 minutes
        self.alert_threshold = self.config.get('alert_threshold', 3)  # Alerts per source IP
        
        # Traffic tracking
        self.traffic_log = defaultdict(list)  # {source_ip: [(timestamp, bytes)]}
        self.alert_log = defaultdict(int)  # {source_ip: alert_count}
        
        self.logger.info("Data Exfiltration Detector initialized")
    
    def detect(self) -> Optional[List[Dict[str, Any]]]:
        """
        Detect potential data exfiltration attempts.
        
        Returns:
            A list of detected data exfiltration events or None
        """
        current_time = time.time()
        events = []
        
        # Analyze traffic logs
        for source_ip, traffic in list(self.traffic_log.items()):
            # Filter traffic within the time window
            recent_traffic = [entry for entry in traffic if current_time - entry[0] <= self.time_window]
            self.traffic_log[source_ip] = recent_traffic
            
            # Calculate total data transferred
            total_data = sum(bytes_transferred for _, bytes_transferred in recent_traffic)
            if total_data >= self.data_threshold:
                # Generate an alert if not already alerted for this source IP
                if self.alert_log[source_ip] < self.alert_threshold:
                    event = {
                        'name': 'Data Exfiltration Detected',
                        'type': 'exfiltration.data',
                        'severity': 4,
                        'score': min(100, 70 + (total_data / self.data_threshold) * 30),
                        'details': {
                            'source_ip': source_ip,
                            'total_data': total_data,
                            'time_window': self.time_window,
                            'threshold': self.data_threshold
                        }
                    }
                    events.append(event)
                    self.alert_log[source_ip] += 1
                    self.logger.info(f"Data exfiltration detected from {source_ip} transferring {total_data} bytes")
        
        return events if events else None
    
    def log_traffic(self, source_ip: str, bytes_transferred: int) -> None:
        """
        Log outbound traffic for analysis.
        
        Args:
            source_ip: The source IP address of the traffic
            bytes_transferred: The amount of data transferred in bytes
        """
        current_time = time.time()
        self.traffic_log[source_ip].append((current_time, bytes_transferred))
        self.logger.debug(f"Logged {bytes_transferred} bytes transferred from {source_ip}")