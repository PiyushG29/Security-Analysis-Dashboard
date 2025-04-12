"""
API Abuse Detector Module for the ASC System

This module detects potential API abuse by monitoring request patterns and
identifying excessive or unauthorized access.
"""

import time
import queue
from typing import Dict, Any, List, Optional
from collections import defaultdict

from .base_detector import BaseDetector


class APIAbuseDetector(BaseDetector):
    """
    Detector for identifying potential API abuse.
    
    This detector:
    - Monitors API request rates
    - Detects excessive or unauthorized access patterns
    - Identifies potential credential stuffing or brute force attacks
    """
    
    def __init__(self, event_queue: queue.Queue, config: Dict[str, Any] = None):
        """
        Initialize the API abuse detector.
        
        Args:
            event_queue: Queue for detected security events
            config: Configuration parameters
        """
        super().__init__(event_queue, config)
        
        # Configuration parameters
        self.request_threshold = self.config.get('request_threshold', 100)  # Max requests per time window
        self.time_window = self.config.get('time_window', 60)  # Time window in seconds
        self.alert_threshold = self.config.get('alert_threshold', 3)  # Alerts per source IP
        
        # Request tracking
        self.request_log = defaultdict(list)  # {source_ip: [timestamp]}
        self.alert_log = defaultdict(int)  # {source_ip: alert_count}
        
        self.logger.info("API Abuse Detector initialized")
    
    def detect(self) -> Optional[List[Dict[str, Any]]]:
        """
        Detect potential API abuse.
        
        Returns:
            A list of detected API abuse events or None
        """
        current_time = time.time()
        events = []
        
        # Analyze request logs
        for source_ip, requests in list(self.request_log.items()):
            # Filter requests within the time window
            recent_requests = [timestamp for timestamp in requests if current_time - timestamp <= self.time_window]
            self.request_log[source_ip] = recent_requests
            
            # Check if the number of requests exceeds the threshold
            if len(recent_requests) >= self.request_threshold:
                # Generate an alert if not already alerted for this source IP
                if self.alert_log[source_ip] < self.alert_threshold:
                    event = {
                        'name': 'API Abuse Detected',
                        'type': 'abuse.api',
                        'severity': 3,
                        'score': min(100, 50 + len(recent_requests) * 2),
                        'details': {
                            'source_ip': source_ip,
                            'request_count': len(recent_requests),
                            'time_window': self.time_window,
                            'threshold': self.request_threshold
                        }
                    }
                    events.append(event)
                    self.alert_log[source_ip] += 1
                    self.logger.info(f"API abuse detected from {source_ip} with {len(recent_requests)} requests")
        
        return events if events else None
    
    def log_request(self, source_ip: str) -> None:
        """
        Log an API request for analysis.
        
        Args:
            source_ip: The source IP address of the request
        """
        current_time = time.time()
        self.request_log[source_ip].append(current_time)
        self.logger.debug(f"Logged API request from {source_ip}")