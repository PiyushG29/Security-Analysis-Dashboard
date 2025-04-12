"""
Base Analyzer Module for the ASC System

This module defines the base class that all analyzer modules must inherit from.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import queue

from ..utils.logger import get_logger


class BaseAnalyzer(ABC):
    """
    Abstract base class for all analyzers in the ASC system.
    
    Analyzers are responsible for processing and enriching security events
    by adding context, correlating with other events, calculating threat scores,
    etc.
    """
    
    def __init__(self, alert_queue: Optional[queue.Queue] = None, config: Dict[str, Any] = None):
        """
        Initialize the analyzer.
        
        Args:
            alert_queue: Optional queue for generated alerts (if analyzer can generate alerts)
            config: Configuration parameters for the analyzer
        """
        self.name = self.__class__.__name__
        self.alert_queue = alert_queue
        self.config = config or {}
        self.logger = get_logger(f"analyzer.{self.name.lower()}")
        self.logger.info(f"{self.name} initialized")
    
    @abstractmethod
    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a security event and enrich it with additional information.
        
        This method must be implemented by all analyzer subclasses.
        
        Args:
            event: The security event to analyze
            
        Returns:
            The enhanced event with additional analysis information
        """
        pass
    
    def generate_alert(self, event: Dict[str, Any]) -> None:
        """
        Generate a security alert based on an analyzed event.
        
        Args:
            event: The analyzed security event
        """
        if not self.alert_queue:
            self.logger.warning("Cannot generate alert: no alert queue provided")
            return
            
        try:
            # Mark the event as an alert
            event['is_alert'] = True
            
            # Add analyzer identification
            event['analyzer'] = self.name.lower()
            
            # Put the alert in the queue
            self.alert_queue.put(event, block=False)
            self.logger.info(f"Alert generated: {event.get('name', 'Unknown')}")
        except queue.Full:
            self.logger.warning("Alert queue is full, alert discarded")
    
    def correlate_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlate multiple events to identify patterns or relationships.
        
        Args:
            events: List of events to correlate
            
        Returns:
            A new event representing the correlation, or None
        """
        raise NotImplementedError("Event correlation not implemented by this analyzer")
    
    def should_alert(self, event: Dict[str, Any]) -> bool:
        """
        Determine if an event should generate an alert based on analyzer rules.
        
        Args:
            event: The event to check
            
        Returns:
            True if the event should generate an alert, False otherwise
        """
        # Default implementation checks for a threshold in config
        threshold = self.config.get('alert_threshold', 80)
        score = event.get('score', 0)
        return score >= threshold