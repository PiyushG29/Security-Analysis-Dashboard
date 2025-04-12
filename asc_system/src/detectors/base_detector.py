"""
Base Detector Module for the ASC System

This module defines the base class that all detector modules must inherit from.
"""

import threading
import queue
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from ..utils.logger import get_logger


class BaseDetector(threading.Thread, ABC):
    """
    Abstract base class for all detectors in the ASC system.
    
    Detectors are responsible for monitoring specific aspects of network traffic
    or system behavior and generating security events when suspicious activity
    is detected.
    """
    
    def __init__(self, event_queue: queue.Queue, config: Dict[str, Any] = None):
        """
        Initialize the detector.
        
        Args:
            event_queue: The queue where detected events will be placed
            config: Configuration parameters for the detector
        """
        threading.Thread.__init__(self, daemon=True)
        self.name = self.__class__.__name__
        self.event_queue = event_queue
        self.config = config or {}
        self.logger = get_logger(f"detector.{self.name.lower()}")
        self.is_running = False
        self.detection_interval = self.config.get('interval', 1.0)  # seconds
        self.logger.info(f"{self.name} initialized")
    
    def run(self):
        """Run the detector thread."""
        self.is_running = True
        self.logger.info(f"{self.name} started")
        
        try:
            self.on_start()
            
            while self.is_running:
                try:
                    # Run the detection cycle
                    events = self.detect()
                    
                    # Process any detected events
                    if events:
                        self._process_events(events)
                        
                    # Sleep for the configured interval
                    time.sleep(self.detection_interval)
                    
                except Exception as e:
                    self.logger.error(f"Error in detection cycle: {e}", exc_info=True)
                    time.sleep(1)  # Avoid spinning on repeated errors
        
        except Exception as e:
            self.logger.error(f"Error in detector thread: {e}", exc_info=True)
        finally:
            self.on_stop()
            self.logger.info(f"{self.name} stopped")
    
    def _process_events(self, events):
        """
        Process detected events and add them to the event queue.
        
        Args:
            events: A list of detected security events
        """
        if not events:
            return
            
        # Ensure events is a list
        if not isinstance(events, list):
            events = [events]
            
        # Add common fields and put in queue
        for event in events:
            # Add detector identification
            event['detector'] = self.name.lower()
            
            # Add timestamp if not present
            if 'timestamp' not in event:
                event['timestamp'] = time.time()
                
            # Put the event in the queue
            try:
                self.event_queue.put(event, block=False)
                self.logger.debug(f"Event detected: {event.get('name', 'Unknown')}")
            except queue.Full:
                self.logger.warning("Event queue is full, event discarded")
    
    @abstractmethod
    def detect(self) -> Optional[list]:
        """
        Perform detection of security events.
        
        This method should be implemented by all detector subclasses.
        
        Returns:
            A list of detected security events or None
        """
        pass
    
    def on_start(self):
        """
        Called when the detector is starting.
        
        Subclasses can override this to perform initialization.
        """
        pass
    
    def on_stop(self):
        """
        Called when the detector is stopping.
        
        Subclasses can override this to perform cleanup.
        """
        pass
    
    def stop(self):
        """Stop the detector thread."""
        self.is_running = False