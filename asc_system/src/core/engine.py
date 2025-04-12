"""
Security Engine for the ASC System

This module contains the main security engine that orchestrates all detection and response components.
"""

import threading
import time
import queue
import logging
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor

from ..utils.logger import get_logger
from ..detectors.base_detector import BaseDetector
from ..analyzers.base_analyzer import BaseAnalyzer
from ..responders.base_responder import BaseResponder

class SecurityEngine(threading.Thread):
    """
    Core security engine that orchestrates all components of the ASC system.
    
    This engine:
    - Manages network traffic capture
    - Coordinates detection modules
    - Processes alerts through analyzers
    - Triggers response actions
    - Handles machine learning model integration
    """
    
    def __init__(self, config: Dict[str, Any], mode: str = "real-time", enable_ml: bool = True):
        """
        Initialize the security engine.
        
        Args:
            config: The system configuration
            mode: Operating mode ("real-time", "historical", "training")
            enable_ml: Whether to enable machine learning components
        """
        super().__init__(name="SecurityEngine")
        self.daemon = True
        
        self.logger = get_logger("engine")
        self.config = config
        self.mode = mode
        self.enable_ml = enable_ml
        
        # Component registries
        self.detectors = {}
        self.analyzers = {}
        self.responders = {}
        
        # Event processing queues
        self.event_queue = queue.Queue(maxsize=10000)
        self.alert_queue = queue.Queue(maxsize=1000)
        
        # Thread control
        self.is_running = False
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('engine.max_workers', 10),
            thread_name_prefix="asc-worker"
        )
        
        self.logger.info(f"Security Engine initialized in {mode} mode")
        self.logger.info(f"Machine learning components {'enabled' if enable_ml else 'disabled'}")
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self) -> None:
        """Initialize all detection, analysis, and response components."""
        self.logger.info("Initializing security components")
        
        self._load_detectors()
        self._load_analyzers()
        self._load_responders()
        
        if self.enable_ml:
            self._initialize_ml_models()
    
    def _load_detectors(self) -> None:
        """Load and initialize detector components based on configuration."""
        detector_config = self.config.get('detection', {})
        
        # Import detectors dynamically based on configuration
        from ..detectors import (
            network_traffic_detector,
            anomaly_detector, 
            ddos_detector,
            port_scan_detector,
            data_exfil_detector,
            api_abuse_detector
        )
        
        # Initialize basic network traffic detector (always required)
        self.detectors['network'] = network_traffic_detector.NetworkTrafficDetector(
            self.event_queue, 
            detector_config.get('network', {})
        )
        
        # Initialize other detectors based on configuration
        enabled_detectors = detector_config.get('enabled_detectors', [])
        
        detector_map = {
            'anomaly': anomaly_detector.AnomalyDetector,
            'ddos': ddos_detector.DDoSDetector,
            'port_scan': port_scan_detector.PortScanDetector,
            'data_exfil': data_exfil_detector.DataExfilDetector,
            'api_abuse': api_abuse_detector.APIAbuseDetector,
        }
        
        # Initialize each enabled detector
        for detector_name in enabled_detectors:
            if detector_name in detector_map:
                try:
                    detector_class = detector_map[detector_name]
                    detector_instance = detector_class(
                        self.event_queue, 
                        detector_config.get(detector_name, {})
                    )
                    self.detectors[detector_name] = detector_instance
                    self.logger.info(f"Initialized {detector_name} detector")
                except Exception as e:
                    self.logger.error(f"Failed to initialize {detector_name} detector: {e}")
    
    def _load_analyzers(self) -> None:
        """Load and initialize analyzer components based on configuration."""
        analyzer_config = self.config.get('analyzers', {})
        
        # Import analyzers dynamically
        from ..analyzers import (
            threat_score_analyzer,
            correlation_analyzer,
            context_analyzer
        )
        
        # Initialize analyzers
        self.analyzers['threat_score'] = threat_score_analyzer.ThreatScoreAnalyzer(
            self.alert_queue,
            analyzer_config.get('threat_score', {})
        )
        
        self.analyzers['correlation'] = correlation_analyzer.CorrelationAnalyzer(
            self.alert_queue,
            analyzer_config.get('correlation', {})
        )
        
        self.analyzers['context'] = context_analyzer.ContextAnalyzer(
            self.alert_queue,
            analyzer_config.get('context', {})
        )
        
        self.logger.info(f"Initialized {len(self.analyzers)} analyzers")
    
    def _load_responders(self) -> None:
        """Load and initialize response components based on configuration."""
        responder_config = self.config.get('response', {})
        
        # Import responders dynamically
        from ..responders import (
            alert_responder,
            containment_responder,
            forensic_responder,
            reporting_responder
        )
        
        # Initialize responders
        self.responders['alert'] = alert_responder.AlertResponder(
            responder_config.get('alert', {})
        )
        
        self.responders['containment'] = containment_responder.ContainmentResponder(
            responder_config.get('containment', {})
        )
        
        self.responders['forensic'] = forensic_responder.ForensicResponder(
            responder_config.get('forensic', {})
        )
        
        self.responders['reporting'] = reporting_responder.ReportingResponder(
            responder_config.get('reporting', {})
        )
        
        self.logger.info(f"Initialized {len(self.responders)} responders")
    
    def _initialize_ml_models(self) -> None:
        """Initialize machine learning models."""
        if not self.enable_ml:
            return
            
        self.logger.info("Initializing machine learning models")
        
        from ..ml import model_manager
        
        try:
            self.ml_manager = model_manager.ModelManager(
                self.config.get('ml', {})
            )
            self.ml_manager.load_models()
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}")
            self.enable_ml = False
    
    def run(self) -> None:
        """Run the security engine (main thread method)."""
        self.is_running = True
        self.logger.info("Security Engine started")
        
        # Start all detector threads
        for name, detector in self.detectors.items():
            detector.start()
            self.logger.info(f"Started {name} detector")
        
        # Process events while running
        while self.is_running:
            try:
                # Process events from the queue
                self._process_event_queue()
                
                # Process alerts from analyzers
                self._process_alert_queue()
                
                # Small sleep to prevent CPU hogging
                time.sleep(0.01)
                
            except Exception as e:
                self.logger.error(f"Error in main engine loop: {e}", exc_info=True)
    
    def _process_event_queue(self) -> None:
        """Process events from the event queue."""
        try:
            # Process up to 100 events at a time to prevent blocking
            for _ in range(100):
                if self.event_queue.empty():
                    break
                    
                event = self.event_queue.get_nowait()
                
                # Submit event to thread pool for processing
                self.thread_pool.submit(self._analyze_event, event)
                
                # Mark task as done
                self.event_queue.task_done()
                
        except queue.Empty:
            # Queue is empty, no problem
            pass
        except Exception as e:
            self.logger.error(f"Error processing event queue: {e}")
    
    def _analyze_event(self, event: Dict[str, Any]) -> None:
        """
        Analyze a security event and determine if it should generate an alert.
        
        Args:
            event: The security event to analyze
        """
        try:
            # Apply ML analysis if enabled
            if self.enable_ml and hasattr(self, 'ml_manager'):
                event = self.ml_manager.enrich_event(event)
            
            # Check if event passes threshold for alert generation
            if self._should_generate_alert(event):
                # Process through analyzers before alerting
                for name, analyzer in self.analyzers.items():
                    event = analyzer.analyze(event)
                
                # Add to alert queue for response handling
                self.alert_queue.put(event)
        except Exception as e:
            self.logger.error(f"Error analyzing event: {e}")
    
    def _should_generate_alert(self, event: Dict[str, Any]) -> bool:
        """
        Determine if an event should generate a security alert.
        
        Args:
            event: The security event to check
            
        Returns:
            True if the event should generate an alert, False otherwise
        """
        # Check if event has a severity or score field
        severity = event.get('severity', 0)
        score = event.get('score', 0)
        
        # Get threshold from config
        threshold = self.config.get('detection.alert_threshold', 70)
        
        # Event exceeds threshold or is marked as critical
        return (severity >= 4 or score >= threshold or 
                event.get('critical', False) or 
                event.get('generate_alert', False))
    
    def _process_alert_queue(self) -> None:
        """Process alerts from the alert queue."""
        try:
            # Process up to 10 alerts at a time
            for _ in range(10):
                if self.alert_queue.empty():
                    break
                    
                alert = self.alert_queue.get_nowait()
                
                # Submit alert to thread pool for response processing
                self.thread_pool.submit(self._respond_to_alert, alert)
                
                # Mark task as done
                self.alert_queue.task_done()
                
        except queue.Empty:
            # Queue is empty, no problem
            pass
        except Exception as e:
            self.logger.error(f"Error processing alert queue: {e}")
    
    def _respond_to_alert(self, alert: Dict[str, Any]) -> None:
        """
        Handle response to a security alert.
        
        Args:
            alert: The security alert to respond to
        """
        try:
            # Log the alert
            self.logger.warning(f"Security Alert: {alert.get('name', 'Unknown')} "
                              f"[Severity: {alert.get('severity', 'Unknown')}]")
            
            # Process through each responder
            for name, responder in self.responders.items():
                if responder.should_respond(alert):
                    responder.respond(alert)
        except Exception as e:
            self.logger.error(f"Error responding to alert: {e}")
    
    def stop(self) -> None:
        """Stop the security engine."""
        self.logger.info("Stopping Security Engine")
        
        # Set running flag to False
        self.is_running = False
        
        # Stop all detectors
        for name, detector in self.detectors.items():
            if detector.is_alive():
                detector.stop()
                self.logger.info(f"Stopped {name} detector")
        
        # Shut down thread pool
        self.thread_pool.shutdown(wait=True)
        
        self.logger.info("Security Engine stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the security engine.
        
        Returns:
            A dictionary with status information
        """
        return {
            'running': self.is_running,
            'mode': self.mode,
            'ml_enabled': self.enable_ml,
            'event_queue_size': self.event_queue.qsize(),
            'alert_queue_size': self.alert_queue.qsize(),
            'detectors': {name: detector.is_alive() for name, detector in self.detectors.items()},
            'responders': list(self.responders.keys()),
            'analyzers': list(self.analyzers.keys()),
        }