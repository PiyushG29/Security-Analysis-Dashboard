"""
Base Responder Module for the ASC System

This module defines the base class that all responder modules must inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List

from ..utils.logger import get_logger


class BaseResponder(ABC):
    """
    Abstract base class for all responders in the ASC system.
    
    Responders are responsible for taking actions in response to security alerts,
    such as sending notifications, blocking traffic, collecting forensic data, etc.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the responder.
        
        Args:
            config: Configuration parameters for the responder
        """
        self.name = self.__class__.__name__
        self.config = config or {}
        self.logger = get_logger(f"responder.{self.name.lower()}")
        self.enabled = self.config.get('enabled', True)
        self.min_severity = self.config.get('min_severity', 3)
        self.logger.info(f"{self.name} initialized (enabled: {self.enabled})")
    
    @abstractmethod
    def respond(self, alert: Dict[str, Any]) -> bool:
        """
        Respond to a security alert with appropriate actions.
        
        This method must be implemented by all responder subclasses.
        
        Args:
            alert: The security alert to respond to
            
        Returns:
            True if the response was successful, False otherwise
        """
        pass
    
    def should_respond(self, alert: Dict[str, Any]) -> bool:
        """
        Determine if this responder should respond to an alert.
        
        Args:
            alert: The security alert to check
            
        Returns:
            True if this responder should handle the alert
        """
        if not self.enabled:
            return False
            
        # Check if alert has a severity field
        severity = alert.get('severity', 0)
        
        # Check if the alert meets the minimum severity threshold
        if severity < self.min_severity:
            return False
            
        # Check if the alert type is in the list of types to respond to
        alert_type = alert.get('type', 'unknown')
        allowed_types = self.config.get('alert_types', [])
        
        if allowed_types and alert_type not in allowed_types:
            return False
            
        return True
    
    def _log_response(self, alert: Dict[str, Any], action: str, success: bool) -> None:
        """
        Log a response action.
        
        Args:
            alert: The alert that triggered the response
            action: The action taken
            success: Whether the action was successful
        """
        alert_name = alert.get('name', 'unknown')
        severity = alert.get('severity', 0)
        
        if success:
            self.logger.info(f"Response action '{action}' for alert '{alert_name}' "
                           f"(severity: {severity}) was successful")
        else:
            self.logger.error(f"Response action '{action}' for alert '{alert_name}' "
                            f"(severity: {severity}) failed")