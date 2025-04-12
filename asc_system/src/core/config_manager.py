"""
Configuration Manager for the ASC System

This module handles loading, validating, and providing access to configuration settings.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional

class ConfigManager:
    """
    Manages configuration settings for the ASC system.
    
    Responsible for:
    - Loading configuration from YAML files
    - Validating configuration settings
    - Providing access to configuration values
    - Handling configuration changes at runtime
    """
    
    def __init__(self, config_path: Path, env_prefix: str = "ASC_"):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file
            env_prefix: Prefix for environment variables that override config
        """
        self.config_path = config_path
        self.env_prefix = env_prefix
        self.config = {}
        self.logger = logging.getLogger("asc.config")
    
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from the YAML file and apply environment variable overrides.
        
        Returns:
            A dictionary containing the merged configuration
        """
        self.logger.info(f"Loading configuration from {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            raise
            
        # Apply environment variable overrides
        self._apply_env_overrides()
        
        # Validate the configuration
        self._validate_config()
        
        return self.config
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to the configuration."""
        for env_var, value in os.environ.items():
            if env_var.startswith(self.env_prefix):
                # Convert ASC_SECTION_KEY to section.key
                config_path = env_var[len(self.env_prefix):].lower().replace('_', '.')
                self._set_nested_config(config_path, value)
                self.logger.debug(f"Override from environment: {config_path} = {value}")
    
    def _set_nested_config(self, path: str, value: str) -> None:
        """
        Set a nested configuration value using dot notation.
        
        Args:
            path: Path to the configuration value using dot notation
            value: The value to set
        """
        keys = path.split('.')
        current = self.config
        
        # Navigate to the deepest dict
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
            
        # Set the value, try to convert to appropriate type
        try:
            # Try to evaluate as Python literal (for booleans, ints, etc.)
            import ast
            current[keys[-1]] = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            # If not a Python literal, keep as string
            current[keys[-1]] = value
    
    def _validate_config(self) -> None:
        """
        Validate the configuration structure and required settings.
        
        Raises:
            ValueError: If the configuration is invalid
        """
        required_sections = ['network', 'detection', 'response', 'ml', 'logging']
        
        for section in required_sections:
            if section not in self.config:
                self.logger.warning(f"Missing required configuration section: {section}")
                self.config[section] = {}
        
        # Validate network configuration
        if 'interface' not in self.config.get('network', {}):
            self.logger.warning("No network interface specified, will use default")
            self.config.setdefault('network', {})['interface'] = 'default'
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key: Path to the configuration value using dot notation
            default: Default value if the key doesn't exist
            
        Returns:
            The configuration value or the default value
        """
        keys = key.split('.')
        current = self.config
        
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
                
        return current
    
    def update(self, key: str, value: Any) -> None:
        """
        Update a configuration value at runtime.
        
        Args:
            key: Path to the configuration value using dot notation
            value: The new value to set
        """
        self._set_nested_config(key, str(value))
        self.logger.info(f"Configuration updated: {key} = {value}")