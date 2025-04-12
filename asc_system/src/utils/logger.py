"""
Logging Configuration for ASC System

This module sets up logging for the entire ASC system.
"""

import os
import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Optional

def setup_logging(log_level: str = "INFO", 
                 log_file: Optional[str] = None,
                 log_format: Optional[str] = None) -> None:
    """
    Configure logging for the ASC system.
    
    Args:
        log_level: The logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional path to a log file
        log_format: Optional custom log format
    """
    # Convert string level to logging level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Set up the default log format
    if not log_format:
        log_format = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
    
    formatter = logging.Formatter(log_format)
    
    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        log_path = Path(log_file)
        
        # Create directory if it doesn't exist
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Set up rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Create a specific logger for the ASC system
    asc_logger = logging.getLogger("asc")
    asc_logger.setLevel(numeric_level)
    
    # Log the startup information
    asc_logger.info(f"Logging initialized at level {log_level}")

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the ASC namespace.
    
    Args:
        name: The name of the logger module
        
    Returns:
        A Logger instance
    """
    return logging.getLogger(f"asc.{name}")