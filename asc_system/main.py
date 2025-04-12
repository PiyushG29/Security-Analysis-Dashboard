#!/usr/bin/env python3
"""
Advanced Security Control (ASC) System - Main Entry Point

This module initializes and runs the AI-powered cybersecurity threat detection system.
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from dotenv import load_dotenv

# Setup path for local imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import core modules
from src.core.engine import SecurityEngine
from src.core.config_manager import ConfigManager
from src.utils.logger import setup_logging

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="AI-powered Cybersecurity Threat Detection System")
    parser.add_argument("-c", "--config", type=str, default="config/default.yaml",
                        help="Path to configuration file")
    parser.add_argument("-m", "--mode", type=str, choices=["real-time", "historical", "training"], 
                        default="real-time", help="Operating mode")
    parser.add_argument("-l", "--log-level", type=str, choices=["DEBUG", "INFO", "WARNING", "ERROR"], 
                        default="INFO", help="Logging level")
    parser.add_argument("--api", action="store_true", help="Start the system with the API server")
    parser.add_argument("--no-ml", action="store_true", 
                        help="Disable machine learning components")
    return parser.parse_args()

def main():
    """Main entry point for the ASC system."""
    # Parse arguments and load environment variables
    args = parse_arguments()
    load_dotenv()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger("asc")
    logger.info("Starting Advanced Security Control System")
    
    try:
        # Initialize configuration
        config_path = Path(args.config)
        if not config_path.exists():
            logger.error(f"Configuration file not found: {config_path}")
            sys.exit(1)
            
        config_manager = ConfigManager(config_path)
        config = config_manager.load_config()
        
        # Initialize security engine
        engine = SecurityEngine(
            config=config,
            mode=args.mode,
            enable_ml=not args.no_ml
        )
        
        # Start the system based on the mode
        if args.api:
            from src.api.server import start_api_server
            start_api_server(engine, config.get("api", {}))
        else:
            # Start the security engine
            engine.start()
            
            # Block until stopped
            try:
                engine.join()
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt received, shutting down...")
                engine.stop()
                
    except Exception as e:
        logger.exception(f"Failed to start ASC system: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()