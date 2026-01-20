#!/usr/bin/env python3
"""
Logging utilities for NoMoreWalls
Provides structured logging to replace print statements
"""

import logging
import sys
from typing import Optional

# Configure logging
def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging configuration"""
    
    # Create logger
    logger = logging.getLogger("NoMoreWalls")
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create file handler for {log_file}: {e}")
    
    return logger

# Global logger instance
logger = setup_logging()

def get_logger() -> logging.Logger:
    """Get the global logger instance"""
    return logger

def log_progress(current: int, total: int, operation: str) -> None:
    """Log progress for long-running operations"""
    if total > 0:
        percentage = (current / total) * 100
        logger.info(f"{operation} progress: {current}/{total} ({percentage:.1f}%)")
    else:
        logger.info(f"{operation} progress: {current}")

def log_error_with_context(error: Exception, context: str, **kwargs) -> None:
    """Log error with additional context"""
    logger.error(f"Error in {context}: {str(error)}", extra=kwargs, exc_info=True)

def log_network_error(url: str, error: Exception, retry_count: int = 0) -> None:
    """Log network-related errors with URL context"""
    logger.warning(f"Network error fetching {url} (attempt {retry_count + 1}): {str(error)}")

def log_validation_error(item: str, error: str) -> None:
    """Log validation errors"""
    logger.warning(f"Validation failed for {item}: {error}")

def log_statistics(stats: dict) -> None:
    """Log statistics in a structured way"""
    logger.info("Statistics:")
    for key, value in stats.items():
        logger.info(f"  {key}: {value}")