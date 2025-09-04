#!/usr/bin/env python3
"""
Error handling utilities for NoMoreWalls
Provides robust error handling and recovery mechanisms
"""

import traceback
import sys
from typing import Optional, Callable, Any, Dict, List
from functools import wraps

from logger import get_logger, log_error_with_context

logger = get_logger()

class NoMoreWallsError(Exception):
    """Base exception for NoMoreWalls application"""
    pass

class ConfigurationError(NoMoreWallsError):
    """Raised when there's a configuration error"""
    pass

class NetworkError(NoMoreWallsError):
    """Raised when there's a network-related error"""
    pass

class ValidationError(NoMoreWallsError):
    """Raised when validation fails"""
    pass

class ParsingError(NoMoreWallsError):
    """Raised when parsing fails"""
    pass

def handle_exception(operation: str, reraise: bool = False):
    """Decorator for handling exceptions in functions"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except KeyboardInterrupt:
                logger.info(f"Operation '{operation}' interrupted by user")
                raise
            except Exception as e:
                log_error_with_context(e, operation)
                if reraise:
                    raise
                return None
        return wrapper
    return decorator

def safe_execute(func: Callable, *args, default=None, operation: str = "unknown", **kwargs) -> Any:
    """Safely execute a function with error handling"""
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        logger.info(f"Operation '{operation}' interrupted by user")
        raise
    except Exception as e:
        log_error_with_context(e, operation)
        return default

def collect_errors(operations: List[Callable], continue_on_error: bool = True) -> Dict[str, Any]:
    """Execute multiple operations and collect their results and errors"""
    results = {}
    errors = {}
    
    for i, operation in enumerate(operations):
        operation_name = getattr(operation, '__name__', f'operation_{i}')
        try:
            results[operation_name] = operation()
        except KeyboardInterrupt:
            logger.info(f"Operations interrupted by user at {operation_name}")
            break
        except Exception as e:
            errors[operation_name] = str(e)
            log_error_with_context(e, operation_name)
            if not continue_on_error:
                break
    
    return {'results': results, 'errors': errors}

def retry_on_failure(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Decorator to retry function on failure"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        import time
                        sleep_time = delay * (backoff ** attempt)
                        logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {str(e)}. Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)
                    else:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}")
            
            if last_exception:
                raise last_exception
        return wrapper
    return decorator

def graceful_shutdown(cleanup_functions: List[Callable] = None):
    """Perform graceful shutdown with cleanup"""
    logger.info("Performing graceful shutdown...")
    
    if cleanup_functions:
        for cleanup_func in cleanup_functions:
            try:
                cleanup_func()
                logger.debug(f"Cleanup function {cleanup_func.__name__} completed")
            except Exception as e:
                logger.error(f"Error in cleanup function {cleanup_func.__name__}: {str(e)}")
    
    logger.info("Shutdown complete")

def setup_global_exception_handler():
    """Setup global exception handler for uncaught exceptions"""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            logger.info("Application interrupted by user")
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logger.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = handle_exception

class ErrorAggregator:
    """Collect and manage multiple errors"""
    
    def __init__(self):
        self.errors: List[Dict[str, Any]] = []
    
    def add_error(self, error: Exception, context: str, **kwargs):
        """Add an error with context"""
        self.errors.append({
            'error': str(error),
            'type': type(error).__name__,
            'context': context,
            'details': kwargs,
            'traceback': traceback.format_exc()
        })
        log_error_with_context(error, context, **kwargs)
    
    def has_errors(self) -> bool:
        """Check if any errors were collected"""
        return len(self.errors) > 0
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of collected errors"""
        if not self.errors:
            return {'total': 0, 'by_type': {}, 'by_context': {}}
        
        by_type = {}
        by_context = {}
        
        for error in self.errors:
            error_type = error['type']
            context = error['context']
            
            by_type[error_type] = by_type.get(error_type, 0) + 1
            by_context[context] = by_context.get(context, 0) + 1
        
        return {
            'total': len(self.errors),
            'by_type': by_type,
            'by_context': by_context
        }
    
    def log_summary(self):
        """Log error summary"""
        if not self.has_errors():
            logger.info("No errors collected")
            return
        
        summary = self.get_error_summary()
        logger.warning(f"Collected {summary['total']} errors")
        
        if summary['by_type']:
            logger.warning("Errors by type:")
            for error_type, count in summary['by_type'].items():
                logger.warning(f"  {error_type}: {count}")
        
        if summary['by_context']:
            logger.warning("Errors by context:")
            for context, count in summary['by_context'].items():
                logger.warning(f"  {context}: {count}")
    
    def clear(self):
        """Clear all collected errors"""
        self.errors.clear()

# Global error aggregator
global_error_aggregator = ErrorAggregator()

def get_error_aggregator() -> ErrorAggregator:
    """Get global error aggregator"""
    return global_error_aggregator