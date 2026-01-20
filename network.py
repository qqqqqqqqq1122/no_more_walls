#!/usr/bin/env python3
"""
Network utilities for NoMoreWalls
Provides robust networking with retry logic and better error handling
"""

import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, Union
from requests_file import FileAdapter

from config import (
    DEFAULT_TIMEOUT, MAX_RETRIES, RETRY_BACKOFF_FACTOR, MAX_RETRY_DELAY,
    USER_AGENT, get_effective_proxy
)
from logger import get_logger, log_network_error

logger = get_logger()

class RobustSession:
    """Robust HTTP session with retry logic and better error handling"""
    
    def __init__(self, proxy: Optional[str] = None):
        self.session = requests.Session()
        self.session.trust_env = False
        
        # Set proxy if provided
        proxy = proxy or get_effective_proxy()
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
            logger.info(f"Using proxy: {proxy}")
        
        # Set user agent
        self.session.headers["User-Agent"] = USER_AGENT
        
        # Add file adapter for local files
        self.session.mount('file://', FileAdapter())
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def get(self, url: str, timeout: Optional[tuple] = None, **kwargs) -> requests.Response:
        """Make a GET request with robust error handling"""
        timeout = timeout or DEFAULT_TIMEOUT
        
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(url, timeout=timeout, **kwargs)
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                log_network_error(url, e, attempt)
                
                if attempt == MAX_RETRIES:
                    raise
                
                # Calculate delay with exponential backoff
                delay = min(RETRY_BACKOFF_FACTOR ** attempt, MAX_RETRY_DELAY)
                logger.info(f"Retrying {url} in {delay:.1f} seconds...")
                time.sleep(delay)
        
        # This should never be reached, but just in case
        raise requests.exceptions.RequestException(f"Failed to fetch {url} after {MAX_RETRIES + 1} attempts")
    
    def post(self, url: str, timeout: Optional[tuple] = None, **kwargs) -> requests.Response:
        """Make a POST request with robust error handling"""
        timeout = timeout or DEFAULT_TIMEOUT
        return self.session.post(url, timeout=timeout, **kwargs)
    
    def close(self):
        """Close the session"""
        self.session.close()

def resolve_relative_file(url: str) -> str:
    """Resolve relative file URLs to absolute paths"""
    if url.startswith('file://'):
        import os
        basedir = os.path.dirname(os.path.abspath(__file__))
        return url.replace('/./', '/'+basedir.lstrip('/').replace(os.sep, '/')+'/')
    return url

def is_valid_url(url: str) -> bool:
    """Validate if a URL is properly formatted"""
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def sanitize_url(url: str) -> str:
    """Sanitize URL for logging (remove sensitive parts)"""
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        # Remove query parameters and fragments that might contain sensitive data
        sanitized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            '', '', ''  # Remove params, query, fragment
        ))
        return sanitized
    except Exception:
        return url

def create_session(proxy: Optional[str] = None) -> RobustSession:
    """Create a new robust session"""
    return RobustSession(proxy)

# Global session instance
_global_session = None

def get_global_session() -> RobustSession:
    """Get or create global session instance"""
    global _global_session
    if _global_session is None:
        _global_session = create_session()
    return _global_session

def close_global_session():
    """Close global session"""
    global _global_session
    if _global_session:
        _global_session.close()
        _global_session = None