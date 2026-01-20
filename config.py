#!/usr/bin/env python3
"""
Configuration management for NoMoreWalls
Centralizes configuration options for better maintainability and robustness
"""

import os
from typing import Tuple, List, Dict, Any

# Network configuration
DEFAULT_TIMEOUT = (6, 5)  # (connection_timeout, read_timeout)
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 1.5
MAX_RETRY_DELAY = 30

# Request configuration  
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) Clash-verge/v2.3.1 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'

# Node validation
FAKE_IPS = ["8.8.8.8", "8.8.4.4", "4.2.2.2", "4.2.2.1", "114.114.114.114", "127.0.0.1", "0.0.0.0"]
FAKE_DOMAINS = [".google.com", ".github.com"]
MIN_PORT = 20
MAX_NAME_LENGTH = 30

# Default values
DEFAULT_UUID = '8'*8+'-8888'*3+'-'+'8'*12

# File paths
LOCAL_PROXY_CONF = "local_proxy.conf"
SOURCES_LIST = "sources.list"
CONFIG_YML = "config.yml"
OUTPUT_DIR = "."
SNIPPETS_DIR = "snippets"

# Output files
LIST_RAW_TXT = "list_raw.txt"
LIST_TXT = "list.txt"
LIST_YML = "list.yml" 
LIST_META_YML = "list.meta.yml"
LIST_RESULT_CSV = "list_result.csv"

# Debug flags
DEBUG_NO_NODES = os.path.exists("local_NO_NODES")
DEBUG_NO_DYNAMIC = os.path.exists("local_NO_DYNAMIC") 
DEBUG_NO_ADBLOCK = os.path.exists("local_NO_ADBLOCK")

# Adblock URLs
ABFURLS = (
    "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
    "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
    "https://cdn.jsdelivr.net/gh/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://cdn.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://cdn.jsdelivr.net/gh/d3ward/toolz/master/src/d3host.adblock",
    "https://cdn.jsdelivr.net/gh/afwfv/DD-AD/main/rule/DD-AD.txt",
)

ABFWHITE = (
    "https://cdn.jsdelivr.net/gh/privacy-protection-tools/dead-horse/master/anti-ad-white-list.txt",
    "file:///./abpwhite.txt",
)

# Thread configuration
MAX_CONCURRENT_REQUESTS = 10

def get_proxy_config() -> str:
    """Get proxy configuration from file or environment"""
    try:
        with open(LOCAL_PROXY_CONF, 'r') as f:
            proxy = f.read().strip()
        return proxy if proxy else None
    except FileNotFoundError:
        return None

def is_local_mode() -> bool:
    """Check if running in local mode"""
    proxy = get_proxy_config()
    return not proxy if proxy is not None else False

def is_github_actions() -> bool:
    """Check if running in GitHub Actions"""
    return os.environ.get("GITHUB_ACTIONS") == "true"

def get_effective_proxy() -> str:
    """Get effective proxy configuration"""
    if is_github_actions():
        return None
    return get_proxy_config()

def validate_config() -> List[str]:
    """Validate configuration and return list of issues"""
    issues = []
    
    # Check required files exist
    required_files = [SOURCES_LIST, CONFIG_YML]
    for file_path in required_files:
        if not os.path.exists(file_path):
            issues.append(f"Required file missing: {file_path}")
    
    # Validate timeout values
    if not isinstance(DEFAULT_TIMEOUT, tuple) or len(DEFAULT_TIMEOUT) != 2:
        issues.append("DEFAULT_TIMEOUT must be a tuple of (connection_timeout, read_timeout)")
    
    if MAX_RETRIES < 0:
        issues.append("MAX_RETRIES must be non-negative")
    
    if RETRY_BACKOFF_FACTOR <= 0:
        issues.append("RETRY_BACKOFF_FACTOR must be positive")
    
    return issues