#!/usr/bin/env python3
"""
Validation utilities for NoMoreWalls
Provides robust validation for proxy nodes and configurations
"""

import json
import base64
import binascii
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urlparse

from config import FAKE_IPS, FAKE_DOMAINS, MIN_PORT, DEFAULT_UUID
from logger import get_logger, log_validation_error

logger = get_logger()

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

def validate_proxy_node(data: Dict[str, Any]) -> List[str]:
    """Validate a proxy node configuration and return list of issues"""
    issues = []
    
    # Check required fields
    if 'server' not in data:
        issues.append("Missing 'server' field")
        return issues
    
    if 'port' not in data:
        issues.append("Missing 'port' field")
        return issues
    
    if 'type' not in data:
        issues.append("Missing 'type' field")
        return issues
    
    # Validate server
    server = data['server']
    if not server or not isinstance(server, str):
        issues.append("Invalid server address")
    elif '.' not in server:
        issues.append("Server address appears to be invalid (no domain separator)")
    elif server in FAKE_IPS:
        issues.append(f"Server address {server} is a known fake IP")
    else:
        # Check for fake domains
        for domain in FAKE_DOMAINS:
            if server == domain.lstrip('.'):
                issues.append(f"Server address {server} is a known fake domain")
                break
            elif server.endswith(domain):
                issues.append(f"Server address {server} uses a known fake domain")
                break
    
    # Validate port
    try:
        port = int(str(data['port']))
        if port < MIN_PORT:
            issues.append(f"Port {port} is too low (minimum {MIN_PORT})")
        elif port > 65535:
            issues.append(f"Port {port} is too high (maximum 65535)")
    except (ValueError, TypeError):
        issues.append(f"Invalid port value: {data['port']}")
    
    # Validate node type
    node_type = data['type']
    valid_types = ['vmess', 'ss', 'ssr', 'trojan', 'vless', 'hysteria2']
    if node_type not in valid_types:
        issues.append(f"Unknown node type: {node_type}")
    
    # Type-specific validations
    if node_type == 'vmess':
        issues.extend(_validate_vmess(data))
    elif node_type == 'ss':
        issues.extend(_validate_ss(data))
    elif node_type == 'ssr':
        issues.extend(_validate_ssr(data))
    elif node_type == 'trojan':
        issues.extend(_validate_trojan(data))
    elif node_type == 'vless':
        issues.extend(_validate_vless(data))
    elif node_type == 'hysteria2':
        issues.extend(_validate_hysteria2(data))
    
    return issues

def _validate_vmess(data: Dict[str, Any]) -> List[str]:
    """Validate VMess-specific configuration"""
    issues = []
    
    if 'uuid' not in data:
        issues.append("VMess node missing UUID")
    elif not data['uuid'] or len(data['uuid']) != len(DEFAULT_UUID):
        issues.append("VMess node has invalid UUID format")
    
    if 'alterId' in data:
        try:
            alter_id = int(data['alterId'])
            if alter_id < 0:
                issues.append("VMess alterId cannot be negative")
        except (ValueError, TypeError):
            issues.append("VMess alterId must be a number")
    
    return issues

def _validate_ss(data: Dict[str, Any]) -> List[str]:
    """Validate Shadowsocks-specific configuration"""
    issues = []
    
    if 'cipher' not in data:
        issues.append("Shadowsocks node missing cipher")
    elif not data['cipher']:
        issues.append("Shadowsocks node has empty cipher")
    
    if 'password' not in data:
        issues.append("Shadowsocks node missing password")
    elif not data['password']:
        issues.append("Shadowsocks node has empty password")
    
    return issues

def _validate_ssr(data: Dict[str, Any]) -> List[str]:
    """Validate ShadowsocksR-specific configuration"""
    issues = []
    
    required_fields = ['protocol', 'cipher', 'obfs', 'password']
    for field in required_fields:
        if field not in data:
            issues.append(f"SSR node missing {field}")
        elif not data[field]:
            issues.append(f"SSR node has empty {field}")
    
    return issues

def _validate_trojan(data: Dict[str, Any]) -> List[str]:
    """Validate Trojan-specific configuration"""
    issues = []
    
    if 'password' not in data:
        issues.append("Trojan node missing password")
    elif not data['password']:
        issues.append("Trojan node has empty password")
    
    return issues

def _validate_vless(data: Dict[str, Any]) -> List[str]:
    """Validate VLESS-specific configuration"""
    issues = []
    
    if 'uuid' not in data:
        issues.append("VLESS node missing UUID")
    elif not data['uuid'] or len(data['uuid']) != len(DEFAULT_UUID):
        issues.append("VLESS node has invalid UUID format")
    
    return issues

def _validate_hysteria2(data: Dict[str, Any]) -> List[str]:
    """Validate Hysteria2-specific configuration"""
    issues = []
    
    if 'password' not in data:
        issues.append("Hysteria2 node missing password")
    elif not data['password']:
        issues.append("Hysteria2 node has empty password")
    
    return issues

def validate_base64(data: str) -> bool:
    """Validate if string is valid base64"""
    try:
        # Add padding if necessary
        padded = data + '=' * ((4-len(data)%4)%4)
        base64.b64decode(padded.encode('utf-8'))
        return True
    except (binascii.Error, UnicodeDecodeError):
        return False

def validate_url(url: str) -> List[str]:
    """Validate URL format and structure"""
    issues = []
    
    if not url:
        issues.append("Empty URL")
        return issues
    
    try:
        parsed = urlparse(url)
        
        if not parsed.scheme:
            issues.append("URL missing scheme")
        elif parsed.scheme not in ['http', 'https', 'file']:
            issues.append(f"Unsupported URL scheme: {parsed.scheme}")
        
        if not parsed.netloc and parsed.scheme != 'file':
            issues.append("URL missing domain")
        
    except Exception as e:
        issues.append(f"Invalid URL format: {str(e)}")
    
    return issues

def validate_proxy_url(url: str) -> List[str]:
    """Validate proxy URL format"""
    issues = []
    
    if not url:
        issues.append("Empty proxy URL")
        return issues
    
    try:
        if '://' not in url:
            issues.append("Proxy URL missing protocol separator")
            return issues
        
        protocol, _ = url.split('://', 1)
        
        if not protocol.isascii():
            issues.append(f"Proxy protocol contains non-ASCII characters: {protocol}")
        
        valid_protocols = ['vmess', 'ss', 'ssr', 'trojan', 'vless', 'hysteria2', 'hy2']
        if protocol not in valid_protocols:
            issues.append(f"Unknown proxy protocol: {protocol}")
    
    except Exception as e:
        issues.append(f"Error parsing proxy URL: {str(e)}")
    
    return issues

def safe_validate_json(data: str) -> Optional[Dict[str, Any]]:
    """Safely validate and parse JSON data"""
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        log_validation_error("JSON data", str(e))
        return None
    except Exception as e:
        log_validation_error("JSON data", f"Unexpected error: {str(e)}")
        return None

def validate_config_file(file_path: str) -> List[str]:
    """Validate configuration file exists and is readable"""
    issues = []
    
    import os
    
    if not os.path.exists(file_path):
        issues.append(f"Configuration file not found: {file_path}")
        return issues
    
    if not os.path.isfile(file_path):
        issues.append(f"Path is not a file: {file_path}")
        return issues
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read(1)  # Try to read first character
    except PermissionError:
        issues.append(f"No permission to read file: {file_path}")
    except UnicodeDecodeError:
        issues.append(f"File encoding error: {file_path}")
    except Exception as e:
        issues.append(f"Error reading file {file_path}: {str(e)}")
    
    return issues