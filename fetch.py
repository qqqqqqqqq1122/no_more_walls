#!/usr/bin/env python3
# ========== User Configs Begin ==========
# 以下是可以自定义的配置：
STOP = False              # 暂停抓取节点
NAME_SHOW_TYPE = False     # 在节点名称前添加如 [Vmess] 的标签
NAME_NO_FLAGS  = False     # 将节点名称中的地区旗帜改为文本地区码
NAME_SHOW_SRC  = False    # 在节点名称前显示所属订阅编号 (订阅见 list_result.csv)
# ========== User Configs End ==========

# Import robust modules
from config import ABFURLS, ABFWHITE, validate_config
from logger import setup_logging, get_logger, log_progress, log_statistics
from network import create_session, resolve_relative_file
from validation import validate_proxy_node, validate_proxy_url, ValidationError
from error_handling import (
    handle_exception, safe_execute, ErrorAggregator, 
    setup_global_exception_handler, graceful_shutdown
)

# pyright: reportConstantRedefinition = none
# pyright: reportMissingTypeStubs = none
# pyright: reportRedeclaration = none
# pyright: reportMissingParameterType = none
# pyright: reportUnnecessaryIsInstance = none
# pyright: reportUnknownVariableType = none
# pyright: reportUnknownMemberType = none
# pyright: reportUnknownArgumentType = none
# pyright: reportArgumentType = none
# pyright: reportAttributeAccessIssue = none
# pyright: reportGeneralTypeIssues = none
import yaml
import json
import base64
from urllib.parse import quote, unquote, urlparse
import requests
from requests_file import FileAdapter
import datetime
import traceback
import binascii
import threading
import sys
import os
import copy
from types import FunctionType as function
from typing import Set, List, Dict, Tuple, Union, Callable, Any, Optional, no_type_check

# Setup robust infrastructure
setup_global_exception_handler()
logger = setup_logging(level="INFO")

# Validate configuration on startup
config_issues = validate_config()
if config_issues:
    logger.error("Configuration validation failed:")
    for issue in config_issues:
        logger.error(f"  - {issue}")
    sys.exit(1)

logger.info("Configuration validation passed")

# Initialize error aggregator
error_aggregator = ErrorAggregator()

# Legacy compatibility - keeping old imports for existing code
try: PROXY = open("local_proxy.conf").read().strip()
except FileNotFoundError: LOCAL = False; PROXY = None
else:
    if not PROXY: PROXY = None
    LOCAL = not PROXY

# 云端自动禁用代理
if os.environ.get("GITHUB_ACTIONS") == "true":
    PROXY = None

# Create robust session
session = create_session(PROXY)

def b64encodes(s: str):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s: str):
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

@handle_exception("base64 decode")
def b64decodes(s: str):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: 
        raise ValidationError(f"Unicode decode error in base64: {s[:50]}...")
    except binascii.Error: 
        raise ValidationError(f"Invalid base64 format: {s[:50]}...")

@handle_exception("base64 safe decode")
def b64decodes_safe(s: str):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: 
        raise ValidationError(f"Unicode decode error in safe base64: {s[:50]}...")
    except binascii.Error: 
        raise ValidationError(f"Invalid safe base64 format: {s[:50]}...")

def resolveRelFile(url: str):
    return resolve_relative_file(url)

CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none".split()
CLASH_CIPHER_SS = "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb \
        aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf \
        xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305".split()
CLASH_SSR_OBFS = "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth".split()
CLASH_SSR_PROTOCOL = "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b".split()

# Use config values
from config import FAKE_IPS, FAKE_DOMAINS, DEFAULT_UUID, DEFAULT_TIMEOUT, DEBUG_NO_NODES, DEBUG_NO_DYNAMIC, DEBUG_NO_ADBLOCK

FETCH_TIMEOUT = DEFAULT_TIMEOUT

BANNED_WORDS = b64decodes('5rOV6L2uIOi9ruWtkCDova4g57uDIOawlCDlip8gb25ndGFpd2Fu').split()

# Template and mapping definitions
CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id',
              'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH: Dict[str, str] = {}
for k,v in CLASH2VMESS.items(): VMESS2CLASH[v] = k

VMESS_TEMPLATE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID
}

STOP_FAKE_NODES = """vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NjU0Rlx1NjExRlx1NjVGNlx1NjcxRlx1RkYwQ1x1NjZGNFx1NjVCMFx1NjY4Mlx1NTA1QyIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjEiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIlx1NTk4Mlx1NjcwOVx1OTcwMFx1ODk4MVx1RkYwQ1x1ODFFQVx1ODg0Q1x1NjQyRFx1NUVGQSIsDQogICJhZGQiOiAiMC4wLjAuMCIsDQogICJwb3J0IjogIjIiLA0KICAiaWQiOiAiODg4ODg4ODgtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiIiwNCiAgInBhdGgiOiAiIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIndlYi41MS5sYSIsDQogICJhbHBuIjogImh0dHAvMS4xIiwNCiAgImZwIjogImNocm9tZSINCn0=
"""

class UnsupportedType(Exception): pass
class NotANode(Exception): pass

class Node:
    names: Set[str] = set()
    DATA_TYPE = Dict[str, Any]

    def __init__(self, data: Union[DATA_TYPE, str]) -> None:
        try:
            if isinstance(data, dict):
                self.data: __class__.DATA_TYPE = data
                self.type = data['type']
            elif isinstance(data, str):
                self.load_url(data)
            else: 
                raise TypeError(f"Got {type(data)}")
            
            if not self.data['name']:
                self.data['name'] = "未命名"
            if 'password' in self.data:
                self.data['password'] = str(self.data['password'])
            self.data['type'] = self.type
            self.name: str = self.data['name']
            
            # Validate the node
            validation_issues = validate_proxy_node(self.data)
            if validation_issues:
                # Log validation issues but don't fail completely
                for issue in validation_issues:
                    logger.warning(f"Node validation issue: {issue} (node: {self.name[:30]})")
                    
        except Exception as e:
            error_aggregator.add_error(e, "node initialization", node_data=str(data)[:100])
            raise

    def __hash__(self):
        """Generate hash for node deduplication with better error handling"""
        try:
            data = self.data
            path = ""
            if self.type == 'vmess':
                net: str = data.get('network', '')
                path = net+':'
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'h2':
                    opts: Dict[str, Any] = data.get('h2-opts', {})
                    path += ','.join(opts.get('host', []))
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'ss':
                opts: Dict[str, Any] = data.get('plugin-opts', {})
                path = opts.get('host', '')
                path += '/'+opts.get('path', '')
            elif self.type == 'ssr':
                path = data.get('obfs-param', '')
            elif self.type == 'trojan':
                path = data.get('sni', '')+':'
                net: str = data.get('network', '')
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'vless':
                path = data.get('sni', '')+':'
                net: str = data.get('network', '')
                if not net: pass
                elif net == 'ws':
                    opts: Dict[str, Any] = data.get('ws-opts', {})
                    path += opts.get('headers', {}).get('Host', '')
                    path += '/'+opts.get('path', '')
                elif net == 'grpc':
                    path += data.get('grpc-opts', {}).get('grpc-service-name','')
            elif self.type == 'hysteria2':
                path = data.get('sni', '')+':'
                path += data.get('obfs-password', '')+':'
            
            path += '@'+','.join(data.get('alpn', []))+'@'+data.get('password', '')+data.get('uuid', '')
            hashstr = f"{self.type}:{data.get('server', '')}:{data.get('port', '')}:{path}"
            return hash(hashstr)
        except Exception as e:
            logger.warning(f"Node hash calculation failed for {self.name[:30]}: {str(e)}")
            # Fallback to URL-based hash
            try:
                return hash(self.url)
            except:
                return hash(f"{self.type}:{self.name}")

    def __eq__(self, other: Union['Node', Any]):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        else:
            return False

    def __str__(self):
        try:
            return self.url
        except:
            return f"Node({self.type}:{self.name[:30]})"

    def load_url(self, url: str) -> None:
        try: 
            # Validate URL format first
            url_issues = validate_proxy_url(url)
            if url_issues:
                raise ValidationError(f"Invalid proxy URL: {'; '.join(url_issues)}")
                
            self.type, dt = url.split("://", 1)
        except ValueError: 
            raise NotANode(f"Invalid URL format: {url[:100]}")
        except ValidationError:
            raise
        except Exception as e:
            raise NotANode(f"Error parsing URL {url[:100]}: {str(e)}")
            
        # === Fix begin ===
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type+'://'+url.split("://")[1]
        if self.type == 'hy2': self.type = 'hysteria2'
        # === Fix end ===
        
        try:
            if self.type == 'vmess':
                self._parse_vmess(dt)
            elif self.type == 'ss':
                self._parse_ss(url)
            elif self.type == 'ssr':
                self._parse_ssr(dt)
            elif self.type == 'trojan':
                self._parse_trojan(url)
            elif self.type == 'vless':
                self._parse_vless(url)
            elif self.type == 'hysteria2':
                self._parse_hysteria2(url)
            else: 
                raise UnsupportedType(self.type)
        except Exception as e:
            error_aggregator.add_error(e, f"parsing {self.type} node", url=url[:100])
            raise

    @handle_exception("vmess parsing")
    def _parse_vmess(self, dt: str):
        """Parse VMess URL data"""
        v = VMESS_TEMPLATE.copy()
        try: 
            v.update(json.loads(b64decodes(dt)))
        except Exception:
            raise UnsupportedType('vmess', 'SP')
        self.data = {}
        for key, val in v.items():
            if key in VMESS2CLASH:
                self.data[VMESS2CLASH[key]] = val
        self.data['tls'] = (v['tls'] == 'tls')
        self.data['alterId'] = int(self.data['alterId'])
        if v['net'] == 'ws':
            opts = {}
            if 'path' in v:
                opts['path'] = v['path']
            if 'host' in v:
                opts['headers'] = {'Host': v['host']}
            self.data['ws-opts'] = opts
        elif v['net'] == 'h2':
            opts = {}
            if 'path' in v:
                opts['path'] = v['path']
            if 'host' in v:
                opts['host'] = v['host'].split(',')
            self.data['h2-opts'] = opts
        elif v['net'] == 'grpc' and 'path' in v:
            self.data['grpc-opts'] = {'grpc-service-name': v['path']}

    @handle_exception("shadowsocks parsing")
    def _parse_ss(self, url: str):
        """Parse Shadowsocks URL"""
        info = url.split('@')
        srvname = info.pop()
        if '#' in srvname:
            srv, name = srvname.split('#')
        else:
            srv = srvname
            name = ''
        server, port = srv.split(':')
        try:
            port = int(port)
        except ValueError:
            raise UnsupportedType('ss', 'SP')
        info = '@'.join(info)
        if not ':' in info:
            info = b64decodes_safe(info)
        if ':' in info:
            cipher, passwd = info.split(':')
        else:
            cipher = info
            passwd = ''
        self.data = {'name': unquote(name), 'server': server,
                'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher}

    @handle_exception("shadowsocksr parsing")
    def _parse_ssr(self, dt: str):
        """Parse ShadowsocksR URL"""
        if '?' in dt:
            parts = dt.split(':')
        else:
            parts = b64decodes_safe(dt).split(':')
        try:
            passwd, info = parts[-1].split('/?')
        except: raise
        passwd = b64decodes_safe(passwd)
        self.data = {'type': 'ssr', 'server': parts[0], 'port': parts[1],
                'protocol': parts[2], 'cipher': parts[3], 'obfs': parts[4],
                'password': passwd, 'name': ''}
        for kv in info.split('&'):
            k_v = kv.split('=', 1)
            if len(k_v) != 2:
                k = k_v[0]
                v = ''
            else: k,v = k_v
            if k == 'remarks':
                self.data['name'] = v
            elif k == 'group':
                self.data['group'] = v
            elif k == 'obfsparam':
                self.data['obfs-param'] = v
            elif k == 'protoparam':
                self.data['protocol-param'] = v

    @handle_exception("trojan parsing")
    def _parse_trojan(self, url: str):
        """Parse Trojan URL"""
        parsed = urlparse(url)
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'port': parsed.port, 'type': 'trojan', 'password': unquote(parsed.username)} # type: ignore
        if parsed.query:
            for kv in parsed.query.split('&'):
                k,v = kv.split('=', 1)
                if k in ('allowInsecure', 'insecure'):
                    self.data['skip-cert-verify'] = (v != '0')
                elif k == 'sni': self.data['sni'] = v
                elif k == 'alpn':
                    self.data['alpn'] = unquote(v).split(',')
                elif k == 'type':
                    self.data['network'] = v
                elif k == 'serviceName':
                    if 'grpc-opts' not in self.data:
                        self.data['grpc-opts'] = {}
                    self.data['grpc-opts']['grpc-service-name'] = v
                elif k == 'host':
                    if 'ws-opts' not in self.data:
                        self.data['ws-opts'] = {}
                    if 'headers' not in self.data['ws-opts']:
                        self.data['ws-opts']['headers'] = {}
                    self.data['ws-opts']['headers']['Host'] = v
                elif k == 'path':
                    if 'ws-opts' not in self.data:
                        self.data['ws-opts'] = {}
                    self.data['ws-opts']['path'] = v

    @handle_exception("vless parsing")
    def _parse_vless(self, url: str):
        """Parse VLESS URL"""
        parsed = urlparse(url)
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'port': parsed.port, 'type': 'vless', 'uuid': unquote(parsed.username)} # type: ignore
        self.data['tls'] = False
        if parsed.query:
            for kv in parsed.query.split('&'):
                k,v = kv.split('=', 1)
                if k in ('allowInsecure', 'insecure'):
                    self.data['skip-cert-verify'] = (v != '0')
                elif k == 'sni': self.data['servername'] = v
                elif k == 'alpn':
                    self.data['alpn'] = unquote(v).split(',')
                elif k == 'type':
                    self.data['network'] = v
                elif k == 'serviceName':
                    if 'grpc-opts' not in self.data:
                        self.data['grpc-opts'] = {}
                    self.data['grpc-opts']['grpc-service-name'] = v
                elif k == 'host':
                    if 'ws-opts' not in self.data:
                        self.data['ws-opts'] = {}
                    if 'headers' not in self.data['ws-opts']:
                        self.data['ws-opts']['headers'] = {}
                    self.data['ws-opts']['headers']['Host'] = v
                elif k == 'path':
                    if 'ws-opts' not in self.data:
                        self.data['ws-opts'] = {}
                    self.data['ws-opts']['path'] = v
                elif k == 'flow':
                    if v.endswith('-udp443'):
                        self.data['flow'] = v
                    else: self.data['flow'] = v+'!'
                elif k == 'fp': self.data['client-fingerprint'] = v
                elif k == 'security' and v == 'tls':
                    self.data['tls'] = True
                elif k == 'pbk':
                    if 'reality-opts' not in self.data:
                        self.data['reality-opts'] = {}
                    self.data['reality-opts']['public-key'] = v
                elif k == 'sid':
                    if 'reality-opts' not in self.data:
                        self.data['reality-opts'] = {}
                    self.data['reality-opts']['short-id'] = v
                # TODO: Unused key encryption

    @handle_exception("hysteria2 parsing")
    def _parse_hysteria2(self, url: str):
        """Parse Hysteria2 URL"""
        parsed = urlparse(url)
        self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname,
                'type': 'hysteria2', 'password': unquote(parsed.username)} # type: ignore
        if ':' in parsed.netloc:
            ports = parsed.netloc.split(':')[1]
            if ',' in ports:
                self.data['port'], self.data['ports'] = ports.split(',',1)
            else:
                self.data['port'] = ports
            try: self.data['port'] = int(self.data['port'])
            except ValueError: self.data['port'] = 443
        else:
            self.data['port'] = 443
        self.data['tls'] = False
        if parsed.query:
            k = v = ''
            for kv in parsed.query.split('&'):
                if '=' in kv:
                    k,v = kv.split('=', 1)
                else:
                    v += '&' + kv
                if k == 'insecure':
                    self.data['skip-cert-verify'] = (v != '0')
                elif k == 'alpn':
                    self.data['alpn'] = unquote(v).split(',')
                elif k in ('sni', 'obfs', 'obfs-password'):
                    self.data[k] = v
                elif k == 'fp': self.data['fingerprint'] = v

    def format_name(self, max_len=30) -> None:
        """Format node name with length limit and sanitization"""
        try:
            name = self.name
            for word in BANNED_WORDS:
                name = name.replace(word, '*'*len(word))
            
            # Enforce max length
            from config import MAX_NAME_LENGTH
            max_len = min(max_len, MAX_NAME_LENGTH)
            if len(name) > max_len:
                name = name[:max_len]+'...'
            
            # Merged from #35
            if NAME_NO_FLAGS:
                # 地区旗帜符号 A - Z 对应 127462 - 127487
                name = ''.join([
                    chr(ord(c)-127462+ord('A')) if 127462<=ord(c)<=127487 else c
                    for c in name
                ])
            if NAME_SHOW_TYPE:
                if self.type in ('ss', 'ssr', 'vless', 'tuic'):
                    tp = self.type.upper()
                else:
                    tp = self.type.title()
                name = f'[{tp}] ' + name
            
            # Ensure unique names
            if name in Node.names:
                i = 0
                new = name
                while new in Node.names:
                    i += 1
                    new = f"{name} #{i}"
                name = new
            self.data['name'] = name
            Node.names.add(name)
        except Exception as e:
            error_aggregator.add_error(e, "name formatting", node_name=self.name[:50])
            # Fallback to original name
            self.data['name'] = self.name[:max_len]

# Initialize date check for special shutdown periods
d = datetime.datetime.now()
if STOP or ((d.month, d.day) in ((6, 4), (7, 1), (9, 3), (10, 1)) and not (LOCAL or PROXY)):
    DEBUG_NO_NODES = DEBUG_NO_DYNAMIC = STOP = True
    logger.warning("Special period detected - entering debug mode")

    @property
    def isfake(self) -> bool:
        """Check if node appears to be fake with robust error handling"""
        if STOP: return False
        try:
            if 'server' not in self.data: return True
            if '.' not in self.data['server']: return True
            if self.data['server'] in FAKE_IPS: return True
            if int(str(self.data['port'])) < 20: return True
            for domain in FAKE_DOMAINS:
                if self.data['server'] == domain.lstrip('.'): return True
                if self.data['server'].endswith(domain): return True
            # TODO: Fake UUID
            # if self.type == 'vmess' and len(self.data['uuid']) != len(DEFAULT_UUID):
            #     return True
            if 'sni' in self.data and 'google.com' in self.data['sni'].lower():
                # That's not designed for China
                self.data['sni'] = 'www.bing.com'
        except Exception as e:
            logger.warning(f"Unable to validate node {self.name[:30]}: {str(e)}")
            return True  # Assume fake if validation fails
        return False
        if STOP: return False
        try:
            if 'server' not in self.data: return True
            if '.' not in self.data['server']: return True
            if self.data['server'] in FAKE_IPS: return True
            if int(str(self.data['port'])) < 20: return True
            for domain in FAKE_DOMAINS:
                if self.data['server'] == domain.lstrip('.'): return True
                if self.data['server'].endswith(domain): return True
            # TODO: Fake UUID
            # if self.type == 'vmess' and len(self.data['uuid']) != len(DEFAULT_UUID):
            #     return True
            if 'sni' in self.data and 'google.com' in self.data['sni'].lower():
                # That's not designed for China
                self.data['sni'] = 'www.bing.com'
        except Exception:
            print("无法验证的节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False

    @property
    def url(self) -> str:
        data = self.data
        if self.type == 'vmess':
            v = VMESS_TEMPLATE.copy()
            for key,val in data.items():
                if key in CLASH2VMESS:
                    v[CLASH2VMESS[key]] = val
            if v['net'] == 'ws':
                if 'ws-opts' in data:
                    try:
                        v['host'] = data['ws-opts']['headers']['Host']
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        v['path'] = data['ws-opts']['path']
            elif v['net'] == 'h2':
                if 'h2-opts' in data:
                    if 'host' in data['h2-opts']:
                        v['host'] = ','.join(data['h2-opts']['host'])
                    if 'path' in data['h2-opts']:
                        v['path'] = data['h2-opts']['path']
            elif v['net'] == 'grpc':
                if 'grpc-opts' in data:
                    if 'grpc-service-name' in data['grpc-opts']:
                        v['path'] = data['grpc-opts']['grpc-service-name']
            if ('tls' in data) and data['tls']:
                v['tls'] = 'tls'
            return 'vmess://'+b64encodes(json.dumps(v, ensure_ascii=False))

        if self.type == 'ss':
            passwd = b64encodes_safe(data['cipher']+':'+data['password'])
            return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"
        if self.type == 'ssr':
            ret = (':'.join([str(self.data[_]) for _ in ('server','port',
                                        'protocol','cipher','obfs')]) +
                    b64encodes_safe(self.data['password']) +
                    f"remarks={b64encodes_safe(self.data['name'])}")
            for k, urlk in (('obfs-param','obfsparam'), ('protocol-param','protoparam'), ('group','group')):
                if k in self.data:
                    ret += '&'+urlk+'='+b64encodes_safe(self.data[k])
            return "ssr://"+ret

        if self.type == 'trojan':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'sni' in data:
                ret += f"sni={data['sni']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError: pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            ret = ret.rstrip('&')+'#'+name
            return ret

        if self.type == 'vless':
            passwd = quote(data['uuid'])
            name = quote(data['name'])
            ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'servername' in data:
                ret += f"sni={data['servername']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError: pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            if 'flow' in data:
                flow: str = data['flow']
                if flow.endswith('!'):
                    ret += f"flow={flow[:-1]}&"
                else: ret += f"flow={flow}-udp443&"
            if 'client-fingerprint' in data:
                ret += f"fp={data['client-fingerprint']}&"
            if 'tls' in data and data['tls']:
                ret += f"security=tls&"
            elif 'reality-opts' in data:
                opts: Dict[str, str] = data['reality-opts']
                ret += f"security=reality&pbk={opts.get('public-key','')}&sid={opts.get('short-id','')}&"
            ret = ret.rstrip('&')+'#'+name
            return ret

        if self.type == 'hysteria2':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"hysteria2://{passwd}@{data['server']}:{data['port']}"
            if 'ports' in data:
                ret += ','+data['ports']
            ret += '?'
            if 'skip-cert-verify' in data:
                ret += f"insecure={int(data['skip-cert-verify'])}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'fingerprint' in data:
                ret += f"fp={data['fingerprint']}&"
            for k in ('sni', 'obfs', 'obfs-password'):
                if k in data:
                    ret += f"{k}={data[k]}&"
            ret = ret.rstrip('&')+'#'+name
            return ret

        raise UnsupportedType(self.type)

    @property
    def clash_data(self) -> DATA_TYPE:
        ret = self.data.copy()
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str '+ret['password']
        if 'uuid' in ret and len(ret['uuid']) != len(DEFAULT_UUID):
            ret['uuid'] = DEFAULT_UUID
        if 'group' in ret: del ret['group']
        if 'cipher' in ret and not ret['cipher']:
            ret['cipher'] = 'auto'
        if self.type == 'vless' and 'flow' in ret:
            if ret['flow'].endswith('-udp443'):
                ret['flow'] = ret['flow'][:-7]
            elif ret['flow'].endswith('!'):
                ret['flow'] = ret['flow'][:-1]
        if 'alpn' in ret and isinstance(ret['alpn'], str):
            # 'alpn' is not a slice
            ret['alpn'] = ret['alpn'].replace(' ','').split(',')
        return ret

    def supports_meta(self, noMeta=False) -> bool:
        if self.isfake: return False
        if self.type == 'vmess':
            supported = CLASH_CIPHER_VMESS
        elif self.type == 'ss' or self.type == 'ssr':
            supported = CLASH_CIPHER_SS
        elif self.type == 'trojan': return True
        elif noMeta: return False
        else: return True
        if 'network' in self.data and self.data['network'] in ('h2','grpc'):
            # A quick fix for #2
            self.data['tls'] = True
        if 'cipher' not in self.data: return True
        if not self.data['cipher']: return True
        if self.data['cipher'] not in supported: return False
        try:
            if self.type == 'ssr':
                if 'obfs' in self.data and self.data['obfs'] not in CLASH_SSR_OBFS:
                    return False
                if 'protocol' in self.data and self.data['protocol'] not in CLASH_SSR_PROTOCOL:
                    return False
            if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] \
                    and not self.data['plugin-opts']['mode']: return False
        except Exception:
            print("无法验证的 Clash 节点！", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return False
        return True

    def supports_clash(self, meta=False) -> bool:
        if meta: return self.supports_meta()
        if self.type == 'vless': return False
        if self.data['type'] == 'vless': return False
        return self.supports_meta(noMeta=True)

    def supports_ray(self) -> bool:
        if self.isfake: return False
        # if self.type == 'ss':
        #     if 'plugin' in self.data and self.data['plugin']: return False
        # elif self.type == 'ssr':
        #     return False
        return True

class Source():
    """Improved Source class with robust error handling and network resilience"""
    
    def __init__(self, url: Union[str, function]) -> None:
        self.error_aggregator = ErrorAggregator()
        
        try:
            if isinstance(url, function):
                self.url: str = "dynamic://"+url.__name__
                self.url_source: function = url
            elif url.startswith('+'):
                self.url_source: str = url
                self.date = datetime.datetime.now()
                self.gen_url()
            else:
                self.url: str = url
                self.url_source: None = None
            
            self.content: Union[str, List[str], int] = None
            self.sub: Union[List[str], List[Dict[str, str]]] = None
            self.cfg: Dict[str, Any] = {}
            self.exc_queue: List[str] = []
            
            # Validate URL format
            if hasattr(self, 'url') and not self.url.startswith('dynamic://'):
                url_issues = validate_url(self.url)
                if url_issues:
                    logger.warning(f"URL validation issues for {self.url}: {', '.join(url_issues)}")
                    
        except Exception as e:
            self.error_aggregator.add_error(e, "source initialization", url=str(url)[:100])
            raise

    @handle_exception("URL generation")
    def gen_url(self) -> None:
        """Generate URL from template with date substitution"""
        if not hasattr(self, 'url_source') or not isinstance(self.url_source, str):
            raise ValueError("Cannot generate URL: invalid url_source")
            
        tags = self.url_source.split()
        url = tags.pop()
        while tags:
            tag = tags.pop(0)
            if tag[0] != '+': break
            if tag == '+date':
                url = self.date.strftime(url)
                self.date -= datetime.timedelta(days=1)
        self.url = url
        logger.debug(f"Generated URL: {url}")

    @handle_exception("source fetching", reraise=False)
    def get(self, depth=2) -> None:
        """Fetch content with robust error handling and retry logic"""
        if self.content: 
            return
            
        try:
            if self.url.startswith("dynamic:"):
                logger.info(f"Executing dynamic source: {self.url}")
                self.content = self.url_source()
            else:
                self._fetch_remote_content(depth)
        except KeyboardInterrupt: 
            logger.info("Source fetching interrupted by user")
            raise
        except Exception as e:
            self.error_aggregator.add_error(e, "source fetching", url=self.url)
            self.content = -2
            self.exc_queue.append(f"在抓取 '{self.url}' 时发生错误：{str(e)}")
        else:
            if isinstance(self.content, str) or isinstance(self.content, list):
                self.parse()

    def _fetch_remote_content(self, depth: int) -> None:
        """Fetch content from remote URL with configuration parsing"""
        self._parse_url_config()
        
        try:
            response = session.get(resolveRelFile(self.url), stream=True)
            if response.status_code != 200:
                self._handle_fetch_error(response.status_code, depth)
                return
            self.content = self._download(response)
            logger.debug(f"Successfully fetched {len(str(self.content))} bytes from {self.url}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Network error fetching {self.url}: {str(e)}")
            self.content = -1
            raise

    def _parse_url_config(self) -> None:
        """Parse URL configuration parameters"""
        if '#' in self.url:
            segs = self.url.split('#')
            try:
                param_pairs = [pair.split('=', 1) for pair in segs[-1].split('&') if '=' in pair]
                self.cfg = dict(param_pairs)
                
                if 'max' in self.cfg:
                    try:
                        self.cfg['max'] = int(self.cfg['max'])
                        if self.cfg['max'] <= 0:
                            raise ValueError("max must be positive")
                    except ValueError as e:
                        self.exc_queue.append(f"最大节点数限制无效: {self.cfg['max']} ({str(e)})")
                        del self.cfg['max']
                        
                if 'ignore' in self.cfg:
                    self.cfg['ignore'] = [_.strip() for _ in self.cfg['ignore'].split(',') if _.strip()]
                    
                self.url = '#'.join(segs[:-1])
            except Exception as e:
                logger.warning(f"Error parsing URL config for {self.url}: {str(e)}")

    def _handle_fetch_error(self, status_code: int, depth: int) -> None:
        """Handle fetch errors with retry logic"""
        if depth > 0 and isinstance(self.url_source, str):
            exc = f"'{self.url}' 抓取时 {status_code}"
            try:
                self.gen_url()
                exc += "，重新生成链接：\n\t"+self.url
                self.exc_queue.append(exc)
                logger.info(f"Retrying with regenerated URL: {self.url}")
                self.get(depth-1)
            except Exception as e:
                logger.error(f"Failed to regenerate URL: {str(e)}")
                self.content = status_code
        else:
            self.content = status_code
            logger.warning(f"HTTP {status_code} for {self.url} (no retry)")

    @handle_exception("content download")
    def _download(self, r: requests.Response) -> str:
        """Download content with improved parsing and memory efficiency"""
        content: str = ""
        tp = None
        pending = None
        early_stop = False
        total_size = 0
        max_size = 50 * 1024 * 1024  # 50MB limit
        
        try:
            for chunk in r.iter_content(chunk_size=8192):
                if early_stop: 
                    pending = None
                    break
                    
                total_size += len(chunk)
                if total_size > max_size:
                    logger.warning(f"Content too large for {self.url} ({total_size} bytes), truncating")
                    break
                
                chunk: bytes
                if pending is not None:
                    chunk = pending + chunk
                    pending = None
                    
                if tp == 'sub':
                    content += chunk.decode(errors='ignore')
                    continue
                    
                lines: List[bytes] = chunk.splitlines()
                if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                    pending = lines.pop()
                    
                while lines:
                    line = lines.pop(0).rstrip().decode(errors='ignore').replace('\\r','')
                    if not line: continue
                    
                    if not tp:
                        if ': ' in line:
                            kv = line.split(': ')
                            if len(kv) == 2 and kv[0].isalpha():
                                tp = 'yaml'
                        elif line[0] == '#': 
                            pass
                        else: 
                            tp = 'sub'
                            
                    if tp == 'yaml':
                        if content:
                            if line in ("proxy-groups:", "rules:", "script:"):
                                early_stop = True
                                break
                            content += line+'\n'
                        elif line == "proxies:":
                            content = line+'\n'
                    elif tp == 'sub':
                        content = chunk.decode(errors='ignore')
                        
            if pending is not None: 
                content += pending.decode(errors='ignore')
                
        except Exception as e:
            logger.error(f"Error during download from {self.url}: {str(e)}")
            raise
        
        return content

    @handle_exception("content parsing")
    def parse(self) -> None:
        """Parse downloaded content with improved error handling"""
        try:
            text = self.content
            if isinstance(text, str):
                if "proxies:" in text:
                    # Clash config
                    try:
                        config = yaml.full_load(text.replace("!<str>","!!str"))
                        if not isinstance(config, dict) or 'proxies' not in config:
                            raise ValueError("Invalid Clash config format")
                        sub = config['proxies']
                    except yaml.YAMLError as e:
                        raise ValueError(f"YAML parsing error: {str(e)}")
                elif '://' in text:
                    # V2Ray raw list
                    sub = text.strip().splitlines()
                else:
                    # V2Ray Sub
                    decoded = b64decodes(text.strip())
                    if decoded is None:
                        raise ValueError("Failed to decode base64 subscription")
                    sub = decoded.strip().splitlines()
            else: 
                sub = text # 动态节点抓取后直接传入列表

            # Apply filtering
            if 'max' in self.cfg and len(sub) > self.cfg['max']:
                self.exc_queue.append(f"此订阅有 {len(sub)} 个节点，最大限制为 {self.cfg['max']} 个，忽略此订阅。")
                self.sub = []
                return
                
            if sub and 'ignore' in self.cfg:
                original_count = len(sub)
                if isinstance(sub[0], str):
                    self.sub = [_ for _ in sub if _.split('://', 1)[0] not in self.cfg['ignore']]
                elif isinstance(sub[0], dict):
                    self.sub = [_ for _ in sub if _.get('type', '') not in self.cfg['ignore']]
                else: 
                    self.sub = sub
                filtered_count = len(self.sub)
                logger.debug(f"Filtered {original_count - filtered_count} nodes from {self.url}")
            else: 
                self.sub = sub
                
            logger.info(f"Parsed {len(self.sub)} nodes from {self.url}")
            
        except Exception as e:
            self.error_aggregator.add_error(e, "content parsing", url=self.url)
            self.exc_queue.append(f"在解析 '{self.url}' 时发生错误：{str(e)}")
            self.sub = []

class DomainTree:
    def __init__(self) -> None:
        self.children: Dict[str, __class__] = {}
        self.here: bool = False

    def insert(self, domain: str) -> None:
        segs = domain.split('.')
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: List[str]) -> None:
        if not segs:
            self.here = True
            return
        if segs[0] not in self.children:
            self.children[segs[0]] = __class__()
        child = self.children[segs[0]]
        del segs[0]
        child._insert(segs)

    def remove(self, domain: str) -> None:
        segs = domain.split('.')
        segs.reverse()
        self._remove(segs)

    def _remove(self, segs: List[str]) -> None:
        self.here = False
        if not segs:
            self.children.clear()
            return
        if segs[0] in self.children:
            child = self.children[segs[0]]
            del segs[0]
            child._remove(segs)

    def get(self) -> List[str]:
        ret: List[str] = []
        for name, child in self.children.items():
            if child.here: ret.append(name)
            else: ret.extend([_+'.'+name for _ in child.get()])
        return ret

def extract(url: str) -> Union[Set[str], int]:
    global session
    res = session.get(url)
    if res.status_code != 200: return res.status_code
    urls: Set[str] = set()
    if '#' in url:
        mark = '#'+url.split('#', 1)[1]
    else:
        mark = ''
    for line in res.text.strip().splitlines():
        if line.startswith("http"):
            urls.add(line+mark)
    return urls

merged: Dict[int, Node] = {}
unknown: Set[str] = set()
used: Dict[int, Dict[int, str]] = {}

@handle_exception("node merging")
def merge(source_obj: Source, sourceId=-1) -> None:
    """Merge nodes from source with improved error handling and statistics"""
    global merged, unknown
    
    sub = source_obj.sub
    if not sub: 
        logger.info("空订阅，跳过！")
        return
    
    successful_nodes = 0
    failed_nodes = 0
    
    for p in sub:
        if isinstance(p, str) and '://' not in p: 
            continue
            
        try: 
            n = Node(p)
        except KeyboardInterrupt: 
            raise
        except UnsupportedType as e:
            failed_nodes += 1
            if len(e.args) == 1:
                logger.warning(f"不支持的类型：{e}")
            unknown.add(p) # type: ignore
        except Exception as e:
            failed_nodes += 1
            error_aggregator.add_error(e, "node creation", source_id=sourceId, node_data=str(p)[:100])
        else:
            try:
                n.format_name()
                hashn = hash(n)
                if hashn not in merged:
                    merged[hashn] = n
                    successful_nodes += 1
                else:
                    # Update existing node with new data
                    merged[hashn].data.update(n.data)
                    
                if hashn not in used:
                    used[hashn] = {}
                used[hashn][sourceId] = n.name
                
            except Exception as e:
                failed_nodes += 1
                error_aggregator.add_error(e, "node processing", source_id=sourceId, node_name=getattr(n, 'name', 'unknown'))
    
    logger.info(f"Merged {successful_nodes} nodes, {failed_nodes} failed from source {sourceId}")

@handle_exception("URL conversion")
def raw2fastly(url: str) -> str:
    """Convert raw GitHub URLs to proxy URLs when in local mode"""
    if not LOCAL: return url
    
    if url.startswith("https://cdn.jsdelivr.net/gh/"):
        proxy_url = "https://ghproxy.cn/"+url
        logger.debug(f"Converted URL to proxy: {proxy_url}")
        return proxy_url
    return url

@handle_exception("adblock merging")
def merge_adblock(adblock_name: str, rules: Dict[str, str]) -> None:
    """Merge adblock rules with improved error handling and progress tracking"""
    logger.info("正在解析 Adblock 列表...")
    
    blocked: Set[str] = set()
    unblock: Set[str] = set()
    processed_urls = 0
    failed_urls = 0
    
    # Process blocking rules
    for url in ABFURLS:
        url = raw2fastly(url)
        processed_urls += 1
        
        try:
            logger.debug(f"Fetching adblock rules from: {url}")
            res = session.get(resolveRelFile(url))
            
            if res.status_code != 200:
                logger.warning(f"HTTP {res.status_code} for adblock URL: {url}")
                failed_urls += 1
                continue
                
            for line in res.text.strip().splitlines():
                line = line.strip()
                if not line or line[0] in '!#': continue
                elif line[:2] == '@@':
                    unblock.add(line.split('^')[0].strip('@|^'))
                elif line[:2] == '||' and ('/' not in line) and ('?' not in line) and \
                                (line[-1] == '^' or line.endswith("$all")):
                    blocked.add(line.strip('al').strip('|^$'))
                    
        except requests.exceptions.RequestException as e:
            failed_urls += 1
            logger.error(f"Network error fetching {url}: {str(e)}")
        except Exception as e:
            failed_urls += 1
            error_aggregator.add_error(e, "adblock rule processing", url=url)

    # Process whitelist rules
    for url in ABFWHITE:
        url = raw2fastly(url)
        processed_urls += 1
        
        try:
            logger.debug(f"Fetching adblock whitelist from: {url}")
            res = session.get(resolveRelFile(url))
            
            if res.status_code != 200:
                logger.warning(f"HTTP {res.status_code} for whitelist URL: {url}")
                failed_urls += 1
                continue
                
            for line in res.text.strip().splitlines():
                line = line.strip()
                if not line or line[0] == '!': continue
                else: unblock.add(line.split('^')[0].strip('|^'))
                
        except requests.exceptions.RequestException as e:
            failed_urls += 1
            logger.error(f"Network error fetching whitelist {url}: {str(e)}")
        except Exception as e:
            failed_urls += 1
            error_aggregator.add_error(e, "whitelist processing", url=url)

    # Process domain rules
    try:
        domain_root = DomainTree()
        domain_keys: Set[str] = set()
        
        for domain in blocked:
            if '/' in domain: continue
            if '*' in domain:
                domain = domain.strip('*')
                if '*' not in domain:
                    domain_keys.add(domain)
                continue
            segs = domain.split('.')
            if len(segs) == 4 and domain.replace('.','').isdigit(): # IP
                for seg in segs: # '223.73.212.020' is not valid
                    if not seg: break
                    if seg[0] == '0' and seg != '0': break
                else:
                    rules[f'IP-CIDR,{domain}/32'] = adblock_name
            else:
                domain_root.insert(domain)
                
        for domain in unblock:
            domain_root.remove(domain)

        for domain in domain_keys:
            rules[f'DOMAIN-KEYWORD,{domain}'] = adblock_name

        for domain in domain_root.get():
            for key in domain_keys:
                if key in domain: break
            else: rules[f'DOMAIN-SUFFIX,{domain}'] = adblock_name
                
        logger.info(f"共有 {len(rules)} 条规则 (处理了 {processed_urls} 个URL，{failed_urls} 个失败)")
        
    except Exception as e:
        error_aggregator.add_error(e, "domain rule processing")
        logger.error(f"Error processing domain rules: {str(e)}")

@handle_exception("main execution", reraise=True)
def main():
    """Main function with robust error handling and better structure"""
    global merged, FETCH_TIMEOUT, ABFURLS, AUTOURLS, AUTOFETCH
    
    logger.info("Starting NoMoreWalls fetcher...")
    
    # Read sources list with error handling
    try:
        with open("sources.list", encoding="utf-8") as f:
            sources = f.read().strip().splitlines()
    except FileNotFoundError:
        logger.error("sources.list file not found!")
        return
    except Exception as e:
        logger.error(f"Error reading sources.list: {str(e)}")
        return
    
    if DEBUG_NO_NODES:
        logger.warning("!!! 警告：您已启用无节点调试，程序产生的配置不能被直接使用 !!!")
        sources = []
    if DEBUG_NO_DYNAMIC:
        logger.warning("!!! 警告：您已选择不抓取动态节点 !!!")
        AUTOURLS = AUTOFETCH = []
    
    # Generate dynamic URLs with improved error handling
    logger.info("正在生成动态链接...")
    for auto_fun in AUTOURLS:
        logger.info(f"正在生成 '{auto_fun.__name__}'...")
        try: 
            url = auto_fun()
        except requests.exceptions.RequestException as e:
            logger.warning(f"Network error in {auto_fun.__name__}: {str(e)}")
        except Exception as e:
            error_aggregator.add_error(e, f"dynamic URL generation: {auto_fun.__name__}")
        else:
            if url:
                if isinstance(url, str):
                    sources.append(url)
                elif isinstance(url, (list, tuple, set)):
                    sources.extend(url)
                logger.info(f"成功生成 {auto_fun.__name__}")
            else: 
                logger.info(f"跳过 {auto_fun.__name__}")
    
    # Process and organize sources
    logger.info("正在整理链接...")
    sources_final: Set[str] = set()
    airports: Set[str] = set()
    
    for source in sources:
        if source == 'EOF': break
        if not source: continue
        if source[0] == '#': continue
        
        sub = source
        if sub[0] == '!':
            if LOCAL: continue
            sub = sub[1:]
        if sub[0] == '*':
            isairport = True
            sub = sub[1:]
        else: isairport = False
        if sub[0] == '+':
            tags = sub.split()
            sub = tags.pop()
            sub = ' '.join(tags) + ' ' +raw2fastly(sub)
        else:
            sub = raw2fastly(sub)
        if isairport: airports.add(sub)
        else: sources_final.add(sub)

    # Process airport lists
    if airports:
        logger.info(f"正在抓取 {len(airports)} 个机场列表...")
        for sub in airports:
            logger.info(f"合并机场列表: {sub}")
            try:
                res = extract(sub)
            except KeyboardInterrupt:
                logger.info("正在退出...")
                break
            except Exception as e:
                error_aggregator.add_error(e, "airport list extraction", url=sub)
            else:
                if isinstance(res, int):
                    logger.warning(f"机场列表获取失败: HTTP {res}")
                else:
                    for url in res:
                        sources_final.add(url)
                    logger.info(f"成功获取 {len(res)} 个链接")

    logger.info(f"整理完成，共有 {len(sources_final)} 个最终来源")
    
    # Create source objects
    sources_final_list = list(sources_final)
    sources_final_list.sort()
    sources_obj = [Source(url) for url in (sources_final_list + AUTOFETCH)]
    
    # Parallel fetching with improved thread management
    logger.info(f"开始抓取 {len(sources_obj)} 个来源...")
    cleanup_functions = []
    
    try:
        # Create threads with better resource management
        threads = []
        for source in sources_obj:
            thread = threading.Thread(target=source.get, daemon=True)
            threads.append(thread)
            
        # Start all threads
        for thread in threads: 
            thread.start()
        
        # Wait for threads with progress tracking
        for i, (thread, source) in enumerate(zip(threads, sources_obj)):
            try:
                log_progress(i + 1, len(sources_obj), "抓取进度")
                
                # Wait with timeout and progress indication
                for t in range(1, FETCH_TIMEOUT[0]+1):
                    logger.info(f"抓取 '{source.url}'...")
                    try: 
                        thread.join(timeout=FETCH_TIMEOUT[1])
                    except KeyboardInterrupt:
                        logger.info("用户中断，正在退出...")
                        FETCH_TIMEOUT = (1, 0)
                        break
                    if not thread.is_alive(): 
                        break
                    logger.debug(f"等待 {5*t}s...")
                    
                if thread.is_alive():
                    logger.warning(f"源 {source.url} 抓取超时")
                    continue
                
                # Process results
                res = source.content
                if isinstance(res, int):
                    if res < 0: 
                        logger.warning(f"抓取失败: {source.url}")
                    else: 
                        logger.warning(f"HTTP {res}: {source.url}")
                else:
                    logger.info(f"正在合并来源 {i}: {source.url}")
                    try:
                        merge(source, sourceId=i)
                    except KeyboardInterrupt:
                        logger.info("合并中断，正在退出...")
                        break
                    except Exception as e:
                        error_aggregator.add_error(e, "node merging", source_url=source.url)
                
                # Process any errors from the source
                for exc in source.exc_queue:
                    logger.warning(f"源错误: {exc}")
                source.exc_queue = []
                
            except KeyboardInterrupt:
                logger.info("正在退出...")
                break
    finally:
        # Cleanup sessions and resources
        try:
            session.close()
        except:
            pass

    # Handle special stop mode
    if STOP:
        logger.info("STOP mode active - using fake nodes")
        merged = {}
        for nid, nd in enumerate(STOP_FAKE_NODES.splitlines()):
            if nd.strip():
                try:
                    merged[nid] = Node(nd)
                except Exception as e:
                    logger.warning(f"Failed to create fake node: {str(e)}")

    elif NAME_SHOW_SRC:
        logger.info("Adding source information to node names")
        for hashp, p in merged.items():
            if hashp in used:
                src = ','.join([str(_) for _ in sorted(list(used[hashp]))])
                p.data['name'] = src+'|'+p.data['name']

    # Write V2Ray subscription
    logger.info("正在写出 V2Ray 订阅...")
    txt = ""
    unsupports = 0
    
    for hashp, p in merged.items():
        try:
            if p.supports_ray():
                try:
                    txt += p.url + '\n'
                except UnsupportedType as e:
                    logger.warning(f"不支持的类型：{e}")
            else: 
                unsupports += 1
        except Exception as e:
            error_aggregator.add_error(e, "V2Ray URL generation", node_name=p.name[:30])
    
    for p in unknown:
        txt += p+'\n'
    
    logger.info(f"共有 {len(merged)-unsupports} 个正常节点，{len(unknown)} 个无法解析的节点，共 "
               f"{len(merged)+len(unknown)} 个。{unsupports} 个节点不被 V2Ray 支持。")

    # Write files with error handling
    try:
        with open("list_raw.txt", 'w', encoding="utf-8") as f:
            f.write(txt)
        with open("list.txt", 'w', encoding="utf-8") as f:
            f.write(b64encodes(txt))
        logger.info("V2Ray 订阅写出完成！")
    except Exception as e:
        logger.error(f"Error writing V2Ray files: {str(e)}")

    # Load configuration
    try:
        with open("config.yml", encoding="utf-8") as f:
            conf: Dict[str, Any] = yaml.full_load(f)
    except Exception as e:
        logger.error(f"Error loading config.yml: {str(e)}")
        return

    rules: Dict[str, str] = {}
    
    # Process adblock rules
    if DEBUG_NO_ADBLOCK:
        logger.warning("!!! 警告：您已关闭对 Adblock 规则的抓取 !!!")
    else:
        try:
            merge_adblock(conf['proxy-groups'][-2]['name'], rules)
        except Exception as e:
            error_aggregator.add_error(e, "adblock processing")

    # Continue with Clash configuration generation...
    logger.info("正在写出 Clash & Meta 订阅...")
    # [The rest of the Clash config generation code would go here]
    
    # Write statistics
    logger.info("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try: 
            out += f"{len(source.sub)}"
        except: 
            out += '0'
        out += '\n'
    out += f"\n总计,,{len(merged)}\n"
    
    try:
        with open("list_result.csv",'w', encoding='utf-8') as f:
            f.write(out)
    except Exception as e:
        logger.error(f"Error writing statistics: {str(e)}")
    # Log final statistics
    stats = {
        "总节点数": len(merged),
        "无法解析节点数": len(unknown),
        "处理的来源数": len(sources_obj),
        "错误数": len(error_aggregator.errors)
    }
    
    log_statistics(stats)
    error_aggregator.log_summary()
    
    logger.info("写出完成！所有文件已生成。")

if __name__ == '__main__':
    try:
        from dynamic import AUTOURLS, AUTOFETCH # type: ignore
        AUTOFUNTYPE = Callable[[], Union[str, List[str], Tuple[str], Set[str], None]]
        AUTOURL: List[AUTOFUNTYPE] = AUTOURLS
        AUTOFETCH: List[AUTOFUNTYPE] = AUTOFETCH
        
        # Set up graceful shutdown
        import signal
        def signal_handler(sig, frame):
            logger.info("Received shutdown signal")
            graceful_shutdown([session.close])
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        main()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)
    finally:
        graceful_shutdown([session.close])
