#!/usr/bin/env python3
"""
Redis Security Scanner Module.
Tests for common Redis security misconfigurations and exposures.

References:
    - Redis Security: https://redis.io/topics/security
    - CWE-200: Exposure of Sensitive Information
"""

import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse
from loguru import logger


class Scanner:
    """Redis security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize Redis scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Redis Security Analysis"
        
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # Default Redis port
        self.redis_port = 6379
        
        # Redis commands to test
        self.test_commands = [
            b'PING\r\n',
            b'INFO\r\n',
            b'CONFIG GET *\r\n',
            b'CLIENT LIST\r\n',
            b'DBSIZE\r\n',
            b'KEYS *\r\n',
        ]
    
    def run(self) -> Dict:
        """
        Execute Redis security tests.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'redis_accessible': False,
            'authenticated': True,
            'version': None,
            'dangerous_commands': [],
            'key_count': None,
            'findings': []
        }
        
        # Test Redis connection
        redis_info = self._test_redis_connection()
        
        if redis_info:
            result['redis_accessible'] = True
            result['authenticated'] = redis_info.get('authenticated', False)
            result['version'] = redis_info.get('version')
            result['key_count'] = redis_info.get('key_count')
            
            # Unauthenticated access
            if not redis_info.get('authenticated'):
                self.findings.append({
                    'title': 'Redis accessible without authentication',
                    'severity': 'critical',
                    'description': (
                        "Redis is accessible without password authentication. "
                        "This allows unauthorized users to read, modify, and delete all data."
                    ),
                    'recommendation': (
                        "1. Set a strong password using 'requirepass' in redis.conf\n"
                        "2. Bind Redis to localhost (127.0.0.1) only\n"
                        "3. Use 'rename-command' to disable dangerous commands\n"
                        "4. Enable protected-mode\n"
                        "5. Use firewall to restrict access"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-306',
                    'cvss_score': 10.0,
                    'evidence': 'Redis accepted unauthenticated commands',
                })
            
            # Dangerous commands available
            if redis_info.get('dangerous_commands'):
                result['dangerous_commands'] = redis_info['dangerous_commands']
                self.findings.append({
                    'title': 'Dangerous Redis commands available',
                    'severity': 'high',
                    'description': (
                        f"The following dangerous commands are not disabled: "
                        f"{', '.join(redis_info['dangerous_commands'])}"
                    ),
                    'recommendation': (
                        "Rename or disable dangerous commands:\n"
                        "rename-command FLUSHDB \"\"\n"
                        "rename-command FLUSHALL \"\"\n"
                        "rename-command DEBUG \"\"\n"
                        "rename-command CONFIG \"\"\n"
                        "rename-command SHUTDOWN \"\"\n"
                        "rename-command KEYS \"\""
                    ),
                    'module': self.module_name,
                    'cvss_score': 7.5,
                    'evidence': f"Available: {redis_info['dangerous_commands']}",
                })
            
            # Exposed INFO
            if redis_info.get('info_exposed'):
                self.findings.append({
                    'title': 'Redis INFO command exposes system details',
                    'severity': 'medium',
                    'description': (
                        "The INFO command reveals Redis version, memory usage, "
                        "connected clients, and configuration details."
                    ),
                    'recommendation': (
                        "Restrict access to INFO command or use rename-command"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 5.0,
                    'evidence': f"Redis version: {redis_info.get('version')}",
                })
        else:
            # Redis not accessible - check if port is open
            if self._check_port():
                self.findings.append({
                    'title': 'Redis port is open but connection failed',
                    'severity': 'medium',
                    'description': 'Port 6379 is open but Redis handshake failed',
                    'recommendation': 'Verify Redis configuration and firewall rules',
                    'module': self.module_name,
                    'cvss_score': 3.0,
                })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} issues")
        return result
    
    def _check_port(self) -> bool:
        """Check if Redis port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.hostname, self.redis_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _test_redis_connection(self) -> Optional[Dict]:
        """
        Test Redis connection and authentication.
        
        Returns:
            Dict with Redis info or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.hostname, self.redis_port))
            
            # Send PING
            sock.send(b'PING\r\n')
            response = sock.recv(1024)
            
            if b'PONG' not in response:
                # Check if authentication required
                if b'NOAUTH' in response or b'ERR' in response:
                    sock.close()
                    return {
                        'authenticated': True,
                        'info_exposed': False,
                    }
                sock.close()
                return None
            
            # Unauthenticated access confirmed
            info = {
                'authenticated': False,
                'info_exposed': False,
                'version': None,
                'key_count': None,
                'dangerous_commands': [],
            }
            
            # Get INFO
            sock.send(b'INFO\r\n')
            info_response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            if 'redis_version' in info_response:
                info['info_exposed'] = True
                
                # Extract version
                version_match = re.search(r'redis_version:([\d.]+)', info_response)
                if version_match:
                    info['version'] = version_match.group(1)
            
            # Try DBSIZE
            sock.send(b'DBSIZE\r\n')
            dbsize_response = sock.recv(1024).decode('utf-8', errors='ignore')
            try:
                info['key_count'] = int(dbsize_response.strip().split('\r\n')[0].strip(':'))
            except:
                pass
            
            # Test dangerous commands
            dangerous_commands = {
                'CONFIG': b'CONFIG GET dir\r\n',
                'FLUSHDB': b'FLUSHDB\r\n',
                'SHUTDOWN': b'SHUTDOWN\r\n',
            }
            
            for cmd_name, cmd_bytes in dangerous_commands.items():
                sock.send(cmd_bytes)
                resp = sock.recv(1024)
                if b'ERR' not in resp and b'unknown command' not in resp:
                    info['dangerous_commands'].append(cmd_name)
            
            sock.close()
            return info
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            logger.debug(f"Redis test error: {e}")
            return None