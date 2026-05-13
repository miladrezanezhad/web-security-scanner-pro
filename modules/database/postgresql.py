#!/usr/bin/env python3
"""
PostgreSQL Security Scanner Module.
Tests for common PostgreSQL security misconfigurations and exposures.

References:
    - PostgreSQL Security: https://www.postgresql.org/docs/current/security.html
    - OWASP Database Security: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
    - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
import socket
import struct
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from loguru import logger


class Scanner:
    """PostgreSQL security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize PostgreSQL scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "PostgreSQL Security Analysis"
        
        # Parse hostname from URL
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # Default PostgreSQL port
        self.default_port = 5432
        
        # Additional PostgreSQL ports
        self.postgresql_ports = [5432, 5433, 15432, 25432]
        
        # PostgreSQL error patterns in web responses
        self.error_patterns = [
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_.*',
            r'valid PostgreSQL result',
            r'PostgreSQL.*Driver',
            r'org\.postgresql\.',
            r'PG::SyntaxError',
            r'PG::Error',
            r'postgresql',
            r'psql',
            r'pg_query\(\)',
            r'pg_exec\(\)',
            r'pg_connect\(\)',
            r'pg_last_error\(\)',
            r'psycopg2',
            r'SQLSTATE',
            r'ERROR:.*relation.*does not exist',
            r'ERROR:.*column.*does not exist',
            r'ERROR:.*syntax error',
            r'ERROR:.*permission denied',
            r'ERROR:.*authentication failed',
        ]
        
        # PostgreSQL management interfaces
        self.management_interfaces = [
            '/pgadmin/',
            '/pgadmin4/',
            '/phppgadmin/',
            '/phpPgAdmin/',
            '/pga/',
            '/pg/',
            '/postgres/',
            '/postgresql/',
            '/db/',
            '/database/',
            '/adminer.php',
            '/pgweb/',
        ]
        
        # Common PostgreSQL files
        self.sensitive_files = [
            '/pg_hba.conf',
            '/postgresql.conf',
            '/.pgpass',
            '/pg_dump.sql',
            '/postgres_backup.sql',
            '/database.sql',
            '/dump.sql',
        ]
        
        # Authentication methods and their security
        self.auth_methods = {
            'trust': {
                'name': 'Trust',
                'secure': False,
                'severity': 'critical',
                'description': 'No authentication required - anyone can connect',
            },
            'password': {
                'name': 'Password (cleartext)',
                'secure': False,
                'severity': 'high',
                'description': 'Password sent in cleartext over the network',
            },
            'md5': {
                'name': 'MD5',
                'secure': False,
                'severity': 'medium',
                'description': 'MD5 hashing is cryptographically broken',
            },
            'scram-sha-256': {
                'name': 'SCRAM-SHA-256',
                'secure': True,
                'severity': 'info',
                'description': 'Secure challenge-response authentication',
            },
            'cert': {
                'name': 'Certificate',
                'secure': True,
                'severity': 'info',
                'description': 'SSL certificate-based authentication',
            },
            'ident': {
                'name': 'Ident',
                'secure': True,
                'severity': 'info',
                'description': 'OS-level identification (local only)',
            },
            'peer': {
                'name': 'Peer',
                'secure': True,
                'severity': 'info',
                'description': 'OS-level peer authentication (local only)',
            },
            'ldap': {
                'name': 'LDAP',
                'secure': True,
                'severity': 'info',
                'description': 'LDAP directory authentication',
            },
        }
    
    def run(self) -> Dict:
        """
        Execute PostgreSQL security tests.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'postgresql_detected': False,
            'ports_open': [],
            'version': None,
            'auth_method': None,
            'ssl_enabled': False,
            'exposed_interfaces': [],
            'error_disclosure': False,
            'sensitive_files_exposed': [],
            'default_credentials_risk': False,
            'findings': []
        }
        
        # Stage 1: Check for exposed PostgreSQL ports
        for port in self.postgresql_ports:
            pg_info = self._check_port(port)
            if pg_info:
                result['ports_open'].append({
                    'port': port,
                    'info': pg_info,
                })
                result['postgresql_detected'] = True
                
                if pg_info.get('version'):
                    result['version'] = pg_info['version']
                
                if pg_info.get('auth_method'):
                    result['auth_method'] = pg_info['auth_method']
                
                if pg_info.get('ssl_enabled'):
                    result['ssl_enabled'] = True
        
        # Stage 2: Check for PostgreSQL errors in web responses
        if self._check_error_disclosure():
            result['error_disclosure'] = True
            result['postgresql_detected'] = True
        
        # Stage 3: Check for exposed management interfaces
        exposed = self._check_management_interfaces()
        if exposed:
            result['exposed_interfaces'] = exposed
            result['postgresql_detected'] = True
        
        # Stage 4: Check for sensitive files
        sensitive = self._check_sensitive_files()
        if sensitive:
            result['sensitive_files_exposed'] = sensitive
        
        # ===================================================================
        # Generate security findings
        # ===================================================================
        
        # Finding: PostgreSQL port exposed
        if result['ports_open']:
            for port_info in result['ports_open']:
                info = port_info['info']
                
                # Check authentication method
                if info.get('auth_method'):
                    auth = info['auth_method']
                    auth_info = self.auth_methods.get(auth, {})
                    
                    if not auth_info.get('secure', False):
                        self.findings.append({
                            'title': f"PostgreSQL with {auth_info.get('name', auth)} authentication exposed on port {port_info['port']}",
                            'severity': auth_info.get('severity', 'high'),
                            'description': (
                                f"PostgreSQL port {port_info['port']} is accessible with "
                                f"{auth_info.get('name', auth)} authentication. "
                                f"{auth_info.get('description', '')}"
                            ),
                            'recommendation': (
                                "1. Change authentication to SCRAM-SHA-256 in pg_hba.conf\n"
                                "2. Bind PostgreSQL to localhost (127.0.0.1) only\n"
                                "3. Use firewall to restrict database access\n"
                                "4. Enable SSL/TLS for all connections\n"
                                "5. Use strong, unique passwords for all database users"
                            ),
                            'module': self.module_name,
                            'cwe_id': 'CWE-287' if auth == 'trust' else 'CWE-200',
                            'cvss_score': 10.0 if auth == 'trust' else 7.5 if auth == 'password' else 5.0,
                            'evidence': f"Port: {port_info['port']}, Auth: {auth_info.get('name', auth)}",
                            'references': [
                                'https://www.postgresql.org/docs/current/auth-pg-hba-conf.html',
                            ]
                        })
                else:
                    self.findings.append({
                        'title': f"PostgreSQL port {port_info['port']} is exposed",
                        'severity': 'high',
                        'description': (
                            f"PostgreSQL is accessible on port {port_info['port']}. "
                            "This exposes the database to unauthorized access attempts."
                        ),
                        'recommendation': (
                            "1. Bind PostgreSQL to localhost (listen_addresses = 'localhost')\n"
                            "2. Use firewall to block external database access\n"
                            "3. Use SSH tunneling for remote access\n"
                            "4. Implement network-level access controls"
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-200',
                        'cvss_score': 7.5,
                        'evidence': f"Open port: {port_info['port']}",
                    })
        
        # Finding: Version exposed
        if result['version']:
            self.findings.append({
                'title': f"PostgreSQL version disclosed: {result['version']}",
                'severity': 'medium',
                'description': (
                    f"PostgreSQL version {result['version']} is exposed. "
                    "Version information helps attackers identify known vulnerabilities."
                ),
                'recommendation': (
                    "1. Update PostgreSQL to the latest version\n"
                    "2. Check for security advisories at postgresql.org/support/security/\n"
                    "3. Consider hiding version information if possible"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 4.0,
                'evidence': f"Version: {result['version']}",
            })
        
        # Finding: Error disclosure
        if result['error_disclosure']:
            self.findings.append({
                'title': 'PostgreSQL error messages exposed in web responses',
                'severity': 'high',
                'description': (
                    "The web application displays PostgreSQL error messages to users. "
                    "This can reveal database structure, table names, column names, "
                    "and potentially sensitive data."
                ),
                'recommendation': (
                    "1. Configure application to suppress database error details\n"
                    "2. Use custom error pages\n"
                    "3. Log detailed errors server-side only\n"
                    "4. Implement proper exception handling"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-209',
                'cvss_score': 7.5,
            })
        
        # Finding: Management interfaces exposed
        for interface in result['exposed_interfaces']:
            self.findings.append({
                'title': f"PostgreSQL management interface exposed: {interface['path']}",
                'severity': 'critical' if interface.get('accessible') else 'high',
                'description': (
                    f"PostgreSQL management interface found at {interface['path']} "
                    f"(Status: {interface['status']}). "
                    "This provides web-based database administration."
                ),
                'recommendation': (
                    "1. Remove pgAdmin/phpPgAdmin if not actively used\n"
                    "2. Restrict access by IP address\n"
                    "3. Use strong authentication and 2FA\n"
                    "4. Run on non-standard port\n"
                    "5. Use VPN for administrative access"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 9.0 if interface.get('accessible') else 7.0,
                'evidence': f"Path: {interface['path']}, Status: {interface['status']}",
            })
        
        # Finding: Sensitive files exposed
        for file_info in result['sensitive_files_exposed']:
            self.findings.append({
                'title': f"Sensitive PostgreSQL file exposed: {file_info['path']}",
                'severity': 'critical' if 'pg_hba.conf' in file_info['path'] else 'high',
                'description': (
                    f"PostgreSQL configuration file {file_info['path']} is publicly accessible. "
                    "This file may contain authentication settings and database configuration."
                ),
                'recommendation': (
                    "1. Remove configuration files from web root\n"
                    "2. Set proper file permissions (600)\n"
                    "3. Use .htaccess to deny access to .conf files"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.5 if 'pg_hba.conf' in file_info['path'] else 7.5,
                'evidence': f"Status: {file_info['status']}",
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Detected: {result['postgresql_detected']}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _check_port(self, port: int) -> Optional[Dict]:
        """
        Check if PostgreSQL port is open and gather information.
        
        Args:
            port: Port number to check
        
        Returns:
            Dict with PostgreSQL info or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.hostname, port))
            
            if result != 0:
                sock.close()
                return None
            
            # Try to receive PostgreSQL startup packet response
            # PostgreSQL sends an authentication request or error message
            
            # Send an empty/invalid startup packet to get a response
            # Length (4 bytes) + Protocol version (4 bytes) = 8 bytes minimum
            startup_packet = struct.pack('!i', 8) + struct.pack('!i', 196608)  # Protocol 3.0
            sock.send(startup_packet)
            
            response = sock.recv(1024)
            sock.close()
            
            if len(response) == 0:
                return {'version': None, 'auth_method': None, 'ssl_enabled': False}
            
            # Parse the response
            message_type = response[0:1]
            
            info = {
                'version': None,
                'auth_method': None,
                'ssl_enabled': False,
            }
            
            # 'R' = Authentication request
            if message_type == b'R':
                auth_code = struct.unpack('!i', response[5:9])[0]
                
                auth_methods = {
                    0: 'trust',
                    2: 'kerberos_v5',
                    3: 'password',
                    5: 'md5',
                    6: 'scm',
                    7: 'gss',
                    8: 'gss_continue',
                    9: 'sspi',
                    10: 'scram-sha-256',
                }
                
                info['auth_method'] = auth_methods.get(auth_code, f'unknown_{auth_code}')
            
            # 'E' = Error message (often contains version info)
            elif message_type == b'E':
                response_text = response.decode('utf-8', errors='ignore')
                
                # Try to extract version from error
                version_match = re.search(r'PostgreSQL\s+([\d.]+)', response_text)
                if version_match:
                    info['version'] = version_match.group(1)
            
            # 'N' = Notice message
            elif message_type == b'N':
                response_text = response.decode('utf-8', errors='ignore')
                version_match = re.search(r'PostgreSQL\s+([\d.]+)', response_text)
                if version_match:
                    info['version'] = version_match.group(1)
            
            # Check for SSL support
            # Send SSL request
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(3)
                sock2.connect((self.hostname, port))
                
                # SSL request: length (8) + SSL code (80877103)
                ssl_request = struct.pack('!i', 8) + struct.pack('!i', 80877103)
                sock2.send(ssl_request)
                
                ssl_response = sock2.recv(1)
                sock2.close()
                
                # 'S' = SSL supported
                if ssl_response == b'S':
                    info['ssl_enabled'] = True
            except:
                pass
            
            return info
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            logger.debug(f"PostgreSQL port check error: {e}")
            return None
    
    def _check_error_disclosure(self) -> bool:
        """
        Check for PostgreSQL errors in web responses.
        
        Returns:
            True if PostgreSQL errors are disclosed
        """
        test_paths = [
            '/',
            '/index.php?id=1\'',
            '/search.php?q=test\'',
            '/product.php?id=1\'',
            '/api/users?id=1\'',
        ]
        
        for path in test_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 500]:
                for pattern in self.error_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        logger.info(f"PostgreSQL error found at {path}")
                        return True
        
        return False
    
    def _check_management_interfaces(self) -> List[Dict]:
        """
        Check for exposed PostgreSQL management tools.
        
        Returns:
            List of exposed interface information
        """
        exposed = []
        
        for path in self.management_interfaces:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 401, 403, 302]:
                exposed.append({
                    'path': path,
                    'status': resp.status_code,
                    'accessible': resp.status_code == 200,
                })
        
        return exposed
    
    def _check_sensitive_files(self) -> List[Dict]:
        """
        Check for exposed PostgreSQL sensitive files.
        
        Returns:
            List of exposed file information
        """
        exposed = []
        
        for path in self.sensitive_files:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                content_length = len(resp.text) if hasattr(resp, 'text') else 0
                exposed.append({
                    'path': path,
                    'status': resp.status_code,
                    'size': content_length,
                })
        
        return exposed