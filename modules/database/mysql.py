#!/usr/bin/env python3
"""
MySQL/MariaDB Security Scanner Module.
Tests for common MySQL security misconfigurations and exposures.

References:
    - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
    - MySQL Security Guidelines: https://dev.mysql.com/doc/refman/8.0/en/security.html
"""

import re
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse
from loguru import logger


class Scanner:
    """MySQL security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize MySQL scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "MySQL Security Analysis"
        
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # Common MySQL ports
        self.mysql_ports = [3306, 3307, 33060, 33061, 33062]
        
        # MySQL error patterns in web responses
        self.error_patterns = [
            r"MySQL server has gone away",
            r"mysql_fetch_array\(\)",
            r"mysql_fetch_assoc\(\)",
            r"mysql_fetch_object\(\)",
            r"mysql_fetch_row\(\)",
            r"mysql_num_rows\(\)",
            r"mysql_query\(\)",
            r"mysql_connect\(\)",
            r"mysql_error\(\)",
            r"SQL syntax.*MySQL",
            r"MySQLSyntaxErrorException",
            r"com.mysql.jdbc",
            r"mysqli_",
            r"Warning.*mysql_",
            r"MySQL server version",
            r"on line \d+.*mysql",
            r"supplied argument is not a valid MySQL",
            r"valid MySQL result",
            r"MySQL result index",
            r"MySQL Error",
            r"MySQL Driver",
            r"MySQL server through socket",
            r"#1267 - Illegal mix of collations",
            r"#1142 - .* command denied to user",
            r"#1146 - Table .* doesn't exist",
            r"#1045 - Access denied for user",
            r"#1044 - Access denied for user",
            r"#1064 - You have an error in your SQL syntax",
        ]
        
        # Common MySQL files
        self.sensitive_files = [
            '/phpmyadmin/',
            '/phpMyAdmin/',
            '/pma/',
            '/myadmin/',
            '/mysql/',
            '/dbadmin/',
            '/sqlmanager/',
            '/mysqlmanager/',
            '/sql/',
            '/database/',
            '/db/',
            '/adminer.php',
            '/mysql/admin/',
        ]
    
    def run(self) -> Dict:
        """
        Execute MySQL security tests.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'mysql_detected': False,
            'ports_open': [],
            'exposed_interfaces': [],
            'error_disclosure': False,
            'findings': []
        }
        
        # Test 1: Check for exposed MySQL ports
        for port in self.mysql_ports:
            if self._check_port(port):
                result['ports_open'].append(port)
                result['mysql_detected'] = True
        
        if result['ports_open']:
            self.findings.append({
                'title': f"MySQL port(s) exposed: {', '.join(map(str, result['ports_open']))}",
                'severity': 'critical',
                'description': (
                    f"MySQL is directly accessible on port(s) {', '.join(map(str, result['ports_open']))}. "
                    "This exposes the database to brute-force attacks and unauthorized access."
                ),
                'recommendation': (
                    "1. Bind MySQL to localhost (127.0.0.1) only\n"
                    "2. Use firewall to block external MySQL access\n"
                    "3. Use strong passwords and consider certificate authentication\n"
                    "4. Disable remote root login\n"
                    "5. Use SSH tunneling for remote access"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 9.0,
                'evidence': f"Open ports: {result['ports_open']}",
            })
        
        # Test 2: Check for MySQL error disclosure in web responses
        if self._check_error_disclosure():
            result['error_disclosure'] = True
            result['mysql_detected'] = True
            
            self.findings.append({
                'title': 'MySQL error messages exposed in web responses',
                'severity': 'high',
                'description': (
                    "The web application displays MySQL error messages to users. "
                    "This can reveal database structure, server version, and potentially "
                    "sensitive information."
                ),
                'recommendation': (
                    "1. Disable display_errors in PHP configuration\n"
                    "2. Implement custom error pages\n"
                    "3. Log errors to file instead of displaying them\n"
                    "4. Use generic error messages for users"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-209',
                'cvss_score': 7.5,
                'evidence': 'MySQL error messages found in HTTP responses',
            })
        
        # Test 3: Check for exposed MySQL management interfaces
        exposed = self._check_management_interfaces()
        if exposed:
            result['exposed_interfaces'] = exposed
            
            for interface in exposed:
                self.findings.append({
                    'title': f"MySQL management interface exposed: {interface['path']}",
                    'severity': 'critical' if interface.get('accessible') else 'high',
                    'description': (
                        f"MySQL management interface found at {interface['path']} "
                        f"(Status: {interface['status']}). "
                        "This provides direct database access through a web interface."
                    ),
                    'recommendation': (
                        "1. Remove phpMyAdmin if not needed\n"
                        "2. Restrict access by IP address\n"
                        "3. Enable two-factor authentication\n"
                        "4. Use strong passwords\n"
                        "5. Rename the admin directory to a non-standard name"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 9.5 if interface.get('accessible') else 7.0,
                    'evidence': f"Path: {interface['path']}, Status: {interface['status']}",
                })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} issues")
        return result
    
    def _check_port(self, port: int) -> bool:
        """Check if MySQL port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.hostname, port))
            sock.close()
            
            if result == 0:
                # Try to get MySQL banner
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((self.hostname, port))
                    banner = sock.recv(1024)
                    sock.close()
                    
                    # MySQL handshake starts with packet length + protocol version
                    if len(banner) > 4 and b'mysql' in banner.lower():
                        return True
                    # Even if we can't confirm MySQL, open port is a finding
                    return True
                except:
                    return True  # Port is open
            
            return False
        except:
            return False
    
    def _check_error_disclosure(self) -> bool:
        """Check for MySQL errors in web responses."""
        # Test common paths that might trigger MySQL errors
        test_paths = [
            '/',
            '/index.php?id=1\'',
            '/search.php?q=test\'',
            '/product.php?id=1\'',
            '/category.php?id=1\'',
            '/user.php?id=1\'',
        ]
        
        for path in test_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 500]:
                for pattern in self.error_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        logger.info(f"MySQL error found at {path}: {pattern}")
                        return True
        
        return False
    
    def _check_management_interfaces(self) -> List[Dict]:
        """Check for exposed MySQL management tools."""
        exposed = []
        
        for path in self.sensitive_files:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 401, 403]:
                exposed.append({
                    'path': path,
                    'status': resp.status_code,
                    'accessible': resp.status_code == 200,
                })
        
        return exposed