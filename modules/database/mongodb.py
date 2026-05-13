#!/usr/bin/env python3
"""
MongoDB Security Scanner Module.
Tests for common MongoDB security misconfigurations and exposures.

References:
    - MongoDB Security Checklist: https://www.mongodb.com/docs/manual/administration/security-checklist/
    - CWE-306: Missing Authentication for Critical Function
"""

import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse
from loguru import logger


class Scanner:
    """MongoDB security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize MongoDB scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "MongoDB Security Analysis"
        
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # Default MongoDB port
        self.mongo_port = 27017
        
        # Additional MongoDB ports
        self.mongo_ports = [27017, 27018, 27019, 28017]
    
    def run(self) -> Dict:
        """
        Execute MongoDB security tests.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'mongodb_accessible': False,
            'ports_open': [],
            'unauthorized_access': False,
            'version': None,
            'findings': []
        }
        
        # Check MongoDB ports
        for port in self.mongo_ports:
            if self._check_port(port):
                result['ports_open'].append(port)
        
        # Test MongoDB connection
        if result['ports_open']:
            mongo_info = self._test_mongodb_connection()
            
            if mongo_info:
                result['mongodb_accessible'] = True
                result['version'] = mongo_info.get('version')
                result['unauthorized_access'] = mongo_info.get('unauthorized', False)
                
                if mongo_info.get('unauthorized'):
                    self.findings.append({
                        'title': 'MongoDB accessible without authentication',
                        'severity': 'critical',
                        'description': (
                            "MongoDB is accessible without authentication. "
                            "Attackers can read, modify, and delete all databases and collections. "
                            "Thousands of MongoDB instances have been compromised and held for ransom due to this misconfiguration."
                        ),
                        'recommendation': (
                            "1. Enable authentication (SCRAM-SHA-256)\n"
                            "2. Bind MongoDB to localhost or private network\n"
                            "3. Enable access control and create user accounts\n"
                            "4. Use TLS/SSL for connections\n"
                            "5. Implement network-level access controls\n"
                            "6. Regularly audit MongoDB logs"
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-306',
                        'cvss_score': 10.0,
                        'evidence': 'MongoDB accepted unauthenticated connection',
                        'references': [
                            'https://www.mongodb.com/docs/manual/administration/security-checklist/',
                            'https://www.cisa.gov/uscert/ncas/alerts/TA17-021A',
                        ]
                    })
                
                if mongo_info.get('version'):
                    self.findings.append({
                        'title': f"MongoDB version exposed: {mongo_info['version']}",
                        'severity': 'medium',
                        'description': (
                            f"MongoDB version {mongo_info['version']} is exposed. "
                            "Version information helps attackers identify known vulnerabilities."
                        ),
                        'recommendation': (
                            "1. Restrict access to buildInfo command\n"
                            "2. Keep MongoDB updated to latest stable version\n"
                            "3. Subscribe to MongoDB security alerts"
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-200',
                        'cvss_score': 4.0,
                    })
            else:
                self.findings.append({
                    'title': f"MongoDB port(s) open: {', '.join(map(str, result['ports_open']))}",
                    'severity': 'high',
                    'description': (
                        f"MongoDB port(s) {', '.join(map(str, result['ports_open']))} are open "
                        "but connection test failed. May still be vulnerable."
                    ),
                    'recommendation': 'Verify MongoDB configuration and authentication settings',
                    'module': self.module_name,
                    'cvss_score': 7.0,
                })
        else:
            # Check for MongoDB HTTP interface (port 28017)
            self._check_http_interface(result)
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} issues")
        return result
    
    def _check_port(self, port: int) -> bool:
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.hostname, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _test_mongodb_connection(self) -> Optional[Dict]:
        """
        Test MongoDB connection and authentication.
        
        Returns:
            Dict with MongoDB info or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.hostname, self.mongo_port))
            
            # Send MongoDB handshake
            # MongoDB Wire Protocol - isMaster command
            import struct
            
            # Simple isMaster command
            msg = b'\x3f\x00\x00\x00'  # Message length
            msg += b'\x00\x00\x00\x00'  # Request ID
            msg += b'\x00\x00\x00\x00'  # Response to
            msg += b'\xd4\x07\x00\x00'  # Opcode (2004 = OP_QUERY)
            msg += b'\x00\x00\x00\x00'  # Flags
            msg += b'admin.$cmd\x00'    # Collection name
            msg += b'\x00\x00\x00\x00'  # Number to skip
            msg += b'\x01\x00\x00\x00'  # Number to return
            
            # Query document
            query = b'\x1e\x00\x00\x00'  # Document length
            query += b'\x10'             # Type: Int32
            query += b'isMaster\x00'     # Key
            query += b'\x01\x00\x00\x00' # Value: 1
            query += b'\x00'             # End of document
            
            msg = msg[:4] + struct.pack('<i', len(msg) - 4 + len(query)) + msg[8:] + query
            
            sock.send(msg)
            response = sock.recv(4096)
            sock.close()
            
            if len(response) > 0:
                # Parse response for version info
                response_str = response.decode('utf-8', errors='ignore')
                
                version = None
                import re
                version_match = re.search(r'version.*?([\d.]+)', response_str)
                if version_match:
                    version = version_match.group(1)
                
                # Check if authentication required
                # If we got a response, likely unauthenticated
                return {
                    'unauthorized': True,
                    'version': version,
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"MongoDB test error: {e}")
            return None
    
    def _check_http_interface(self, result: Dict):
        """Check for MongoDB HTTP interface."""
        resp = self.browser.get(f':28017')
        if resp and resp.status_code == 200:
            result['ports_open'].append(28017)
            
            self.findings.append({
                'title': 'MongoDB HTTP interface exposed',
                'severity': 'high',
                'description': (
                    "MongoDB HTTP status interface is accessible on port 28017. "
                    "This exposes server statistics, logs, and potentially sensitive data."
                ),
                'recommendation': (
                    "1. Disable the HTTP interface (--nohttpinterface)\n"
                    "2. Bind to localhost only\n"
                    "3. Use firewall to block port 28017"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
                'evidence': 'HTTP 200 response on port 28017',
            })