#!/usr/bin/env python3
"""
DirectAdmin Security Scanner Module.
Tests for common DirectAdmin security misconfigurations and exposures.

References:
    - DirectAdmin Security: https://www.directadmin.com/features.php?id=security
"""

import re
import socket
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from loguru import logger


class Scanner:
    """DirectAdmin security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize DirectAdmin scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "DirectAdmin Security Analysis"
        
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # DirectAdmin default port
        self.da_port = 2222
        
        # DirectAdmin paths
        self.da_paths = [
            '/',
            '/CMD_LOGIN',
            '/login',
            '/admin/',
            '/phpmyadmin/',
            '/webmail/',
            '/roundcube/',
            '/squirrelmail/',
        ]
        
        # Version patterns
        self.version_patterns = [
            r'DirectAdmin\s+([\d.]+)',
            r'Powered by DirectAdmin\s+([\d.]+)',
            r'<title>DirectAdmin\s+([\d.]+)</title>',
        ]
    
    def run(self) -> Dict:
        """
        Execute DirectAdmin security tests.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'directadmin_detected': False,
            'version': None,
            'port_open': False,
            'interface_accessible': False,
            'findings': []
        }
        
        # Check DirectAdmin port
        result['port_open'] = self._check_port()
        
        if result['port_open']:
            result['directadmin_detected'] = True
            
            # Try to access interface
            da_info = self._test_directadmin_interface()
            if da_info:
                result['interface_accessible'] = True
                result['version'] = da_info.get('version')
        
        # Check web paths on standard ports
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            for pattern in self.version_patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    result['directadmin_detected'] = True
                    result['version'] = match.group(1)
                    break
            
            # Check for DirectAdmin login page
            if 'DirectAdmin' in resp.text or 'directadmin' in resp.text.lower():
                result['directadmin_detected'] = True
        
        # Generate findings
        if result['port_open']:
            self.findings.append({
                'title': 'DirectAdmin port (2222) is exposed',
                'severity': 'high',
                'description': (
                    "DirectAdmin control panel port 2222 is accessible from the internet. "
                    "This exposes the hosting control panel to brute-force attacks."
                ),
                'recommendation': (
                    "1. Restrict access to port 2222 by IP address\n"
                    "2. Use firewall to limit access\n"
                    "3. Enable brute-force protection (BFM)\n"
                    "4. Use two-factor authentication\n"
                    "5. Change the default port"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
                'evidence': 'Port 2222 is open',
            })
        
        if result['interface_accessible']:
            self.findings.append({
                'title': 'DirectAdmin login interface accessible',
                'severity': 'high',
                'description': (
                    "The DirectAdmin login page is accessible without IP restrictions. "
                    f"{'Version: ' + result['version'] if result['version'] else ''}"
                ),
                'recommendation': (
                    "1. Implement IP-based access control\n"
                    "2. Enable two-factor authentication\n"
                    "3. Use strong admin passwords\n"
                    "4. Monitor login attempts\n"
                    "5. Keep DirectAdmin updated"
                ),
                'module': self.module_name,
                'cvss_score': 7.0,
            })
        
        if result['version']:
            self.findings.append({
                'title': f"DirectAdmin version disclosed: {result['version']}",
                'severity': 'medium',
                'description': f"DirectAdmin version {result['version']} is visible",
                'recommendation': (
                    "1. Update to latest DirectAdmin version\n"
                    "2. Hide version information if possible"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 4.0,
            })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} issues")
        return result
    
    def _check_port(self) -> bool:
        """Check if DirectAdmin port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.hostname, self.da_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _test_directadmin_interface(self) -> Optional[Dict]:
        """
        Test DirectAdmin interface accessibility.
        
        Returns:
            Dict with DA info or None
        """
        # Try accessing via the DA port
        try:
            import requests
            
            da_url = f"https://{self.hostname}:{self.da_port}"
            resp = requests.get(da_url, verify=False, timeout=5)
            
            if resp.status_code in [200, 401]:
                info = {}
                
                for pattern in self.version_patterns:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        info['version'] = match.group(1)
                        break
                
                return info
        except:
            pass
        
        return None