#!/usr/bin/env python3
"""
cPanel/WHM Security Scanner Module.
Tests for common cPanel security misconfigurations and exposures.

References:
    - cPanel Security: https://docs.cpanel.net/knowledge-base/security/
    - OWASP: Testing for Admin Interfaces
"""

import re
import socket
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from loguru import logger


class Scanner:
    """cPanel/WHM security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize cPanel scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "cPanel/WHM Security Analysis"
        
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # cPanel ports and paths
        self.cpanel_ports = {
            2082: 'cPanel (HTTP)',
            2083: 'cPanel (HTTPS)',
            2086: 'WHM (HTTP)',
            2087: 'WHM (HTTPS)',
            2095: 'Webmail (HTTP)',
            2096: 'Webmail (HTTPS)',
        }
        
        self.cpanel_paths = [
            '/cpanel',
            '/cpanel/',
            '/webmail',
            '/webmail/',
            '/whm',
            '/whm/',
            '/cpanelwebcall/',
            '/cpsess',
            '/.cpanel',
            '/cgi-sys/',
            '/cgi-bin/',
        ]
        
        self.sensitive_files = [
            '/.cpanel.yml',
            '/.cpanel/nvdata.json',
            '/cpanel.tar.gz',
            '/cpanel_backup.tar.gz',
            '/whm_backup.tar.gz',
        ]
        
        # cPanel version detection patterns
        self.version_patterns = [
            r'cPanel\s+&amp;\s+WHM\s+([\d.]+)',
            r'cPanel\s+([\d.]+)',
            r'Powered by cPanel\s+([\d.]+)',
            r'<title>cPanel.*?([\d.]+)</title>',
        ]
    
    def run(self) -> Dict:
        """
        Execute cPanel security tests.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'cpanel_detected': False,
            'version': None,
            'open_ports': [],
            'exposed_paths': [],
            'whm_accessible': False,
            'findings': []
        }
        
        # Test 1: Check cPanel ports
        for port, service in self.cpanel_ports.items():
            if self._check_port(port):
                result['open_ports'].append({
                    'port': port,
                    'service': service,
                })
                result['cpanel_detected'] = True
        
        # Test 2: Check web paths
        for path in self.cpanel_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 301, 302, 401, 403]:
                result['exposed_paths'].append({
                    'path': path,
                    'status': resp.status_code,
                })
                result['cpanel_detected'] = True
                
                # Check for version info
                if resp.status_code == 200:
                    for pattern in self.version_patterns:
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        if match:
                            result['version'] = match.group(1)
                            break
                    
                    # Check for WHM
                    if 'whm' in resp.text.lower() or 'web host manager' in resp.text.lower():
                        if path in ['/whm', '/whm/']:
                            result['whm_accessible'] = True
        
        # Test 3: Check sensitive files
        for file_path in self.sensitive_files:
            resp = self.browser.get(file_path)
            if resp and resp.status_code == 200:
                self.findings.append({
                    'title': f'Sensitive cPanel file exposed: {file_path}',
                    'severity': 'critical',
                    'description': (
                        f"cPanel configuration file {file_path} is publicly accessible. "
                        "This file may contain sensitive configuration data."
                    ),
                    'recommendation': (
                        "1. Restrict access to .cpanel directory\n"
                        "2. Add the following to .htaccess:\n"
                        "   <FilesMatch \"\.(yml|json|tar.gz)$\">\n"
                        "       Order deny,allow\n"
                        "       Deny from all\n"
                        "   </FilesMatch>\n"
                        "3. Move backups outside web root"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 9.0,
                    'evidence': f"File accessible at {file_path}",
                })
        
        # Generate findings
        if result['open_ports']:
            port_list = ', '.join([f"{p['port']} ({p['service']})" for p in result['open_ports']])
            self.findings.append({
                'title': f'cPanel ports exposed: {port_list}',
                'severity': 'high',
                'description': (
                    f"cPanel/WHM services are directly accessible on ports: {port_list}. "
                    "This exposes administrative interfaces to the internet."
                ),
                'recommendation': (
                    "1. Restrict cPanel/WHM port access by IP (using firewall)\n"
                    "2. Use VPN for administrative access\n"
                    "3. Consider using CloudFlare or similar for DDoS protection\n"
                    "4. Enable two-factor authentication"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
                'evidence': f"Open ports: {port_list}",
            })
        
        if result['whm_accessible']:
            self.findings.append({
                'title': 'WHM (Web Host Manager) web interface exposed',
                'severity': 'critical',
                'description': (
                    "WHM interface is accessible via web. WHM provides full server "
                    "administration capabilities including account creation, service "
                    "management, and root-level access."
                ),
                'recommendation': (
                    "1. Restrict WHM access to specific IP addresses\n"
                    "2. Enable two-factor authentication for WHM\n"
                    "3. Use a non-standard port for WHM\n"
                    "4. Implement rate limiting on login attempts\n"
                    "5. Monitor WHM access logs for suspicious activity"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 9.5,
                'evidence': 'WHM interface accessible via web',
            })
        
        if result['version']:
            self.findings.append({
                'title': f'cPanel version disclosed: {result["version"]}',
                'severity': 'medium',
                'description': (
                    f"cPanel version {result['version']} is publicly visible. "
                    "Version information helps attackers identify known vulnerabilities."
                ),
                'recommendation': (
                    "1. Update to the latest cPanel version\n"
                    "2. Check for known CVEs for your version\n"
                    "3. Configure cPanel to hide version information"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 4.0,
                'evidence': f"Version: {result['version']}",
            })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} issues")
        return result
    
    def _check_port(self, port: int) -> bool:
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.hostname, port))
            sock.close()
            return result == 0
        except:
            return False