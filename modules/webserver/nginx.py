#!/usr/bin/env python3
"""
Nginx Web Server Security Scanner Module.
Tests for common Nginx security misconfigurations and vulnerabilities.

References:
    - Nginx Security: https://nginx.org/en/docs/control.html
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
"""

import re
from typing import Dict, List, Optional
from loguru import logger


class Scanner:
    """Nginx web server security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Nginx Security Analysis"
        
        self.nginx_paths = {
            'status': '/nginx-status',
            'status_alt': '/nginx_status',
            'stub_status': '/stub_status',
            'dashboard': '/dashboard/',
        }
        
        self.version_patterns = [
            r'nginx/([\d.]+)',
            r'nginx version:.*?([\d.]+)',
        ]
    
    def run(self) -> Dict:
        """Execute Nginx security tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'nginx_detected': False,
            'version': None,
            'status_exposed': False,
            'findings': []
        }
        
        # Detect Nginx
        detection = self._detect_nginx()
        result['nginx_detected'] = detection['detected']
        result['version'] = detection.get('version')
        
        if not result['nginx_detected']:
            result['findings'].append({
                'title': 'No Nginx web server detected',
                'severity': 'info',
                'description': 'No evidence of Nginx was found.',
                'recommendation': 'If Nginx is used, ensure it is properly secured.',
                'module': self.module_name,
            })
            return result
        
        # Check stub_status
        if self._check_stub_status():
            result['status_exposed'] = True
            self.findings.append({
                'title': 'Nginx stub_status page is publicly accessible',
                'severity': 'medium',
                'description': (
                    "The stub_status page exposes active connections, "
                    "accepted connections, and request statistics."
                ),
                'recommendation': (
                    "Restrict access in nginx.conf:\n"
                    "location /nginx-status {\n"
                    "    stub_status on;\n"
                    "    allow 127.0.0.1;\n"
                    "    deny all;\n"
                    "}"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
            })
        
        # Version disclosure
        if result['version']:
            self.findings.append({
                'title': f"Nginx version disclosed: {result['version']}",
                'severity': 'low',
                'description': f"Nginx version {result['version']} is exposed.",
                'recommendation': "Set 'server_tokens off;' in nginx.conf",
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 3.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _detect_nginx(self) -> Dict:
        """Detect Nginx server."""
        result = {'detected': False, 'version': None}
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        server = resp.headers.get('Server', '')
        match = re.search(r'nginx(?:/([\d.]+))?', server, re.IGNORECASE)
        if match:
            result['detected'] = True
            result['version'] = match.group(1)
        
        return result
    
    def _check_stub_status(self) -> bool:
        """Check if stub_status is exposed."""
        for name, path in self.nginx_paths.items():
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                if 'Active connections' in resp.text or 'server accepts' in resp.text:
                    return True
        return False