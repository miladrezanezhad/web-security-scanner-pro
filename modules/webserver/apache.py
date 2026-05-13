#!/usr/bin/env python3
"""
Apache HTTP Server Security Scanner Module.
Tests for common Apache security misconfigurations and vulnerabilities.

References:
    - Apache Security Tips: https://httpd.apache.org/docs/2.4/misc/security_tips.html
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
    - CWE-16: Configuration
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """Apache HTTP Server security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Apache Security Analysis"
        
        # Apache-specific paths
        self.apache_paths = {
            'server_status': '/server-status',
            'server_info': '/server-info',
            'icons': '/icons/',
            'manual': '/manual/',
            'cgi_bin': '/cgi-bin/',
            'htaccess': '/.htaccess',
            'htpasswd': '/.htpasswd',
            'apache_config': '/.apache2.conf',
            'httpd_conf': '/httpd.conf',
        }
        
        # Apache error patterns
        self.error_patterns = [
            r'Apache/([\d.]+)',
            r'Apache Server at',
            r'Server at.*Port \d+',
            r'ServerTokens',
            r'httpd\.conf',
            r'\.htaccess',
            r'mod_',
        ]
        
        # Apache mod_status indicators
        self.status_indicators = [
            'Apache Server Status',
            'Server Version',
            'Server Built',
            'Current Time',
            'Restart Time',
            'Server uptime',
            'Total accesses',
            'CPU Usage',
            'requests/sec',
            'requests currently being processed',
            'idle workers',
        ]
        
        # Apache mod_info indicators
        self.info_indicators = [
            'Server Information',
            'Module Name',
            'mod_',
            'Server Settings',
            'Module List',
            'Loaded Modules',
        ]
    
    def run(self) -> Dict:
        """Execute Apache security tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'apache_detected': False,
            'version': None,
            'server_status_exposed': False,
            'server_info_exposed': False,
            'directory_listing': False,
            'trace_method': False,
            'sensitive_files': [],
            'findings': []
        }
        
        # Detect Apache
        detection = self._detect_apache()
        result['apache_detected'] = detection['detected']
        result['version'] = detection.get('version')
        
        if not result['apache_detected']:
            result['findings'].append({
                'title': 'No Apache HTTP Server detected',
                'severity': 'info',
                'description': 'No evidence of Apache was found.',
                'recommendation': 'If Apache is used, ensure it is properly secured.',
                'module': self.module_name,
            })
            return result
        
        # Check server-status
        status_result = self._check_server_status()
        result['server_status_exposed'] = status_result
        
        if status_result:
            self.findings.append({
                'title': 'Apache server-status page is publicly accessible',
                'severity': 'high',
                'description': (
                    "The /server-status page is exposed. This reveals:\n"
                    "- All current requests including URLs and client IPs\n"
                    "- Server uptime and performance statistics\n"
                    "- Active worker threads and their status\n"
                    "- Potentially sensitive request parameters"
                ),
                'recommendation': (
                    "Restrict access in httpd.conf:\n"
                    "<Location /server-status>\n"
                    "    SetHandler server-status\n"
                    "    Require ip 127.0.0.1\n"
                    "</Location>"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
            })
        
        # Check server-info
        info_result = self._check_server_info()
        result['server_info_exposed'] = info_result
        
        if info_result:
            self.findings.append({
                'title': 'Apache server-info page is publicly accessible',
                'severity': 'high',
                'description': (
                    "The /server-info page is exposed. This reveals:\n"
                    "- Apache version and build information\n"
                    "- All loaded modules and their configurations\n"
                    "- Server configuration settings\n"
                    "- Host information"
                ),
                'recommendation': (
                    "Restrict access in httpd.conf:\n"
                    "<Location /server-info>\n"
                    "    SetHandler server-info\n"
                    "    Require ip 127.0.0.1\n"
                    "</Location>"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
            })
        
        # Check TRACE method
        trace_result = self._check_trace_method()
        result['trace_method'] = trace_result
        
        if trace_result:
            self.findings.append({
                'title': 'HTTP TRACE method is enabled',
                'severity': 'medium',
                'description': (
                    "The TRACE method is enabled. This can be used for "
                    "Cross-Site Tracing (XST) attacks to steal cookies."
                ),
                'recommendation': (
                    "Add to httpd.conf:\n"
                    "TraceEnable off"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-749',
                'cvss_score': 5.0,
            })
        
        # Check directory listing
        dir_result = self._check_directory_listing()
        result['directory_listing'] = dir_result
        
        if dir_result:
            self.findings.append({
                'title': 'Directory listing is enabled',
                'severity': 'medium',
                'description': (
                    "Directory listing allows users to browse directory contents."
                ),
                'recommendation': (
                    "Add to httpd.conf or .htaccess:\n"
                    "Options -Indexes"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-548',
                'cvss_score': 4.0,
            })
        
        # Check .htaccess exposure
        htaccess_result = self._check_htaccess_exposure()
        if htaccess_result:
            self.findings.append({
                'title': '.htaccess file is publicly accessible',
                'severity': 'critical',
                'description': 'The .htaccess file can be downloaded, revealing server configuration.',
                'recommendation': (
                    "Add to httpd.conf:\n"
                    "<Files .htaccess>\n"
                    "    Require all denied\n"
                    "</Files>"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _detect_apache(self) -> Dict:
        """Detect Apache HTTP Server."""
        result = {'detected': False, 'version': None}
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        server = resp.headers.get('Server', '')
        match = re.search(r'Apache(?:/([\d.]+))?', server, re.IGNORECASE)
        if match:
            result['detected'] = True
            result['version'] = match.group(1)
            return result
        
        # Check for Apache-specific paths
        for name, path in self.apache_paths.items():
            check = self.browser.head(path)
            if check and check.status_code in [200, 403, 401]:
                result['detected'] = True
                return result
        
        return result
    
    def _check_server_status(self) -> bool:
        """Check if server-status is exposed."""
        resp = self.browser.get('/server-status')
        if resp and resp.status_code == 200:
            for indicator in self.status_indicators:
                if indicator in resp.text:
                    return True
        return False
    
    def _check_server_info(self) -> bool:
        """Check if server-info is exposed."""
        resp = self.browser.get('/server-info')
        if resp and resp.status_code == 200:
            for indicator in self.info_indicators:
                if indicator in resp.text:
                    return True
        return False
    
    def _check_trace_method(self) -> bool:
        """Check if TRACE method is enabled."""
        try:
            import requests
            resp = requests.request('TRACE', self.target_url, timeout=5, verify=False)
            return resp.status_code == 200
        except:
            return False
    
    def _check_directory_listing(self) -> bool:
        """Check if directory listing is enabled."""
        test_paths = ['/images/', '/css/', '/js/', '/uploads/']
        
        for path in test_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                if 'Index of' in resp.text or 'Parent Directory' in resp.text:
                    return True
        return False
    
    def _check_htaccess_exposure(self) -> bool:
        """Check if .htaccess is publicly accessible."""
        resp = self.browser.get('/.htaccess')
        return resp is not None and resp.status_code == 200