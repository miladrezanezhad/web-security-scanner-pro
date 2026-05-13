#!/usr/bin/env python3
"""
Microsoft IIS Security Scanner Module.
Tests for common IIS security misconfigurations and vulnerabilities.

References:
    - IIS Security: https://docs.microsoft.com/en-us/iis/
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
"""

import re
from typing import Dict, List, Optional
from loguru import logger


class Scanner:
    """Microsoft IIS security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "IIS Security Analysis"
        
        self.iis_paths = {
            'start': '/iisstart.htm',
            'welcome': '/welcome.png',
            'trace': '/trace.axd',
            'aspnet_client': '/aspnet_client/',
            'web_config': '/web.config',
            'owa': '/owa/',
            'ecp': '/ecp/',
            'ews': '/ews/',
            'autodiscover': '/autodiscover/',
            'powershell': '/powershell/',
        }
        
        self.iis_versions = {
            '10.0': 'IIS 10.0 (Windows Server 2016/2019/2022)',
            '8.5': 'IIS 8.5 (Windows Server 2012 R2)',
            '8.0': 'IIS 8.0 (Windows Server 2012)',
            '7.5': 'IIS 7.5 (Windows Server 2008 R2)',
            '7.0': 'IIS 7.0 (Windows Server 2008)',
        }
    
    def run(self) -> Dict:
        """Execute IIS security tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'iis_detected': False,
            'version': None,
            'web_config_exposed': False,
            'trace_axd_exposed': False,
            'exchange_detected': False,
            'findings': []
        }
        
        # Detect IIS
        detection = self._detect_iis()
        result['iis_detected'] = detection['detected']
        result['version'] = detection.get('version')
        
        if not result['iis_detected']:
            result['findings'].append({
                'title': 'No Microsoft IIS detected',
                'severity': 'info',
                'description': 'No evidence of IIS was found.',
                'module': self.module_name,
            })
            return result
        
        # Check web.config exposure
        if self._check_web_config():
            result['web_config_exposed'] = True
            self.findings.append({
                'title': 'web.config file is publicly accessible',
                'severity': 'critical',
                'description': (
                    "The web.config file can be downloaded. This file may contain:\n"
                    "- Database connection strings with credentials\n"
                    "- Application settings and secrets\n"
                    "- Authentication configuration\n"
                    "- Machine keys for encryption"
                ),
                'recommendation': (
                    "Add to web.config:\n"
                    "<security>\n"
                    "    <requestFiltering>\n"
                    "        <hiddenSegments>\n"
                    "            <add segment=\"web.config\" />\n"
                    "        </hiddenSegments>\n"
                    "    </requestFiltering>\n"
                    "</security>"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.5,
            })
        
        # Check trace.axd
        if self._check_trace_axd():
            result['trace_axd_exposed'] = True
            self.findings.append({
                'title': 'ASP.NET tracing is enabled (trace.axd)',
                'severity': 'high',
                'description': (
                    "Trace.axd exposes detailed request information including:\n"
                    "- Session IDs and cookies\n"
                    "- Server variables\n"
                    "- Request data and parameters\n"
                    "- Application state"
                ),
                'recommendation': (
                    "Disable tracing in web.config:\n"
                    "<trace enabled=\"false\" />"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
            })
        
        # Check for Exchange Server
        exchange_result = self._check_exchange()
        if exchange_result:
            result['exchange_detected'] = True
            self.findings.append({
                'title': 'Microsoft Exchange Server detected',
                'severity': 'high',
                'description': (
                    "Exchange Server endpoints detected. Exchange has been targeted "
                    "by critical vulnerabilities (ProxyLogon, ProxyShell)."
                ),
                'recommendation': (
                    "1. Ensure Exchange is fully patched\n"
                    "2. Apply latest Cumulative Updates\n"
                    "3. Use Exchange Health Checker\n"
                    "4. Restrict external access to Exchange endpoints"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 8.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _detect_iis(self) -> Dict:
        """Detect Microsoft IIS."""
        result = {'detected': False, 'version': None}
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        server = resp.headers.get('Server', '')
        match = re.search(r'Microsoft-IIS(?:/([\d.]+))?', server, re.IGNORECASE)
        if match:
            result['detected'] = True
            result['version'] = match.group(1)
            return result
        
        # Check for IIS-specific paths
        for name, path in self.iis_paths.items():
            if name in ['start', 'welcome']:
                check = self.browser.head(path)
                if check and check.status_code == 200:
                    result['detected'] = True
                    return result
        
        # Check for ASP.NET indicators
        asp_headers = ['X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in asp_headers:
            if header in resp.headers:
                result['detected'] = True
                return result
        
        return result
    
    def _check_web_config(self) -> bool:
        """Check if web.config is exposed."""
        resp = self.browser.get('/web.config')
        if resp and resp.status_code == 200:
            content = resp.text[:500]
            return '<?xml' in content or '<configuration>' in content
        return False
    
    def _check_trace_axd(self) -> bool:
        """Check if trace.axd is accessible."""
        resp = self.browser.get('/trace.axd')
        if resp and resp.status_code == 200:
            return 'Trace' in resp.text or 'trace' in resp.text.lower()
        return False
    
    def _check_exchange(self) -> bool:
        """Check for Exchange Server endpoints."""
        exchange_paths = ['/owa/', '/ecp/', '/ews/', '/autodiscover/']
        
        for path in exchange_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 301, 302, 401]:
                return True
        
        return False