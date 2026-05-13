#!/usr/bin/env python3
"""
Microsoft IIS Security Scanner Module.
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
            'web_config': '/web.config',
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
                'recommendation': 'If IIS is used, ensure it is properly secured.',
                'module': self.module_name,
            })
            return result
        
        # Check web.config exposure
        if self._check_web_config():
            result['web_config_exposed'] = True
            result['findings'].append({
                'title': 'web.config file is publicly accessible',
                'severity': 'critical',
                'description': 'The web.config file can be downloaded, revealing sensitive configuration.',
                'recommendation': 'Block access to web.config via IIS request filtering.',
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.5,
            })
        
        # Check trace.axd
        if self._check_trace_axd():
            result['trace_axd_exposed'] = True
            result['findings'].append({
                'title': 'ASP.NET tracing is enabled (trace.axd)',
                'severity': 'high',
                'description': 'Trace.axd exposes detailed request information.',
                'recommendation': 'Disable tracing in web.config: <trace enabled="false" />',
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
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
        
        for name, path in self.iis_paths.items():
            if name in ['start', 'welcome']:
                check = self.browser.head(path)
                if check and check.status_code == 200:
                    result['detected'] = True
                    return result
        
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