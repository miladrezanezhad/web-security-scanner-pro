#!/usr/bin/env python3
"""
LiteSpeed Web Server Security Scanner Module.
"""

import re
from typing import Dict, List, Optional
from loguru import logger


class Scanner:
    """LiteSpeed Web Server security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "LiteSpeed Security Analysis"
        
        self.litespeed_paths = {
            'admin': ':7080/',
            'admin_ssl': ':8443/',
            'status': '/status/',
            'phpinfo': '/phpinfo.php',
        }
    
    def run(self) -> Dict:
        """Execute LiteSpeed security tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'litespeed_detected': False,
            'version': None,
            'admin_exposed': False,
            'cache_plugin': False,
            'findings': []
        }
        
        # Detect LiteSpeed
        detection = self._detect_litespeed()
        result['litespeed_detected'] = detection['detected']
        result['version'] = detection.get('version')
        result['cache_plugin'] = detection.get('cache_plugin', False)
        
        if not result['litespeed_detected']:
            result['findings'].append({
                'title': 'No LiteSpeed Web Server detected',
                'severity': 'info',
                'description': 'No evidence of LiteSpeed was found.',
                'recommendation': 'If LiteSpeed is used, ensure it is properly secured.',
                'module': self.module_name,
            })
            return result
        
        # Check admin interface
        if self._check_admin_interface():
            result['admin_exposed'] = True
            result['findings'].append({
                'title': 'LiteSpeed WebAdmin interface is exposed',
                'severity': 'critical',
                'description': 'The LiteSpeed admin interface is accessible.',
                'recommendation': 'Restrict admin access by IP and use strong authentication.',
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 9.0,
            })
        
        # Check cache plugin
        if result['cache_plugin']:
            result['findings'].append({
                'title': 'LiteSpeed Cache plugin detected',
                'severity': 'info',
                'description': 'LiteSpeed Cache plugin is active.',
                'recommendation': 'Ensure the cache plugin is updated to the latest version.',
                'module': self.module_name,
            })
        
        # Version disclosure
        if result['version']:
            result['findings'].append({
                'title': f"LiteSpeed version disclosed: {result['version']}",
                'severity': 'low',
                'description': f"LiteSpeed version {result['version']} is exposed.",
                'recommendation': 'Configure server to hide version information.',
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 3.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _detect_litespeed(self) -> Dict:
        """Detect LiteSpeed server."""
        result = {'detected': False, 'version': None, 'cache_plugin': False}
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        server = resp.headers.get('Server', '')
        match = re.search(r'LiteSpeed(?:/([\d.]+))?', server, re.IGNORECASE)
        if match:
            result['detected'] = True
            result['version'] = match.group(1)
        
        if 'x-litespeed-cache' in resp.headers:
            result['detected'] = True
            result['cache_plugin'] = True
        
        litespeed_indicators = ['litespeed', 'litespeed_cache', 'lscache']
        for indicator in litespeed_indicators:
            if indicator in resp.text.lower():
                result['detected'] = True
                break
        
        return result
    
    def _check_admin_interface(self) -> bool:
        """Check if admin interface is exposed."""
        for name, path in self.litespeed_paths.items():
            if name.startswith('admin'):
                resp = self.browser.get(path)
                if resp and resp.status_code in [200, 401, 403]:
                    return True
        return False