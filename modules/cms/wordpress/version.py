#!/usr/bin/env python3
"""
WordPress Version Detection Module.
Enumerates WordPress version through multiple methods.

References:
    - WPScan Version Detection: https://github.com/wpscanteam/wpscan
"""

import re
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """WordPress version detection scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress Version Detection"
        
        # Version detection sources
        self.version_sources = {
            'meta_generator': {
                'path': '/',
                'pattern': r'<meta\s+name="generator"\s+content="WordPress\s+([\d.]+)',
            },
            'readme': {
                'path': '/readme.html',
                'pattern': r'Version\s+([\d.]+)',
            },
            'rss_feed': {
                'path': '/feed/',
                'pattern': r'<generator>https://wordpress.org/\?v=([\d.]+)</generator>',
            },
            'atom_feed': {
                'path': '/feed/atom/',
                'pattern': r'<generator.*?>https://wordpress.org/\?v=([\d.]+)</generator>',
            },
            'rdf_feed': {
                'path': '/feed/rdf/',
                'pattern': r'<admin:generatorAgent.*?>WordPress/([\d.]+)</admin:generatorAgent>',
            },
            'wp_json': {
                'path': '/wp-json/',
                'pattern': None,  # Complex extraction
            },
            'login_page': {
                'path': '/wp-login.php',
                'pattern': r'ver=([\d.]+)',
            },
            'admin_css': {
                'path': '/wp-admin/css/install.css',
                'pattern': r'ver=([\d.]+)',
            },
            'admin_js': {
                'path': '/wp-admin/js/common.js',
                'pattern': r'ver=([\d.]+)',
            },
            'embed_js': {
                'path': '/wp-includes/js/wp-embed.min.js',
                'pattern': r'ver=([\d.]+)',
            },
        }
        
        # Known version ranges and their security status
        self.version_info = {
            'latest': '6.5.3',
            'supported': ['6.5.x', '6.4.x', '6.3.x'],
            'eol': ['5.x', '4.x', '3.x', '2.x', '1.x'],
        }
    
    def run(self) -> Dict:
        """Execute version detection."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'version': None,
            'version_sources': [],
            'is_latest': False,
            'is_supported': True,
            'is_outdated': False,
            'findings': []
        }
        
        # Try all version sources
        for source_name, source_info in self.version_sources.items():
            version = self._extract_version(source_name, source_info)
            if version:
                result['version_sources'].append({
                    'source': source_name,
                    'version': version,
                })
                
                if not result['version']:
                    result['version'] = version
        
        # Analyze version
        if result['version']:
            result['is_latest'] = result['version'] >= self.version_info['latest']
            result['is_supported'] = any(
                result['version'].startswith(support.replace('.x', ''))
                for support in self.version_info['supported']
            )
            result['is_outdated'] = not result['is_supported']
            
            # Generate findings
            if result['is_outdated']:
                self.findings.append({
                    'title': f"WordPress version {result['version']} is outdated",
                    'severity': 'high',
                    'description': (
                        f"WordPress {result['version']} is no longer supported. "
                        "Outdated versions receive no security updates."
                    ),
                    'recommendation': f"Upgrade to WordPress {self.version_info['latest']} immediately.",
                    'module': self.module_name,
                    'cwe_id': 'CWE-1104',
                    'cvss_score': 7.5,
                })
            elif not result['is_latest']:
                self.findings.append({
                    'title': f"WordPress {result['version']} is not the latest version",
                    'severity': 'medium',
                    'description': (
                        f"Latest version is {self.version_info['latest']}. "
                        "Update to receive security patches."
                    ),
                    'recommendation': f"Update to WordPress {self.version_info['latest']}.",
                    'module': self.module_name,
                    'cvss_score': 4.0,
                })
            
            self.findings.append({
                'title': f"WordPress version disclosed: {result['version']}",
                'severity': 'low',
                'description': f"Version {result['version']} detected via {len(result['version_sources'])} sources.",
                'recommendation': "Consider hiding WordPress version information.",
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 2.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _extract_version(self, source_name: str, source_info: Dict) -> Optional[str]:
        """Extract version from a specific source."""
        resp = self.browser.get(source_info['path'])
        if not resp or resp.status_code != 200:
            return None
        
        if source_info['pattern']:
            match = re.search(source_info['pattern'], resp.text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Special handling for wp-json
        if source_name == 'wp_json':
            return self._extract_from_wp_json(resp.text)
        
        return None
    
    def _extract_from_wp_json(self, response_text: str) -> Optional[str]:
        """Extract version from WordPress REST API response."""
        try:
            import json
            data = json.loads(response_text)
            
            # Check namespace for version
            namespaces = data.get('namespaces', [])
            for ns in namespaces:
                if 'wp/v' in ns:
                    return None  # API version, not WordPress version
            
            # Check authentication routes
            if 'authentication' in data:
                return None
            
            # Check site info
            site_info = data.get('site', {})
            if 'url' in site_info:
                return None
            
        except:
            pass
        
        return None