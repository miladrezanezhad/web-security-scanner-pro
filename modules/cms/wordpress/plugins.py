#!/usr/bin/env python3
"""
WordPress Plugin Enumeration Module.
Detects installed plugins and checks for known vulnerabilities.
"""

import re
import json
from typing import Dict, List, Optional, Set
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """WordPress plugin enumeration and vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress Plugin Enumeration"
        
        # Top 50 most popular WordPress plugins
        self.popular_plugins = [
            'elementor', 'woocommerce', 'wordfence', 'yoast-seo',
            'contact-form-7', 'jetpack', 'akismet', 'all-in-one-seo-pack',
            'wordpress-seo', 'google-analytics', 'wpforms', 'updraftplus',
            'wp-rocket', 'w3-total-cache', 'duplicator', 'ninja-forms',
            'really-simple-ssl', 'imagify', 'litespeed-cache', 'site-kit',
            'classic-editor', 'tablepress', 'redux-framework', 'elementor-pro',
            'sucuri-scanner', 'better-wp-security', 'wp-smushit', 'broken-link-checker',
            'autoptimize', 'mailchimp', 'monsterinsights', 'seedprod',
            'wp-mail-smtp', 'wp-super-cache', 'wordpress-popular-posts', 'regenerate-thumbnails',
            'redirection', 'query-monitor', 'advanced-custom-fields', 'gravityforms',
            'wp-file-manager', 'revslider', 'essential-addons', 'wp-reset',
            'disable-comments', 'custom-post-type-ui', 'shortpixel', 'mailpoet',
            'divi-builder', 'visual-composer',
        ]
        
        # Plugin detection methods
        self.detection_methods = {
            'readme': '/wp-content/plugins/{plugin}/readme.txt',
            'style': '/wp-content/plugins/{plugin}/style.css',
            'directory': '/wp-content/plugins/{plugin}/',
            'screenshot': '/wp-content/plugins/{plugin}/screenshot-1.png',
        }
    
    def run(self) -> Dict:
        """Execute plugin enumeration."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'plugins_found': [],
            'total_plugins': 0,
            'active_plugins': [],
            'inactive_plugins': [],
            'vulnerable_plugins': [],
            'findings': []
        }
        
        # Method 1: Passive detection from HTML source
        html_plugins = self._detect_from_html()
        
        # Method 2: Active detection by checking plugin paths
        path_plugins = self._detect_from_paths()
        
        # Method 3: Check wp-json for plugin info
        api_plugins = self._detect_from_api()
        
        # Combine all findings
        all_plugins = {}
        
        for plugin_list in [html_plugins, path_plugins, api_plugins]:
            for plugin in plugin_list:
                slug = plugin.get('slug', '').lower()
                if slug:
                    if slug not in all_plugins:
                        all_plugins[slug] = plugin
                    else:
                        # Merge detection methods
                        all_plugins[slug]['methods'].extend(plugin.get('methods', []))
        
        result['plugins_found'] = list(all_plugins.values())
        result['total_plugins'] = len(result['plugins_found'])
        
        # Generate findings
        if result['plugins_found']:
            plugin_names = [p.get('name', p.get('slug', 'Unknown')) for p in result['plugins_found'][:15]]
            
            self.findings.append({
                'title': f"{result['total_plugins']} WordPress plugins detected",
                'severity': 'medium',
                'description': (
                    f"Detected plugins: {', '.join(plugin_names)}. "
                    "Outdated plugins are a common source of vulnerabilities."
                ),
                'recommendation': (
                    "1. Remove unused plugins\n"
                    "2. Update all plugins to latest versions\n"
                    "3. Review plugin permissions\n"
                    "4. Only install plugins from trusted sources"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 4.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _detect_from_html(self) -> List[Dict]:
        """Detect plugins from HTML source code."""
        plugins = []
        
        resp = self.browser.get('/')
        if not resp or resp.status_code != 200:
            return plugins
        
        # Pattern 1: Standard plugin paths in HTML
        pattern1 = r'/wp-content/plugins/([^/\'"]+)'
        matches = re.findall(pattern1, resp.text)
        
        for match in set(matches):
            if match not in ['..', '.']:
                plugins.append({
                    'slug': match,
                    'name': match.replace('-', ' ').title(),
                    'methods': ['html_source'],
                    'version': None,
                })
        
        # Pattern 2: Enqueued plugin styles/scripts
        pattern2 = r'/wp-content/plugins/([^/]+)/[^/]+\.(?:css|js)\?ver=([\d.]+)'
        matches = re.findall(pattern2, resp.text)
        
        for slug, version in matches:
            # Update existing or add new
            existing = next((p for p in plugins if p['slug'] == slug), None)
            if existing:
                existing['version'] = version
                existing['methods'].append('enqueued_asset')
            else:
                plugins.append({
                    'slug': slug,
                    'name': slug.replace('-', ' ').title(),
                    'version': version,
                    'methods': ['enqueued_asset'],
                })
        
        return plugins
    
    def _detect_from_paths(self) -> List[Dict]:
        """Detect plugins by checking plugin paths."""
        plugins = []
        
        # Check popular plugins
        for plugin in self.popular_plugins[:20]:
            for method_name, path_template in self.detection_methods.items():
                path = path_template.format(plugin=plugin)
                resp = self.browser.head(path)
                
                if resp and resp.status_code in [200, 403]:
                    version = None
                    
                    # Try to get version from readme
                    if method_name == 'readme':
                        resp = self.browser.get(path)
                        if resp and resp.status_code == 200:
                            version_match = re.search(r'Stable tag:\s*([\d.]+)', resp.text)
                            if version_match:
                                version = version_match.group(1)
                    
                    plugins.append({
                        'slug': plugin,
                        'name': plugin.replace('-', ' ').title(),
                        'version': version,
                        'methods': [method_name],
                    })
                    break
        
        return plugins
    
    def _detect_from_api(self) -> List[Dict]:
        """Detect plugins from WordPress REST API."""
        plugins = []
        
        resp = self.browser.get('/wp-json/wp/v2/plugins')
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if isinstance(data, list):
                    for plugin in data:
                        if isinstance(plugin, dict):
                            plugins.append({
                                'slug': plugin.get('plugin', ''),
                                'name': plugin.get('name', ''),
                                'version': plugin.get('version', ''),
                                'methods': ['rest_api'],
                            })
            except json.JSONDecodeError:
                pass
        
        return plugins