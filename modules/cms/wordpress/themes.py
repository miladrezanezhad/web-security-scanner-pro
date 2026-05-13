#!/usr/bin/env python3
"""
WordPress Theme Detection Module.
Detects active and installed WordPress themes.

References:
    - WordPress Theme Handbook: https://developer.wordpress.org/themes/
"""

import re
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """WordPress theme detection scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress Theme Detection"
        
        # Popular WordPress themes
        self.popular_themes = [
            'astra', 'oceanwp', 'generatepress', 'neve', 'kadence',
            'hello-elementor', 'twentytwentyfour', 'twentytwentythree',
            'divi', 'avada', 'enfold', 'bethem', 'bridge', 'flatsome',
            'porto', 'woodmart', 'newspaper', 'jupiter', 'salient',
        ]
    
    def run(self) -> Dict:
        """Execute theme detection."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'active_theme': None,
            'theme_version': None,
            'parent_theme': None,
            'installed_themes': [],
            'findings': []
        }
        
        # Method 1: Extract from HTML
        html_theme = self._detect_from_html()
        if html_theme:
            result['active_theme'] = html_theme.get('slug')
            result['theme_version'] = html_theme.get('version')
        
        # Method 2: Check style.css for active theme
        css_theme = self._detect_from_style_css()
        if css_theme:
            if not result['active_theme']:
                result['active_theme'] = css_theme.get('slug')
            if not result['theme_version']:
                result['theme_version'] = css_theme.get('version')
            result['parent_theme'] = css_theme.get('parent')
        
        # Generate findings
        if result['active_theme']:
            self.findings.append({
                'title': f"WordPress theme detected: {result['active_theme']}",
                'severity': 'info',
                'description': (
                    f"Active theme: {result['active_theme']} "
                    f"{'v' + result['theme_version'] if result['theme_version'] else ''}"
                ),
                'recommendation': "Ensure theme is kept updated to latest version.",
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 1.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _detect_from_html(self) -> Optional[Dict]:
        """Detect theme from HTML source."""
        resp = self.browser.get('/')
        if not resp or resp.status_code != 200:
            return None
        
        # Pattern 1: Theme stylesheet
        pattern = r'/wp-content/themes/([^/]+)/'
        match = re.search(pattern, resp.text)
        if match:
            theme_slug = match.group(1)
            
            # Check for version
            version_pattern = rf'/wp-content/themes/{re.escape(theme_slug)}/[^"\']+\?ver=([\d.]+)'
            version_match = re.search(version_pattern, resp.text)
            
            return {
                'slug': theme_slug,
                'name': theme_slug.replace('-', ' ').title(),
                'version': version_match.group(1) if version_match else None,
            }
        
        return None
    
    def _detect_from_style_css(self) -> Optional[Dict]:
        """Detect theme by reading style.css."""
        # First find theme slug from HTML
        resp = self.browser.get('/')
        if not resp or resp.status_code != 200:
            return None
        
        theme_match = re.search(r'/wp-content/themes/([^/]+)/', resp.text)
        if not theme_match:
            return None
        
        theme_slug = theme_match.group(1)
        
        # Read theme's style.css
        css_resp = self.browser.get(f'/wp-content/themes/{theme_slug}/style.css')
        if not css_resp or css_resp.status_code != 200:
            return None
        
        result = {
            'slug': theme_slug,
            'name': None,
            'version': None,
            'parent': None,
        }
        
        # Parse theme header
        theme_name_match = re.search(r'Theme Name:\s*(.+)', css_resp.text)
        if theme_name_match:
            result['name'] = theme_name_match.group(1).strip()
        
        version_match = re.search(r'Version:\s*([\d.]+)', css_resp.text)
        if version_match:
            result['version'] = version_match.group(1)
        
        parent_match = re.search(r'Template:\s*(.+)', css_resp.text)
        if parent_match:
            result['parent'] = parent_match.group(1).strip()
        
        return result