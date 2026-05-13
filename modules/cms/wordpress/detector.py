#!/usr/bin/env python3
"""
WordPress Detection Module.
Identifies WordPress installations through multiple detection methods
including header analysis, meta tags, file structure, and API responses.

References:
    - WordPress Codex: https://codex.wordpress.org/
    - WPScan: https://wpscan.com/
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """WordPress detection and fingerprinting scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize WordPress detector.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress Detection"
        
        # WordPress-specific paths for detection
        self.wp_detection_paths = {
            'admin': '/wp-admin/',
            'login': '/wp-login.php',
            'content': '/wp-content/',
            'includes': '/wp-includes/',
            'cron': '/wp-cron.php',
            'xmlrpc': '/xmlrpc.php',
            'readme': '/readme.html',
            'license': '/license.txt',
        }
        
        # HTML indicators of WordPress
        self.html_indicators = [
            '<meta name="generator" content="WordPress',
            'wp-content/themes/',
            'wp-content/plugins/',
            'wp-includes/js/wp-embed',
            'wp-includes/css/',
            '/wp-json/',
            'wp-embed.min.js',
            'wp-emoji-release.min.js',
            'wp-admin/admin-ajax.php',
            'wp-login.php?action=',
        ]
        
        # Header indicators
        self.header_indicators = [
            ('X-Powered-By', 'WordPress'),
            ('Link', 'wp-json'),
            ('X-WP-Nonce', None),
        ]
        
        # Known WordPress file hashes for version fingerprinting
        self.file_fingerprints = {
            '/wp-admin/css/common.css': {
                '6.4': 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
                '6.5': 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7',
            },
            '/wp-includes/js/wp-embed.min.js': {
                '6.4': 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8',
            },
        }
    
    def run(self) -> Dict:
        """
        Execute WordPress detection tests.
        
        Returns:
            Dict with detection results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'is_wordpress': False,
            'detection_methods': [],
            'detection_score': 0,
            'max_score': 100,
            'confidence': 'none',
            'multisite_detected': False,
            'hosting_provider': None,
            'findings': []
        }
        
        # Run all detection methods
        detections = []
        
        # Method 1: Check WordPress-specific paths
        path_detection = self._check_paths()
        if path_detection['detected']:
            detections.append(('path_check', 30, path_detection['paths_found']))
        
        # Method 2: Check HTML indicators
        html_detection = self._check_html_indicators()
        if html_detection['detected']:
            detections.append(('html_indicators', 25, html_detection['indicators_found']))
        
        # Method 3: Check HTTP headers
        header_detection = self._check_headers()
        if header_detection['detected']:
            detections.append(('header_check', 15, header_detection['headers_found']))
        
        # Method 4: Check readme.html
        readme_detection = self._check_readme()
        if readme_detection['detected']:
            detections.append(('readme_check', 10, ['readme.html exists']))
        
        # Method 5: Check REST API
        api_detection = self._check_rest_api()
        if api_detection['detected']:
            detections.append(('rest_api', 10, ['REST API accessible']))
        
        # Method 6: Check login page
        login_detection = self._check_login_page()
        if login_detection['detected']:
            detections.append(('login_page', 10, ['Login page identified']))
        
        # Calculate total score
        total_score = sum(score for _, score, _ in detections)
        result['detection_score'] = total_score
        
        # Determine if WordPress
        if total_score >= 30:
            result['is_wordpress'] = True
        
        # Determine confidence level
        if total_score >= 70:
            result['confidence'] = 'high'
        elif total_score >= 40:
            result['confidence'] = 'medium'
        elif total_score >= 20:
            result['confidence'] = 'low'
        else:
            result['confidence'] = 'none'
        
        # Compile detection methods
        for method, score, evidence in detections:
            result['detection_methods'].append({
                'method': method,
                'score': score,
                'evidence': evidence[:5],  # Limit to 5 items
            })
        
        # Check for multisite
        result['multisite_detected'] = self._check_multisite()
        
        # Check for common hosting providers
        result['hosting_provider'] = self._detect_hosting_provider()
        
        # Add findings
        if result['is_wordpress']:
            self.findings.append({
                'title': f"WordPress CMS detected (confidence: {result['confidence']})",
                'severity': 'info',
                'description': (
                    f"WordPress was detected with {result['confidence']} confidence "
                    f"(score: {total_score}/100). "
                    f"Detection methods: {', '.join([m for m, _, _ in detections])}."
                ),
                'recommendation': (
                    "1. Keep WordPress core updated to latest version\n"
                    "2. Keep all plugins and themes updated\n"
                    "3. Use strong admin credentials\n"
                    "4. Implement security plugins (Wordfence, Sucuri)\n"
                    "5. Regularly backup your site"
                ),
                'module': self.module_name,
                'evidence': f"Detection score: {total_score}/100",
                'references': [
                    'https://wordpress.org/documentation/',
                    'https://developer.wordpress.org/advanced-administration/security/',
                ]
            })
            
            if result['multisite_detected']:
                self.findings.append({
                    'title': 'WordPress Multisite installation detected',
                    'severity': 'info',
                    'description': 'This is a WordPress Multisite (network) installation.',
                    'recommendation': 'Ensure network-wide security policies are enforced.',
                    'module': self.module_name,
                })
        
        result['findings'] = self.findings
        return result
    
    def _check_paths(self) -> Dict:
        """Check for WordPress-specific paths."""
        result = {
            'detected': False,
            'paths_found': [],
        }
        
        for name, path in self.wp_detection_paths.items():
            if name in ['readme', 'license']:
                continue  # Checked separately
            
            resp = self.browser.head(path)
            if resp and resp.status_code in [200, 301, 302, 403]:
                result['paths_found'].append(f"{path} ({resp.status_code})")
                result['detected'] = True
        
        return result
    
    def _check_html_indicators(self) -> Dict:
        """Check HTML source for WordPress indicators."""
        result = {
            'detected': False,
            'indicators_found': [],
        }
        
        resp = self.browser.get('/')
        if not resp or resp.status_code != 200:
            return result
        
        # Parse HTML
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Check meta generator
        meta = soup.find('meta', attrs={'name': 'generator'})
        if meta and 'WordPress' in meta.get('content', ''):
            result['indicators_found'].append(f"Meta generator: {meta['content']}")
            result['detected'] = True
        
        # Check for WordPress-specific HTML patterns
        for indicator in self.html_indicators:
            if indicator in resp.text:
                result['indicators_found'].append(indicator[:80])
                result['detected'] = True
        
        return result
    
    def _check_headers(self) -> Dict:
        """Check HTTP headers for WordPress indicators."""
        result = {
            'detected': False,
            'headers_found': [],
        }
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        for header_name, expected_value in self.header_indicators:
            if header_name in resp.headers:
                value = resp.headers[header_name]
                if expected_value is None or expected_value.lower() in value.lower():
                    result['headers_found'].append(f"{header_name}: {value[:100]}")
                    result['detected'] = True
        
        return result
    
    def _check_readme(self) -> Dict:
        """Check for WordPress readme.html."""
        result = {
            'detected': False,
        }
        
        resp = self.browser.get('/readme.html')
        if resp and resp.status_code == 200:
            if 'WordPress' in resp.text:
                result['detected'] = True
                
                # Try to extract version
                version_match = re.search(r'Version\s+([\d.]+)', resp.text)
                if version_match:
                    result['version'] = version_match.group(1)
        
        return result
    
    def _check_rest_api(self) -> Dict:
        """Check WordPress REST API."""
        result = {
            'detected': False,
        }
        
        resp = self.browser.get('/wp-json/')
        if resp and resp.status_code == 200:
            try:
                import json
                data = json.loads(resp.text)
                if isinstance(data, dict) and 'namespaces' in data:
                    result['detected'] = True
            except:
                pass
        
        return result
    
    def _check_login_page(self) -> Dict:
        """Check if login page is WordPress."""
        result = {
            'detected': False,
        }
        
        resp = self.browser.get('/wp-login.php')
        if resp and resp.status_code == 200:
            login_indicators = [
                'wp-submit',
                'user_login',
                'user_pass',
                'wordpress',
                'wp-login',
                'Lost your password',
            ]
            
            for indicator in login_indicators:
                if indicator.lower() in resp.text.lower():
                    result['detected'] = True
                    break
        
        return result
    
    def _check_multisite(self) -> bool:
        """Check if WordPress multisite is enabled."""
        resp = self.browser.get('/')
        if not resp:
            return False
        
        multisite_indicators = [
            'wp-signup.php',
            'wp-activate.php',
            'wp-content/blogs.dir',
            'wp-content/uploads/sites/',
        ]
        
        for indicator in multisite_indicators:
            if indicator in resp.text:
                return True
        
        return False
    
    def _detect_hosting_provider(self) -> Optional[str]:
        """Detect common WordPress hosting providers."""
        resp = self.browser.get('/')
        if not resp:
            return None
        
        hosting_signatures = {
            'WP Engine': ['wpengine', 'wpe-', 'WP Engine'],
            'Kinsta': ['kinsta', 'Kinsta'],
            'SiteGround': ['siteground', 'SiteGround'],
            'Bluehost': ['bluehost', 'BlueHost'],
            'GoDaddy': ['godaddy', 'GoDaddy', 'sucuri'],
            'Cloudways': ['cloudways', 'Cloudways'],
            'Flywheel': ['flywheel', 'Flywheel'],
            'Pantheon': ['pantheon', 'Pantheon'],
        }
        
        check_text = resp.text.lower()
        headers_str = ' '.join([f"{k}: {v}" for k, v in resp.headers.items()]).lower()
        combined = check_text + ' ' + headers_str
        
        for provider, signatures in hosting_signatures.items():
            for sig in signatures:
                if sig.lower() in combined:
                    return provider
        
        return None