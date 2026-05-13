#!/usr/bin/env python3
"""
Drupal CMS Security Scanner Module.
Tests for common Drupal security vulnerabilities and misconfigurations.

References:
    - Drupal Security: https://www.drupal.org/security
    - Drupal Security Advisories: https://www.drupal.org/security/advisory-policy
    - OWASP CMS Security: https://owasp.org/www-project-web-security-testing-guide/
"""

import re
import json
from typing import Dict, List, Optional
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """Drupal security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize Drupal scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Drupal Security Analysis"
        
        # Drupal paths for detection and enumeration
        self.drupal_paths = {
            'core': '/core/',
            'modules': '/modules/',
            'themes': '/themes/',
            'profiles': '/profiles/',
            'sites': '/sites/',
            'admin': '/admin/',
            'user_login': '/user/login',
            'user_register': '/user/register',
            'user_password': '/user/password',
            'rss': '/rss.xml',
        }
        
        # Drupal files that reveal version or configuration
        self.version_files = [
            '/core/lib/Drupal.php',
            '/core/core.api.php',
            '/CHANGELOG.txt',
            '/core/CHANGELOG.txt',
            '/COPYRIGHT.txt',
            '/MAINTAINERS.txt',
            '/INSTALL.txt',
            '/UPDATE.txt',
            '/core/INSTALL.txt',
        ]
        
        # Version detection patterns
        self.version_patterns = [
            r'Drupal\s+([\d.]+)',
            r'<meta name="Generator" content="Drupal\s+([\d.]+)',
            r'Drupal.settings.*?"version":\s*"([\d.]+)"',
            r'drupal-([\d.]+)',
            r'/core/misc/drupal\.js\?v=([\d.]+)',
            r'VERSION\s*=\s*[\'"]?([\d.]+)[\'"]?',
        ]
        
        # Common Drupal modules to check
        self.common_modules = [
            'views', 'ctools', 'token', 'pathauto', 'entity',
            'webform', 'metatag', 'redirect', 'paragraphs',
            'admin_toolbar', 'devel', 'rules', 'field_group',
            'google_analytics', 'xmlsitemap', 'backup_migrate',
            'captcha', 'recaptcha', 'colorbox', 'date',
        ]
        
        # Sensitive paths
        self.sensitive_paths = [
            '/sites/default/settings.php',
            '/sites/default/settings.local.php',
            '/sites/default/services.yml',
            '/sites/default/files/private/',
            '/sites/default/files/config/',
            '/.git/HEAD',
            '/.env',
            '/admin/reports/status/php',
        ]
    
    def run(self) -> Dict:
        """
        Execute Drupal security tests.
        
        Returns:
            Dict with findings and comprehensive analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'drupal_detected': False,
            'version': None,
            'version_source': None,
            'modules_found': [],
            'theme_detected': None,
            'user_enumeration_possible': False,
            'sensitive_files_exposed': [],
            'findings': []
        }
        
        # Stage 1: Detect Drupal
        detection = self._detect_drupal()
        result['drupal_detected'] = detection['detected']
        
        if not detection['detected']:
            result['findings'].append({
                'title': 'No Drupal installation detected',
                'severity': 'info',
                'description': 'No evidence of Drupal CMS was found on the target.',
                'recommendation': 'If Drupal is installed, verify it is properly configured.',
                'module': self.module_name,
            })
            return result
        
        # Stage 2: Detect version
        version_info = self._detect_version()
        result['version'] = version_info.get('version')
        result['version_source'] = version_info.get('source')
        
        if version_info.get('version'):
            result['findings'].append({
                'title': f"Drupal version detected: {version_info['version']}",
                'severity': 'medium',
                'description': (
                    f"Drupal version {version_info['version']} was detected via "
                    f"{version_info.get('source', 'unknown')}. Version disclosure helps "
                    "attackers identify known vulnerabilities for this specific version."
                ),
                'recommendation': (
                    "1. Update to the latest Drupal version\n"
                    "2. Check drupal.org/security for advisories\n"
                    "3. Remove CHANGELOG.txt and other version-revealing files\n"
                    "4. Hide the generator meta tag\n"
                    "5. Subscribe to Drupal security announcements"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
                'evidence': f"Version {version_info['version']} from {version_info.get('source')}",
            })
        
        # Stage 3: Enumerate modules
        modules = self._enumerate_modules()
        result['modules_found'] = modules
        
        if modules:
            result['findings'].append({
                'title': f"Drupal modules enumerated: {len(modules)} found",
                'severity': 'low',
                'description': (
                    f"Found {len(modules)} Drupal modules: {', '.join(modules[:10])}. "
                    "Module enumeration helps attackers identify vulnerable extensions."
                ),
                'recommendation': (
                    "1. Remove unused modules\n"
                    "2. Keep all modules updated\n"
                    "3. Review module permissions\n"
                    "4. Disable module listing in production"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 3.0,
                'evidence': f"Modules: {', '.join(modules[:10])}",
            })
        
        # Stage 4: Check sensitive file exposure
        sensitive = self._check_sensitive_files()
        result['sensitive_files_exposed'] = sensitive
        
        for exposed_file in sensitive:
            result['findings'].append({
                'title': f"Sensitive Drupal file exposed: {exposed_file['path']}",
                'severity': 'critical' if 'settings.php' in exposed_file['path'] else 'high',
                'description': (
                    f"Drupal configuration file {exposed_file['path']} is publicly accessible. "
                    "This file may contain database credentials, API keys, and other secrets."
                ),
                'recommendation': (
                    "1. Restrict access to sensitive files via web server config\n"
                    "2. Move configuration files outside web root\n"
                    "3. Set proper file permissions (400 or 440)\n"
                    "4. Use .htaccess to deny access to .php files in sites/default/"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.5 if 'settings.php' in exposed_file['path'] else 7.5,
                'evidence': f"Status: {exposed_file['status']}",
            })
        
        # Stage 5: Test user enumeration
        user_enum = self._test_user_enumeration()
        result['user_enumeration_possible'] = user_enum['possible']
        
        if user_enum['possible']:
            result['findings'].append({
                'title': 'Drupal user enumeration possible',
                'severity': 'medium',
                'description': (
                    "Drupal allows user enumeration through password reset forms "
                    "or user registration pages. Attackers can discover valid usernames."
                ),
                'recommendation': (
                    "1. Install and configure the Username Enumeration Prevention module\n"
                    "2. Use generic error messages for login/register forms\n"
                    "3. Implement rate limiting on user-related forms\n"
                    "4. Consider using email-based login instead of username"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-204',
                'cvss_score': 4.0,
                'evidence': f"Method: {user_enum.get('method')}",
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Detected: {result['drupal_detected']}, "
            f"Version: {result['version']}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _detect_drupal(self) -> Dict:
        """Detect if the target is running Drupal."""
        result = {
            'detected': False,
            'indicators': [],
        }
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        # Check meta generator tag
        soup = BeautifulSoup(resp.text, 'html.parser')
        meta = soup.find('meta', attrs={'name': 'Generator'})
        if meta and 'Drupal' in meta.get('content', ''):
            result['detected'] = True
            result['indicators'].append('Generator meta tag')
        
        # Check for Drupal-specific paths
        for name, path in self.drupal_paths.items():
            check = self.browser.head(path)
            if check and check.status_code in [200, 301, 302, 403]:
                if name not in result['indicators']:
                    result['indicators'].append(f"Path: {path}")
                result['detected'] = True
        
        # Check for Drupal JS
        if '/core/misc/drupal.js' in resp.text or '/misc/drupal.js' in resp.text:
            result['detected'] = True
            result['indicators'].append('Drupal JavaScript files')
        
        # Check headers
        if 'X-Generator' in resp.headers:
            if 'Drupal' in resp.headers['X-Generator']:
                result['detected'] = True
                result['indicators'].append('X-Generator header')
        
        return result
    
    def _detect_version(self) -> Dict:
        """Detect Drupal version."""
        result = {
            'version': None,
            'source': None,
        }
        
        # Method 1: Check meta tag
        resp = self.browser.get('/')
        if resp:
            for pattern in self.version_patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    result['version'] = match.group(1)
                    result['source'] = 'HTML meta/page source'
                    break
        
        # Method 2: Check version files
        if not result['version']:
            for file_path in self.version_files:
                resp = self.browser.get(file_path)
                if resp and resp.status_code == 200:
                    for pattern in self.version_patterns:
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        if match:
                            result['version'] = match.group(1)
                            result['source'] = f"File: {file_path}"
                            break
                if result['version']:
                    break
        
        # Method 3: Check CSS/JS version query strings
        if not result['version']:
            resp = self.browser.get('/')
            if resp:
                css_match = re.search(r'/core/themes/[^"]+\?v=([\d.]+)', resp.text)
                if css_match:
                    result['version'] = css_match.group(1)
                    result['source'] = 'CSS/JS version parameter'
        
        return result
    
    def _enumerate_modules(self) -> List[str]:
        """Enumerate installed Drupal modules."""
        found_modules = []
        
        for module in self.common_modules:
            # Check module directory
            module_path = f'/modules/{module}/'
            resp = self.browser.head(module_path)
            if resp and resp.status_code in [200, 301, 302, 403]:
                found_modules.append(module)
                continue
            
            # Check contrib module directory
            contrib_path = f'/modules/contrib/{module}/'
            resp = self.browser.head(contrib_path)
            if resp and resp.status_code in [200, 301, 302, 403]:
                found_modules.append(module)
                continue
            
            # Check for module info file
            info_path = f'/modules/{module}/{module}.info.yml'
            resp = self.browser.head(info_path)
            if resp and resp.status_code == 200:
                found_modules.append(module)
        
        return found_modules
    
    def _check_sensitive_files(self) -> List[Dict]:
        """Check for exposed sensitive files."""
        exposed = []
        
        for path in self.sensitive_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                # For settings.php, check if it's being executed (returns empty)
                # vs being downloaded (returns PHP code)
                content_length = len(resp.text)
                
                if 'settings.php' in path:
                    if content_length > 50 or '<?php' in resp.text:
                        exposed.append({
                            'path': path,
                            'status': resp.status_code,
                            'content_length': content_length,
                        })
                else:
                    exposed.append({
                        'path': path,
                        'status': resp.status_code,
                    })
        
        return exposed
    
    def _test_user_enumeration(self) -> Dict:
        """Test if user enumeration is possible."""
        result = {
            'possible': False,
            'method': None,
        }
        
        # Test password reset form
        resp = self.browser.get('/user/password')
        if resp and resp.status_code == 200:
            # Test with existing username
            test_usernames = ['admin', 'administrator', 'root', 'test']
            
            for username in test_usernames:
                post_resp = self.browser.post('/user/password', data={'name': username})
                if post_resp and post_resp.status_code == 200:
                    # Check if response differs for valid vs invalid username
                    if 'recognized' in post_resp.text.lower():
                        result['possible'] = True
                        result['method'] = 'Password reset form - username recognition'
                        break
        
        # Test user registration
        resp = self.browser.get('/user/register')
        if resp and resp.status_code == 200:
            result['possible'] = True
            result['method'] = 'Open registration page'
        
        return result