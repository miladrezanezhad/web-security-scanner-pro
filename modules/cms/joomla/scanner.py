#!/usr/bin/env python3
"""
Joomla CMS Security Scanner Module.
Tests for common Joomla security vulnerabilities and misconfigurations.

References:
    - Joomla Security: https://docs.joomla.org/Security
    - Joomla Vulnerable Extensions List: https://vel.joomla.org/
    - OWASP CMS Security: https://owasp.org/www-project-web-security-testing-guide/
"""

import re
import json
from typing import Dict, List, Optional
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """Joomla security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize Joomla scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Joomla Security Analysis"
        
        # Joomla paths for detection
        self.joomla_paths = {
            'administrator': '/administrator/',
            'components': '/components/',
            'modules': '/modules/',
            'plugins': '/plugins/',
            'templates': '/templates/',
            'language': '/language/',
            'libraries': '/libraries/',
            'media': '/media/',
            'cache': '/cache/',
            'logs': '/logs/',
            'tmp': '/tmp/',
        }
        
        # Version detection files
        self.version_files = [
            '/administrator/manifests/files/joomla.xml',
            '/language/en-GB/en-GB.xml',
            '/media/system/js/core.js',
            '/plugins/system/cache/cache.xml',
        ]
        
        # Version patterns
        self.version_patterns = [
            r'<version>([\d.]+)</version>',
            r'Joomla!\s*([\d.]+)',
            r'<meta name="generator" content="Joomla!\s*([\d.]+)',
            r'joomla-([\d.]+)',
            r'/media/system/js/core\.js\?([\d.]+)',
        ]
        
        # Common Joomla extensions
        self.common_extensions = [
            'com_virtuemart', 'com_community', 'com_k2',
            'com_jce', 'com_fabrik', 'com_akeeba',
            'com_phocagallery', 'com_rsform', 'com_jsn',
            'com_contact', 'com_content', 'com_users',
            'com_weblinks', 'com_newsfeeds', 'com_search',
            'mod_login', 'mod_menu', 'mod_breadcrumbs',
            'plg_system_cache', 'plg_system_debug',
            'plg_editors_tinymce', 'plg_editors_codemirror',
        ]
        
        # Sensitive paths
        self.sensitive_paths = [
            '/configuration.php',
            '/configuration.php-dist',
            '/configuration.php.bak',
            '/configuration.php~',
            '/configuration.php.old',
            '/administrator/backups/',
            '/tmp/',
            '/logs/',
            '/.git/HEAD',
            '/.env',
        ]
    
    def run(self) -> Dict:
        """
        Execute Joomla security tests.
        
        Returns:
            Dict with findings and comprehensive analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'joomla_detected': False,
            'version': None,
            'version_source': None,
            'extensions_found': [],
            'template_detected': None,
            'admin_exposed': False,
            'user_enumeration_possible': False,
            'sensitive_files_exposed': [],
            'debug_mode': False,
            'findings': []
        }
        
        # Stage 1: Detect Joomla
        detection = self._detect_joomla()
        result['joomla_detected'] = detection['detected']
        
        if not detection['detected']:
            result['findings'].append({
                'title': 'No Joomla installation detected',
                'severity': 'info',
                'description': 'No evidence of Joomla CMS was found on the target.',
                'recommendation': 'If Joomla is installed, verify it is properly configured.',
                'module': self.module_name,
            })
            return result
        
        # Stage 2: Detect version
        version_info = self._detect_version()
        result['version'] = version_info.get('version')
        result['version_source'] = version_info.get('source')
        
        if version_info.get('version'):
            result['findings'].append({
                'title': f"Joomla version detected: {version_info['version']}",
                'severity': 'medium',
                'description': (
                    f"Joomla version {version_info['version']} was detected via "
                    f"{version_info.get('source')}. Version disclosure helps attackers "
                    "identify known vulnerabilities."
                ),
                'recommendation': (
                    "1. Update to the latest Joomla version\n"
                    "2. Check developer.joomla.org/security-center for advisories\n"
                    "3. Remove version information from templates\n"
                    "4. Use security extensions for additional protection"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
                'evidence': f"Version {version_info['version']} from {version_info.get('source')}",
            })
        
        # Stage 3: Check administrator exposure
        admin_check = self._check_admin_exposure()
        result['admin_exposed'] = admin_check['exposed']
        
        if admin_check['exposed']:
            result['findings'].append({
                'title': 'Joomla administrator panel publicly accessible',
                'severity': 'high',
                'description': (
                    "The Joomla administrator login page is publicly accessible at "
                    f"{admin_check.get('url')}. This exposes the admin panel to "
                    "brute-force attacks and vulnerability exploitation."
                ),
                'recommendation': (
                    "1. Restrict administrator access by IP address\n"
                    "2. Use .htaccess to password-protect /administrator/\n"
                    "3. Implement two-factor authentication\n"
                    "4. Rename the administrator directory\n"
                    "5. Use Admin Tools extension for additional protection"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
                'evidence': f"URL: {admin_check.get('url')}",
            })
        
        # Stage 4: Enumerate extensions
        extensions = self._enumerate_extensions()
        result['extensions_found'] = extensions
        
        if extensions:
            result['findings'].append({
                'title': f"Joomla extensions enumerated: {len(extensions)} found",
                'severity': 'low',
                'description': (
                    f"Found {len(extensions)} Joomla extensions: {', '.join(extensions[:10])}. "
                    "Extension enumeration helps identify vulnerable components."
                ),
                'recommendation': (
                    "1. Remove unused extensions\n"
                    "2. Keep all extensions updated\n"
                    "3. Check VEL (Vulnerable Extensions List) regularly\n"
                    "4. Only install extensions from trusted sources"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 3.0,
                'evidence': f"Extensions: {', '.join(extensions[:10])}",
            })
        
        # Stage 5: Check sensitive files
        sensitive = self._check_sensitive_files()
        result['sensitive_files_exposed'] = sensitive
        
        for exposed_file in sensitive:
            severity = 'critical' if 'configuration.php' in exposed_file['path'] else 'high'
            result['findings'].append({
                'title': f"Sensitive Joomla file exposed: {exposed_file['path']}",
                'severity': severity,
                'description': (
                    f"Joomla file {exposed_file['path']} is publicly accessible. "
                    "configuration.php contains database credentials and secret keys."
                ),
                'recommendation': (
                    "1. Move configuration.php outside web root\n"
                    "2. Set file permissions to 400 or 440\n"
                    "3. Use .htaccess to deny access to .php files\n"
                    "4. Remove backup and temporary files"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.5 if 'configuration.php' in exposed_file['path'] else 7.5,
                'evidence': f"Status: {exposed_file['status']}",
            })
        
        # Stage 6: Check debug mode
        debug_check = self._check_debug_mode()
        result['debug_mode'] = debug_check['enabled']
        
        if debug_check['enabled']:
            result['findings'].append({
                'title': 'Joomla debug mode is enabled',
                'severity': 'high',
                'description': (
                    "Joomla debug mode is enabled. This exposes detailed error messages, "
                    "database queries, and system information to users."
                ),
                'recommendation': (
                    "1. Disable debug mode in Global Configuration\n"
                    "2. Set Error Reporting to 'None' in production\n"
                    "3. Configure custom error pages"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-489',
                'cvss_score': 7.0,
                'evidence': f"Debug indicator: {debug_check.get('indicator')}",
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Detected: {result['joomla_detected']}, "
            f"Version: {result['version']}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _detect_joomla(self) -> Dict:
        """Detect if the target is running Joomla."""
        result = {
            'detected': False,
            'indicators': [],
        }
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        # Check meta generator
        soup = BeautifulSoup(resp.text, 'html.parser')
        meta = soup.find('meta', attrs={'name': 'generator'})
        if meta and 'Joomla' in meta.get('content', ''):
            result['detected'] = True
            result['indicators'].append('Generator meta tag')
        
        # Check Joomla-specific paths
        for name, path in self.joomla_paths.items():
            check = self.browser.head(path)
            if check and check.status_code in [200, 301, 302, 403]:
                result['indicators'].append(f"Path: {path}")
                result['detected'] = True
        
        # Check Joomla-specific text
        joomla_indicators = [
            'joomla', 'Joomla!', 'com_content',
            'mod_login', 'JRoute', 'JFactory',
            '/media/jui/', '/media/system/',
        ]
        
        for indicator in joomla_indicators:
            if indicator in resp.text:
                result['detected'] = True
                result['indicators'].append(f"Text indicator: {indicator}")
                break
        
        return result
    
    def _detect_version(self) -> Dict:
        """Detect Joomla version."""
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
        
        # Method 2: Check XML manifest files
        if not result['version']:
            for file_path in self.version_files:
                resp = self.browser.get(file_path)
                if resp and resp.status_code == 200:
                    for pattern in self.version_patterns[:2]:
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        if match:
                            result['version'] = match.group(1)
                            result['source'] = f"File: {file_path}"
                            break
                if result['version']:
                    break
        
        # Method 3: Check administrator page
        if not result['version']:
            resp = self.browser.get('/administrator/')
            if resp and resp.status_code == 200:
                for pattern in self.version_patterns:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        result['version'] = match.group(1)
                        result['source'] = 'Administrator page'
                        break
        
        return result
    
    def _check_admin_exposure(self) -> Dict:
        """Check if administrator panel is exposed."""
        result = {
            'exposed': False,
            'url': None,
        }
        
        resp = self.browser.get('/administrator/')
        if resp and resp.status_code == 200:
            if 'joomla' in resp.text.lower() or 'login' in resp.text.lower():
                result['exposed'] = True
                result['url'] = urljoin(self.target_url, '/administrator/')
        
        return result
    
    def _enumerate_extensions(self) -> List[str]:
        """Enumerate installed Joomla extensions."""
        found = []
        
        for extension in self.common_extensions:
            ext_type = extension.split('_')[0]
            ext_name = '_'.join(extension.split('_')[1:])
            
            if ext_type == 'com':
                path = f'/components/{ext_name}/'
            elif ext_type == 'mod':
                path = f'/modules/{ext_name}/'
            elif ext_type == 'plg':
                # Plugin paths are more complex
                plugin_parts = extension.split('_')
                if len(plugin_parts) >= 3:
                    path = f'/plugins/{plugin_parts[1]}/{plugin_parts[2]}/'
                else:
                    continue
            else:
                continue
            
            resp = self.browser.head(path)
            if resp and resp.status_code in [200, 301, 302, 403]:
                found.append(extension)
        
        return found
    
    def _check_sensitive_files(self) -> List[Dict]:
        """Check for exposed sensitive files."""
        exposed = []
        
        for path in self.sensitive_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                exposed.append({
                    'path': path,
                    'status': resp.status_code,
                })
        
        return exposed
    
    def _check_debug_mode(self) -> Dict:
        """Check if Joomla debug mode is enabled."""
        result = {
            'enabled': False,
            'indicator': None,
        }
        
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            debug_indicators = [
                'jdebug', 'debug-mode',
                'JDEBUG', 'system-debug',
                '?tp=1', 'template_preview',
            ]
            
            for indicator in debug_indicators:
                if indicator in resp.text:
                    result['enabled'] = True
                    result['indicator'] = indicator
                    break
        
        return result