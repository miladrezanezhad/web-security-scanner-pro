#!/usr/bin/env python3
"""
WordPress Security Hardening Checker.
Verifies WordPress security hardening configurations.

References:
    - WordPress Hardening: https://wordpress.org/documentation/article/hardening-wordpress/
    - OWASP WordPress Security: https://owasp.org/www-project-web-security-testing-guide/
"""

import re
from typing import Dict, List, Optional
from loguru import logger


class Scanner:
    """WordPress security hardening scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress Hardening Check"
        
        # Security headers that should be present
        self.required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Strict-Transport-Security': 'max-age=',
        }
        
        # Sensitive files to check
        self.sensitive_files = [
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.php~',
            '/wp-config.php.old',
            '/wp-config.php.save',
            '/wp-config.php.swp',
            '/.wp-config.php.swp',
            '/wp-content/debug.log',
            '/.git/HEAD',
            '/.svn/entries',
            '/.env',
        ]
        
        # Directory listing checks
        self.directory_checks = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-includes/',
        ]
    
    def run(self) -> Dict:
        """Execute hardening checks."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'security_headers': {},
            'missing_headers': [],
            'exposed_files': [],
            'directory_listing': [],
            'debug_mode': False,
            'file_editor_enabled': False,
            'xmlrpc_enabled': False,
            'score': 100,
            'findings': []
        }
        
        # Check security headers
        header_result = self._check_security_headers()
        result['security_headers'] = header_result['present']
        result['missing_headers'] = header_result['missing']
        
        if result['missing_headers']:
            self.findings.append({
                'title': f"Missing security headers: {', '.join(result['missing_headers'])}",
                'severity': 'medium',
                'description': "WordPress is missing important security headers.",
                'recommendation': (
                    "Add to .htaccess or use a security plugin:\n"
                    "Header set X-Content-Type-Options 'nosniff'\n"
                    "Header set X-Frame-Options 'SAMEORIGIN'\n"
                    "Header set Referrer-Policy 'strict-origin-when-cross-origin'"
                ),
                'module': self.module_name,
                'cvss_score': 4.0,
            })
            result['score'] -= len(result['missing_headers']) * 10
        
        # Check sensitive files
        exposed = self._check_sensitive_files()
        result['exposed_files'] = exposed
        
        for file_info in exposed:
            self.findings.append({
                'title': f"Sensitive file exposed: {file_info['path']}",
                'severity': 'critical' if 'wp-config' in file_info['path'] else 'high',
                'description': f"File {file_info['path']} is publicly accessible.",
                'recommendation': (
                    "Remove backup files and restrict access to configuration files."
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.0 if 'wp-config' in file_info['path'] else 7.0,
            })
            result['score'] -= 25 if 'wp-config' in file_info['path'] else 15
        
        # Check directory listing
        dir_listing = self._check_directory_listing()
        result['directory_listing'] = dir_listing
        
        for dir_info in dir_listing:
            self.findings.append({
                'title': f"Directory listing enabled: {dir_info['path']}",
                'severity': 'medium',
                'description': f"Directory listing is enabled for {dir_info['path']}.",
                'recommendation': "Add 'Options -Indexes' to .htaccess.",
                'module': self.module_name,
                'cwe_id': 'CWE-548',
                'cvss_score': 4.0,
            })
            result['score'] -= 10
        
        # Check debug mode
        debug_check = self._check_debug_mode()
        result['debug_mode'] = debug_check
        
        if debug_check:
            self.findings.append({
                'title': 'WordPress debug mode may be enabled',
                'severity': 'high',
                'description': "Debug mode exposes sensitive information in error messages.",
                'recommendation': "Set WP_DEBUG to false in wp-config.php.",
                'module': self.module_name,
                'cwe_id': 'CWE-489',
                'cvss_score': 7.0,
            })
            result['score'] -= 20
        
        # Ensure score doesn't go below 0
        result['score'] = max(0, result['score'])
        
        result['findings'] = self.findings
        return result
    
    def _check_security_headers(self) -> Dict:
        """Check for required security headers."""
        result = {
            'present': {},
            'missing': [],
        }
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        for header, expected_value in self.required_headers.items():
            if header in resp.headers:
                value = resp.headers[header]
                if expected_value in value:
                    result['present'][header] = value
                else:
                    result['missing'].append(header)
            else:
                result['missing'].append(header)
        
        return result
    
    def _check_sensitive_files(self) -> List[Dict]:
        """Check for exposed sensitive files."""
        exposed = []
        
        for file_path in self.sensitive_files:
            resp = self.browser.get(file_path)
            if resp and resp.status_code == 200:
                content = resp.text[:200]
                exposed.append({
                    'path': file_path,
                    'status': resp.status_code,
                    'content_preview': content,
                })
        
        return exposed
    
    def _check_directory_listing(self) -> List[Dict]:
        """Check for enabled directory listing."""
        listing_enabled = []
        
        for dir_path in self.directory_checks:
            resp = self.browser.get(dir_path)
            if resp and resp.status_code == 200:
                listing_indicators = [
                    'Index of',
                    'Parent Directory',
                    'Last modified',
                    '<title>Index of',
                ]
                
                for indicator in listing_indicators:
                    if indicator in resp.text:
                        listing_enabled.append({
                            'path': dir_path,
                            'indicator': indicator,
                        })
                        break
        
        return listing_enabled
    
    def _check_debug_mode(self) -> bool:
        """Check if WordPress debug mode is enabled."""
        resp = self.browser.get('/wp-content/debug.log')
        
        if resp and resp.status_code == 200:
            if 'PHP' in resp.text or 'Error' in resp.text:
                return True
        
        return False