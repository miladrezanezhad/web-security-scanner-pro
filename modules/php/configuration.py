#!/usr/bin/env python3
"""
PHP Configuration Security Analysis Module.
Analyzes PHP configuration (php.ini) settings for security weaknesses.

References:
    - PHP Manual: https://www.php.net/manual/en/ini.list.php
    - OWASP PHP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/PHP_Security_Cheat_Sheet.html
    - PHP Security Consortium: https://phpsec.org/
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin
from loguru import logger

from modules.php import PHP_SECURITY_DIRECTIVES, DANGEROUS_FUNCTIONS


class Scanner:
    """PHP configuration security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize PHP configuration scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "PHP Configuration Analysis"
        
        # Methods to detect PHP configuration
        self.detection_methods = [
            'phpinfo_page',
            'error_messages',
            'headers',
            'session_cookies',
            'source_disclosure',
        ]
        
        # Common phpinfo paths
        self.phpinfo_paths = [
            '/phpinfo.php',
            '/info.php',
            '/php_info.php',
            '/test.php',
            '/php.php',
            '/i.php',
            '/p.php',
            '/x.php',
            '/admin/phpinfo.php',
            '/admin/info.php',
            '/debug/phpinfo.php',
            '/dev/phpinfo.php',
            '/old/phpinfo.php',
            '/backup/phpinfo.php',
            '/temp/phpinfo.php',
        ]
        
        # PHP source disclosure paths
        self.source_paths = [
            '/index.php~',
            '/index.php.bak',
            '/index.php.old',
            '/index.php.orig',
            '/index.php.save',
            '/index.php.swp',
            '/index.phps',
            '/.index.php.swp',
            '/config.php~',
            '/config.php.bak',
            '/config.php.old',
            '/wp-config.php~',
            '/wp-config.php.bak',
            '/wp-config.php.old',
            '/wp-config.phps',
        ]
    
    def run(self) -> Dict:
        """
        Execute PHP configuration analysis.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'phpinfo_accessible': False,
            'phpinfo_urls': [],
            'config_directives': {},
            'weak_directives': [],
            'dangerous_functions_enabled': [],
            'source_disclosure': [],
            'session_config_weak': False,
            'error_reporting_verbose': False,
            'display_errors_enabled': False,
            'findings': []
        }
        
        # Stage 1: Check for exposed phpinfo()
        phpinfo_check = self._check_phpinfo()
        result['phpinfo_accessible'] = phpinfo_check['accessible']
        result['phpinfo_urls'] = phpinfo_check['urls']
        
        if phpinfo_check['accessible']:
            for url in phpinfo_check['urls']:
                self.findings.append({
                    'title': f'phpinfo() page is publicly accessible: {url}',
                    'severity': 'critical',
                    'description': (
                        f"A phpinfo() page is publicly accessible at {url}. "
                        "This page exposes detailed PHP configuration including:\n"
                        "- PHP version and build information\n"
                        "- All loaded extensions and their versions\n"
                        "- All php.ini configuration directives\n"
                        "- Environment variables\n"
                        "- Server paths and file locations\n"
                        "- Database configuration\n"
                        "- Loaded modules and their configurations"
                    ),
                    'recommendation': (
                        "1. IMMEDIATELY delete phpinfo.php or restrict access\n"
                        "2. Add to .htaccess:\n"
                        "   <Files phpinfo.php>\n"
                        "       Order deny,allow\n"
                        "       Deny from all\n"
                        "   </Files>\n"
                        "3. Never deploy phpinfo() to production servers\n"
                        "4. Use a deployment checklist to verify debug files are removed"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 9.0,
                    'evidence': f"URL: {url}",
                })
        
        # Stage 2: Detect configuration from error messages
        error_config = self._detect_from_errors()
        
        if error_config.get('display_errors'):
            result['display_errors_enabled'] = True
            self.findings.append({
                'title': 'PHP display_errors appears to be enabled',
                'severity': 'high',
                'description': (
                    "PHP error messages are being displayed to users. This reveals:\n"
                    "- File paths and directory structure\n"
                    "- Database connection details\n"
                    "- PHP version information\n"
                    "- Application code and logic"
                ),
                'recommendation': (
                    "1. Set in php.ini: display_errors = Off\n"
                    "2. Set: log_errors = On\n"
                    "3. Set: error_log = /path/to/error.log\n"
                    "4. Use custom error handler in application code\n"
                    "5. Ensure error log file is outside web root"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-209',
                'cvss_score': 7.5,
            })
        
        # Stage 3: Check headers for PHP configuration indicators
        header_config = self._detect_from_headers()
        
        if header_config.get('expose_php'):
            self.findings.append({
                'title': 'PHP version exposed in X-Powered-By header',
                'severity': 'medium',
                'description': (
                    f"PHP version is disclosed in the X-Powered-By header: "
                    f"{header_config.get('php_version', 'unknown')}. "
                    "This helps attackers identify known vulnerabilities."
                ),
                'recommendation': (
                    "1. Set in php.ini: expose_php = Off\n"
                    "2. Remove via web server config:\n"
                    "   Apache: Header unset X-Powered-By\n"
                    "   Nginx: proxy_hide_header X-Powered-By;"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
                'evidence': f"Header: X-Powered-By: {header_config.get('php_version', '')}",
            })
        
        # Stage 4: Check session cookie configuration
        session_config = self._detect_session_config()
        result['session_config_weak'] = session_config.get('weak', False)
        
        if session_config.get('missing_httponly'):
            self.findings.append({
                'title': 'Session cookies missing HttpOnly flag',
                'severity': 'high',
                'description': (
                    "Session cookies do not have the HttpOnly flag set. "
                    "This allows JavaScript to access session cookies, "
                    "making XSS attacks more dangerous."
                ),
                'recommendation': (
                    "Set in php.ini:\n"
                    "  session.cookie_httponly = On"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-1004',
                'cvss_score': 6.5,
            })
        
        if session_config.get('missing_secure'):
            self.findings.append({
                'title': 'Session cookies missing Secure flag',
                'severity': 'high',
                'description': (
                    "Session cookies do not have the Secure flag set. "
                    "This allows cookies to be transmitted over unencrypted HTTP connections, "
                    "making them vulnerable to man-in-the-middle attacks."
                ),
                'recommendation': (
                    "Set in php.ini:\n"
                    "  session.cookie_secure = On\n"
                    "Note: Requires HTTPS to be properly configured."
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-614',
                'cvss_score': 7.5,
            })
        
        if session_config.get('missing_samesite'):
            self.findings.append({
                'title': 'Session cookies missing SameSite attribute',
                'severity': 'medium',
                'description': (
                    "Session cookies do not have the SameSite attribute set. "
                    "This makes the application vulnerable to CSRF attacks."
                ),
                'recommendation': (
                    "Set in php.ini:\n"
                    "  session.cookie_samesite = Strict (or Lax)"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-1275',
                'cvss_score': 5.0,
            })
        
        # Stage 5: Check for PHP source code disclosure
        source_check = self._check_source_disclosure()
        result['source_disclosure'] = source_check
        
        for source in source_check:
            self.findings.append({
                'title': f"PHP source code disclosure: {source['path']}",
                'severity': 'high',
                'description': (
                    f"PHP source code is exposed at {source['path']}. "
                    "This reveals application logic, database credentials, "
                    "and potentially other sensitive configuration."
                ),
                'recommendation': (
                    "1. Remove backup files from web root\n"
                    "2. Configure web server to not serve .php~ or .php.bak files\n"
                    "3. Add to .htaccess:\n"
                    "   <FilesMatch \"\.(php~|php\.bak|php\.old|phps)$\">\n"
                    "       Order deny,allow\n"
                    "       Deny from all\n"
                    "   </FilesMatch>"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-540',
                'cvss_score': 8.0,
                'evidence': f"Path: {source['path']}, Status: {source['status']}",
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"phpinfo: {result['phpinfo_accessible']}, "
            f"Display errors: {result['display_errors_enabled']}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _check_phpinfo(self) -> Dict:
        """
        Check for exposed phpinfo() pages.
        
        Returns:
            Dict with phpinfo accessibility info
        """
        result = {
            'accessible': False,
            'urls': [],
        }
        
        for path in self.phpinfo_paths:
            resp = self.browser.get(path)
            
            if resp and resp.status_code == 200:
                # Check for phpinfo indicators
                phpinfo_indicators = [
                    'PHP Version',
                    'phpinfo()',
                    'System</td>',
                    'Build Date</td>',
                    'Configure Command</td>',
                    'Server API</td>',
                    'Virtual Directory Support</td>',
                    'Configuration File (php.ini) Path</td>',
                    'Loaded Configuration File</td>',
                    'PHP Extension</td>',
                    'PHP License</td>',
                ]
                
                for indicator in phpinfo_indicators:
                    if indicator in resp.text:
                        result['accessible'] = True
                        result['urls'].append(urljoin(self.target_url, path))
                        break
        
        return result
    
    def _detect_from_errors(self) -> Dict:
        """
        Detect PHP configuration from error messages.
        
        Returns:
            Dict with error configuration info
        """
        result = {
            'display_errors': False,
        }
        
        # Test paths that might trigger errors
        test_paths = [
            '/?test[]=1',  # Array to string conversion
            '/?page[]=test',
            '/wp-content/plugins/nonexistent/',
            '/index.php/nonexistent',
        ]
        
        for path in test_paths:
            resp = self.browser.get(path)
            if not resp:
                continue
            
            # Check for PHP error patterns
            error_indicators = [
                r'<b>Warning</b>:',
                r'<b>Notice</b>:',
                r'<b>Fatal error</b>:',
                r'<b>Parse error</b>:',
                r'on line <b>\d+</b>',
                r'in <b>/[^<]+</b> on line',
                r'PHP (Warning|Notice|Error|Fatal)',
                r'Stack trace:',
                r'#\d+ /[^(]+\(\d+\):',
                r'Array to string conversion',
                r'Undefined index:',
                r'Undefined variable:',
                r'Division by zero',
            ]
            
            for pattern in error_indicators:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    result['display_errors'] = True
                    return result
        
        return result
    
    def _detect_from_headers(self) -> Dict:
        """
        Detect PHP configuration from HTTP headers.
        
        Returns:
            Dict with header configuration info
        """
        result = {
            'expose_php': False,
            'php_version': None,
        }
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        # Check X-Powered-By header
        powered_by = resp.headers.get('X-Powered-By', '')
        if powered_by and 'PHP' in powered_by:
            result['expose_php'] = True
            
            # Extract version
            version_match = re.search(r'PHP/([\d.]+)', powered_by)
            if version_match:
                result['php_version'] = version_match.group(1)
        
        return result
    
    def _detect_session_config(self) -> Dict:
        """
        Detect session cookie configuration.
        
        Returns:
            Dict with session config info
        """
        result = {
            'weak': False,
            'missing_httponly': False,
            'missing_secure': False,
            'missing_samesite': False,
        }
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        # Check Set-Cookie headers
        set_cookies = resp.headers.get('Set-Cookie', '')
        if not set_cookies:
            # Try multiple cookies
            cookies = resp.cookies if hasattr(resp, 'cookies') else []
            if not cookies:
                return result
        
        # Analyze cookie attributes
        cookie_header = set_cookies.lower() if set_cookies else ''
        
        if 'httponly' not in cookie_header:
            result['missing_httponly'] = True
            result['weak'] = True
        
        if 'secure' not in cookie_header:
            result['missing_secure'] = True
            result['weak'] = True
        
        if 'samesite' not in cookie_header:
            result['missing_samesite'] = True
            result['weak'] = True
        
        return result
    
    def _check_source_disclosure(self) -> List[Dict]:
        """
        Check for PHP source code disclosure.
        
        Returns:
            List of exposed source files
        """
        exposed = []
        
        for path in self.source_paths:
            resp = self.browser.get(path)
            
            if resp and resp.status_code == 200:
                content = resp.text[:500]
                
                # Check if it looks like PHP source code
                php_indicators = [
                    '<?php',
                    '<?=',
                    'namespace ',
                    'use \\',
                    'function ',
                    'class ',
                    'define(',
                    '$GLOBALS',
                    'require_once',
                    'include_once',
                    'wp-config',
                    'DB_NAME',
                    'DB_USER',
                    'DB_PASSWORD',
                ]
                
                for indicator in php_indicators:
                    if indicator in content:
                        exposed.append({
                            'path': path,
                            'status': resp.status_code,
                            'size': len(resp.text),
                            'content_preview': content[:200],
                        })
                        break
        
        return exposed