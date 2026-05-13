#!/usr/bin/env python3
"""
WordPress XML-RPC Security Scanner.
Tests XML-RPC interface for security vulnerabilities.

References:
    - WordPress XML-RPC: https://codex.wordpress.org/XML-RPC_WordPress_API
    - Brute Force via XML-RPC: https://blog.sucuri.net/
"""

import re
import time
from typing import Dict, List, Optional
from loguru import logger


class Scanner:
    """WordPress XML-RPC security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress XML-RPC Analysis"
    
    def run(self) -> Dict:
        """Execute XML-RPC security tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'xmlrpc_enabled': False,
            'pingback_enabled': False,
            'brute_force_possible': False,
            'methods_available': [],
            'findings': []
        }
        
        # Check if XML-RPC is accessible
        resp = self.browser.get('/xmlrpc.php')
        if not resp or resp.status_code != 200:
            result['findings'].append({
                'title': 'XML-RPC is not accessible',
                'severity': 'info',
                'description': 'XML-RPC endpoint is not available.',
                'recommendation': 'No action needed.',
                'module': self.module_name,
            })
            return result
        
        result['xmlrpc_enabled'] = True
        
        # Test system.listMethods
        methods = self._test_list_methods()
        result['methods_available'] = methods
        
        if methods:
            self.findings.append({
                'title': f"XML-RPC enabled with {len(methods)} methods available",
                'severity': 'medium',
                'description': (
                    f"XML-RPC is enabled. Available methods: {', '.join(methods[:10])}. "
                    "XML-RPC can be used for brute-force attacks and DDoS amplification."
                ),
                'recommendation': (
                    "1. Disable XML-RPC if not needed:\n"
                    "   Add to .htaccess: <Files xmlrpc.php> Deny from all </Files>\n"
                    "2. Or use a plugin like 'Disable XML-RPC'\n"
                    "3. If needed, restrict to specific IPs\n"
                    "4. Implement rate limiting"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-749',
                'cvss_score': 5.0,
            })
        
        # Test for multicall brute force
        brute_result = self._test_multicall_brute_force()
        result['brute_force_possible'] = brute_result
        
        if brute_result:
            self.findings.append({
                'title': 'XML-RPC multicall brute force possible',
                'severity': 'high',
                'description': (
                    "The system.multicall method allows testing multiple passwords "
                    "in a single request, enabling efficient brute-force attacks."
                ),
                'recommendation': (
                    "1. Disable XML-RPC immediately\n"
                    "2. Install Wordfence or similar security plugin\n"
                    "3. Implement fail2ban for wp-login\n"
                    "4. Use strong passwords and 2FA"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-307',
                'cvss_score': 7.5,
            })
        
        # Test pingback vulnerability
        ping_result = self._test_pingback()
        result['pingback_enabled'] = ping_result
        
        if ping_result:
            self.findings.append({
                'title': 'XML-RPC pingback enabled (potential DDoS amplification)',
                'severity': 'medium',
                'description': (
                    "The pingback.ping method is enabled. This can be abused for "
                    "DDoS amplification attacks against other sites."
                ),
                'recommendation': (
                    "1. Disable pingback by adding to functions.php:\n"
                    "   add_filter('xmlrpc_methods', function($methods) {\n"
                    "       unset($methods['pingback.ping']);\n"
                    "       return $methods;\n"
                    "   });\n"
                    "2. Or disable XML-RPC entirely"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-406',
                'cvss_score': 5.3,
            })
        
        result['findings'] = self.findings
        return result
    
    def _test_list_methods(self) -> List[str]:
        """Test for available XML-RPC methods."""
        xml_payload = """<?xml version="1.0"?>
        <methodCall>
            <methodName>system.listMethods</methodName>
            <params></params>
        </methodCall>"""
        
        resp = self.browser.post('/xmlrpc.php', data=xml_payload)
        if not resp or resp.status_code != 200:
            return []
        
        methods = []
        method_matches = re.findall(r'<string>(.+?)</string>', resp.text)
        
        for method in method_matches:
            methods.append(method)
        
        return methods
    
    def _test_multicall_brute_force(self) -> bool:
        """Test if multicall brute force is possible."""
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
        <methodCall>
            <methodName>system.multicall</methodName>
            <params>
                <param><value><array><data>
                    <value><struct>
                        <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
                        <member><name>params</name><value><array><data>
                            <value><string>admin</string></value>
                            <value><string>test123</string></value>
                        </data></array></value></member>
                    </struct></value>
                </data></array></value></param>
            </params>
        </methodCall>"""
        
        resp = self.browser.post('/xmlrpc.php', data=xml_payload)
        
        if resp and resp.status_code == 200:
            # Check if response indicates authentication attempt was processed
            if 'faultCode' in resp.text or 'Incorrect' in resp.text:
                return True
        
        return False
    
    def _test_pingback(self) -> bool:
        """Test if pingback is enabled."""
        xml_payload = """<?xml version="1.0"?>
        <methodCall>
            <methodName>pingback.ping</methodName>
            <params>
                <param><value><string>http://example.com/</string></value></param>
                <param><value><string>{target}</string></value></param>
            </params>
        </methodCall>""".format(target=self.target_url)
        
        resp = self.browser.post('/xmlrpc.php', data=xml_payload)
        
        if resp and resp.status_code == 200:
            if 'faultCode' in resp.text:
                # Pingback is enabled but returned an error (expected for invalid URLs)
                return True
        
        return False