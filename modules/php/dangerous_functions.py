#!/usr/bin/env python3
"""
PHP Dangerous Functions Detection Module.
Identifies usage of dangerous PHP functions through source code analysis
and runtime detection methods.

References:
    - PHP Security: https://www.php.net/manual/en/security.php
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
    - CWE-78: OS Command Injection
    - CWE-94: Code Injection
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger

from modules.php import DANGEROUS_FUNCTIONS


class Scanner:
    """PHP dangerous functions detection scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize dangerous functions scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "PHP Dangerous Functions Detection"
        
        # Test parameters for function injection
        self.test_params = {
            'command_injection': [
                ';id;',
                '|id',
                '`id`',
                '$(id)',
                '& id &',
                '|| id',
                '&& id',
            ],
            'code_injection': [
                '<?php phpinfo(); ?>',
                '<?= phpinfo() ?>',
                'eval("phpinfo()")',
                'system("id")',
            ],
        }
        
        # Functions to test for in error messages
        self.disabled_function_indicators = [
            'has been disabled for security reasons',
            'function is disabled',
            'has been disabled',
            'is not available',
        ]
    
    def run(self) -> Dict:
        """
        Execute dangerous functions detection.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'dangerous_functions_detected': [],
            'disabled_functions_detected': [],
            'command_injection_possible': False,
            'code_injection_possible': False,
            'findings': []
        }
        
        # Stage 1: Check for dangerous functions in source disclosure
        source_functions = self._check_source_code_functions()
        if source_functions:
            result['dangerous_functions_detected'].extend(source_functions)
        
        # Stage 2: Test for command injection
        cmd_result = self._test_command_injection()
        result['command_injection_possible'] = cmd_result['possible']
        
        if cmd_result['possible']:
            self.findings.append({
                'title': 'PHP command injection may be possible',
                'severity': 'critical',
                'description': (
                    "The application appears to execute user input as system commands. "
                    "This could allow remote code execution on the server."
                ),
                'recommendation': (
                    "1. Never pass user input to: exec(), system(), passthru(), shell_exec()\n"
                    "2. Use escapeshellcmd() and escapeshellarg() if shell commands are necessary\n"
                    "3. Consider using PHP libraries instead of shell commands\n"
                    "4. Set disable_functions in php.ini to block dangerous functions"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-78',
                'cvss_score': 9.8,
                'evidence': cmd_result.get('evidence', ''),
            })
        
        # Stage 3: Test for code injection
        code_result = self._test_code_injection()
        result['code_injection_possible'] = code_result['possible']
        
        if code_result['possible']:
            self.findings.append({
                'title': 'PHP code injection may be possible (eval/assert)',
                'severity': 'critical',
                'description': (
                    "The application appears to evaluate user input as PHP code. "
                    "This could allow arbitrary code execution on the server."
                ),
                'recommendation': (
                    "1. Never use eval() or assert() with user input\n"
                    "2. Never use preg_replace() with /e modifier\n"
                    "3. Avoid create_function() (deprecated)\n"
                    "4. Use call_user_func() or call_user_func_array() with caution\n"
                    "5. Set disable_functions in php.ini"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-94',
                'cvss_score': 9.8,
                'evidence': code_result.get('evidence', ''),
            })
        
        # Stage 4: Check for disabled function indicators
        disabled = self._check_disabled_functions()
        result['disabled_functions_detected'] = disabled
        
        if disabled:
            # Good news - functions are disabled
            self.findings.append({
                'title': f"Some dangerous PHP functions are disabled: {', '.join(disabled[:10])}",
                'severity': 'info',
                'description': (
                    f"The following functions appear to be disabled: {', '.join(disabled[:10])}. "
                    "This is a good security practice."
                ),
                'recommendation': (
                    "Ensure all dangerous functions are disabled:\n"
                    "disable_functions = exec,system,passthru,shell_exec,"
                    "proc_open,popen,curl_exec,curl_multi_exec,"
                    "parse_ini_file,show_source"
                ),
                'module': self.module_name,
            })
        
        # Stage 5: Report on dangerous functions found in source
        if source_functions:
            for func_info in source_functions:
                self.findings.append({
                    'title': f"Dangerous PHP function found: {func_info['function']}",
                    'severity': func_info['severity'],
                    'description': (
                        f"The dangerous function '{func_info['function']}' was detected. "
                        f"Category: {func_info.get('category', 'unknown')}\n"
                        f"Context: {func_info.get('context', 'N/A')[:200]}"
                    ),
                    'recommendation': (
                        "Review the usage of this function and consider:\n"
                        "1. Removing it if not needed\n"
                        "2. Using safer alternatives\n"
                        "3. Adding it to disable_functions in php.ini\n"
                        "4. Implementing proper input validation"
                    ),
                    'module': self.module_name,
                    'cwe_id': func_info.get('cwe', 'CWE-94'),
                    'cvss_score': 9.0 if func_info['severity'] == 'critical' else 7.0,
                    'evidence': func_info.get('context', '')[:200],
                })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Functions found: {len(source_functions)}, "
            f"CMD injection: {result['command_injection_possible']}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _check_source_code_functions(self) -> List[Dict]:
        """
        Check for dangerous functions in exposed PHP source code.
        
        Returns:
            List of dangerous function findings
        """
        functions_found = []
        
        # Paths where PHP source might be exposed
        source_paths = [
            '/index.phps',
            '/index.php.bak',
            '/wp-config.phps',
            '/wp-config.php.bak',
            '/config.phps',
        ]
        
        for path in source_paths:
            resp = self.browser.get(path)
            if not resp or resp.status_code != 200:
                continue
            
            content = resp.text
            
            # Search for dangerous functions
            for category, category_info in DANGEROUS_FUNCTIONS.items():
                for func_name in category_info['functions']:
                    # Look for function calls: func_name(
                    pattern = rf'\b{re.escape(func_name)}\s*\('
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        # Get context around the match
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 100)
                        context = content[start:end].strip()
                        
                        functions_found.append({
                            'function': func_name,
                            'category': category,
                            'severity': category_info['severity'],
                            'cwe': category_info.get('cwe'),
                            'context': context,
                            'source': path,
                        })
        
        return functions_found
    
    def _test_command_injection(self) -> Dict:
        """
        Test for command injection vulnerabilities.
        
        Returns:
            Dict with command injection test results
        """
        result = {
            'possible': False,
            'evidence': '',
        }
        
        # Test common injection points
        test_paths = [
            '/?cmd=;id;',
            '/?exec=;id;',
            '/?command=;id;',
            '/?action=;id;',
            '/?page=;id;',
        ]
        
        for path in test_paths:
            resp = self.browser.get(path)
            if not resp:
                continue
            
            # Check for command output indicators
            cmd_indicators = [
                r'uid=\d+',
                r'gid=\d+',
                r'groups=\d+',
                r'root:x:0:0',
                r'bin:x:1:1',
                r'daemon:x:2:2',
            ]
            
            for indicator in cmd_indicators:
                if re.search(indicator, resp.text, re.IGNORECASE):
                    result['possible'] = True
                    result['evidence'] = f"Command output detected at {path}"
                    return result
        
        return result
    
    def _test_code_injection(self) -> Dict:
        """
        Test for PHP code injection vulnerabilities.
        
        Returns:
            Dict with code injection test results
        """
        result = {
            'possible': False,
            'evidence': '',
        }
        
        # Test parameters that might be eval'd
        test_payloads = [
            ';phpinfo();',
            ';system("id");',
            '".phpinfo()."',
        ]
        
        for payload in test_payloads:
            resp = self.browser.get(f'/?test={payload}')
            if not resp:
                continue
            
            # Check for phpinfo output
            phpinfo_indicators = [
                'PHP Version',
                'System</td>',
                'phpinfo()',
                'Configure Command',
            ]
            
            for indicator in phpinfo_indicators:
                if indicator in resp.text:
                    result['possible'] = True
                    result['evidence'] = f"phpinfo() output detected with payload: {payload}"
                    return result
        
        return result
    
    def _check_disabled_functions(self) -> List[str]:
        """
        Check for indicators that dangerous functions are disabled.
        
        Returns:
            List of disabled function names
        """
        disabled = []
        
        # Test common disabled functions
        test_functions = [
            'exec', 'system', 'passthru', 'shell_exec',
            'popen', 'proc_open', 'eval', 'assert',
        ]
        
        for func_name in test_functions:
            resp = self.browser.get(f'/?{func_name}=test')
            if not resp:
                continue
            
            for indicator in self.disabled_function_indicators:
                if indicator in resp.text.lower() and func_name in resp.text.lower():
                    disabled.append(func_name)
                    break
        
        return disabled