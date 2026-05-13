#!/usr/bin/env python3
"""
SQL Injection Vulnerability Scanner.
Tests for various SQL injection types including error-based, boolean-based,
time-based, and UNION-based SQL injection.

References:
    - OWASP: https://owasp.org/www-community/attacks/SQL_Injection
    - PortSwigger: https://portswigger.net/web-security/sql-injection
    - CWE-89: SQL Injection
"""

import re
import time
import string
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlencode, parse_qs, urlparse
from loguru import logger


class Scanner:
    """SQL Injection vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "SQL Injection Detection"
        
        # SQL injection payloads by type
        self.payloads = {
            'error': [
                "'",
                '"',
                "' OR '1'='1",
                '" OR "1"="1',
                "' OR '1'='1' --",
                "admin'--",
                "1' ORDER BY 1--",
                "1' ORDER BY 100--",
            ],
            'boolean': [
                ("1 AND 1=1", "1 AND 1=2"),
                ("1' AND '1'='1", "1' AND '1'='2"),
                ("1 AND 1=1--", "1 AND 1=2--"),
            ],
            'time': [
                "' OR SLEEP(3)--",
                "' OR pg_sleep(3)--",
                "'; WAITFOR DELAY '0:0:3'--",
                "1' AND SLEEP(3)--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
            ],
            'union': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
                "' UNION SELECT @@version--",
            ],
        }
        
        # Error patterns
        self.error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_.*',
            r'MySQLSyntaxErrorException',
            r'valid MySQL result',
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_.*',
            r'SQLite/JDBCDriver',
            r'System\.Data\.SQLite',
            r'\[SQL Server\]',
            r'ODBC SQL Server Driver',
            r'ORA-\d{5}',
            r'Oracle error',
            r'quoted string not properly terminated',
            r'unclosed quotation mark',
            r'SQL command not properly ended',
            r'Unclosed quotation mark',
            r'You have an error in your SQL syntax',
            r'Division by zero',
            r'Illegal mix of collations',
        ]
    
    def run(self) -> Dict:
        """Execute SQL injection vulnerability tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'urls_tested': [],
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'findings': []
        }
        
        # Discover test URLs
        test_urls = self._discover_urls()
        
        for url, params in test_urls:
            result['urls_tested'].append(url)
            
            if params:
                for param_name in params:
                    result['parameters_tested'].append(param_name)
                    
                    # Test for SQL injection
                    vuln_type = self._test_parameter(url, param_name, params)
                    
                    if vuln_type:
                        result['vulnerable_parameters'].append({
                            'url': url,
                            'parameter': param_name,
                            'type': vuln_type,
                        })
        
        # Generate findings
        for vuln in result['vulnerable_parameters']:
            self.findings.append({
                'title': f"SQL Injection in '{vuln['parameter']}' parameter",
                'severity': 'critical',
                'description': (
                    f"SQL Injection ({vuln['type']}) in '{vuln['parameter']}' "
                    f"at {vuln['url']}. SQL injection can lead to data theft, "
                    "modification, and complete database compromise."
                ),
                'recommendation': (
                    "1. Use parameterized queries (prepared statements)\n"
                    "2. Use stored procedures\n"
                    "3. Implement input validation\n"
                    "4. Apply least privilege to database users\n"
                    "5. Use ORM frameworks with built-in protections\n"
                    "6. Escape all user-supplied input"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-89',
                'cvss_score': 9.8,
                'evidence': f"Type: {vuln['type']}, URL: {vuln['url']}",
            })
        
        result['findings'] = self.findings
        return result
    
    def _discover_urls(self) -> List:
        """Discover URLs with parameters."""
        urls = []
        
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(self.target_url, action) if action else self.target_url
                
                inputs = {}
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name:
                        inputs[name] = input_tag.get('value', 'test')
                
                if inputs:
                    urls.append((form_url, inputs))
            
            # Find links with parameters
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if '?' in href:
                    parsed = urlparse(urljoin(self.target_url, href))
                    query_params = parse_qs(parsed.query)
                    if query_params:
                        urls.append((parsed.geturl().split('?')[0], query_params))
        
        # Add common test paths
        common_paths = [
            '/?id=1',
            '/?page=1',
            '/?product=1',
            '/?category=1',
            '/?user=1',
        ]
        
        for path in common_paths:
            parsed = urlparse(urljoin(self.target_url, path))
            query_params = parse_qs(parsed.query)
            if query_params:
                urls.append((parsed.geturl().split('?')[0], query_params))
        
        return urls[:20]
    
    def _test_parameter(self, url: str, param_name: str, params: Dict) -> Optional[str]:
        """Test a parameter for SQL injection."""
        # Test 1: Error-based
        for payload in self.payloads['error'][:5]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self.browser.get(url, params=test_params)
            if resp:
                for pattern in self.error_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return 'error_based'
        
        # Test 2: Time-based
        for payload in self.payloads['time'][:3]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            start = time.time()
            resp = self.browser.get(url, params=test_params)
            elapsed = time.time() - start
            
            if elapsed > 2.5:
                return 'time_based'
        
        # Test 3: Boolean-based
        for true_payload, false_payload in self.payloads['boolean'][:2]:
            # True request
            true_params = params.copy()
            true_params[param_name] = true_payload
            true_resp = self.browser.get(url, params=true_params)
            
            # False request
            false_params = params.copy()
            false_params[param_name] = false_payload
            false_resp = self.browser.get(url, params=false_params)
            
            if true_resp and false_resp:
                if len(true_resp.text) != len(false_resp.text):
                    return 'boolean_based'
        
        return None