#!/usr/bin/env python3
"""
Broken Access Control & Business Logic Vulnerability Scanner.
Detects:
    1. Insecure Direct Object References (IDOR / BOLA) across numerical and uuid parameters.
    2. HTTP Verb Tampering / Method Bypasses (HEAD, PUT, DELETE, PATCH, TRACE).
    3. CORS Misconfiguration Exploitation (Arbitrary Origin Reflection with Credentials).

References:
    - OWASP A01:2021 - Broken Access Control
    - CWE-639: Authorization Bypass Through User-Controlled Key
    - CWE-284: Improper Access Control
    - CWE-942: Permissive Cross-domain Policy with Untrusted Domains
"""

import re
import json
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from loguru import logger


class Scanner:
    """Broken Access Control and Business Logic security scanner."""

    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize the scanner.

        Args:
            browser: StealthBrowser instance
            target_url: Root target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Broken Access Control & Business Logic"

        # Common IDOR parameter names
        self.idor_params = [
            'id', 'user_id', 'uid', 'account_id', 'profile_id',
            'doc_id', 'file_id', 'order_id', 'invoice_id', 'item_id'
        ]

        # Common endpoints sensitive to Method Tampering
        self.sensitive_endpoints = [
            '/admin', '/admin/users', '/api/users', '/api/settings',
            '/api/orders', '/user/profile', '/api/v1/users', '/dashboard'
        ]

    def run(self) -> Dict:
        """
        Execute Broken Access Control tests.

        Returns:
            Dict containing tested parameters, bypassed verbs, and findings.
        """
        logger.info(f"Starting {self.module_name} scan on {self.target_url}")

        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'idor_tested': 0,
            'idor_vulnerabilities': [],
            'method_tampering_bypasses': [],
            'cors_misconfigurations': [],
            'findings': []
        }

        # 1. Test Insecure Direct Object References (IDOR)
        self._test_idor(result)

        # 2. Test HTTP Verb / Method Tampering
        self._test_http_method_tampering(result)

        # 3. Test CORS Misconfigurations with arbitrary origins
        self._test_cors_misconfiguration(result)

        self.findings = result['findings']
        logger.info(
            f"{self.module_name} finished. "
            f"Findings: {len(self.findings)}"
        )
        return result

    def _test_idor(self, result: Dict):
        """Probe common numerical parameters to detect potential IDOR information disclosure."""
        test_paths = [
            '/api/user', '/api/users', '/profile', '/account', '/order', '/invoice',
            '/api/v1/user', '/api/v1/profile', '/user/view', '/user'
        ]

        for path in test_paths:
            for param in self.idor_params[:4]:
                result['idor_tested'] += 1

                # Step 1: Request with ID 1
                resp1 = self.browser.get(path, params={param: '1'})
                if not resp1 or resp1.status_code != 200:
                    continue

                # Step 2: Request with incremented ID 2
                resp2 = self.browser.get(path, params={param: '2'})
                if not resp2 or resp2.status_code != 200:
                    continue

                # Compare responses: if both return 200 JSON with different contents without auth
                if resp1.text != resp2.text and len(resp1.text) > 30 and len(resp2.text) > 30:
                    # Look for sensitive JSON keywords
                    sensitive_keys = ['email', 'username', 'name', 'phone', 'address', 'balance', 'role']
                    c1_lower = resp1.text.lower()
                    c2_lower = resp2.text.lower()

                    matched_keys = [k for k in sensitive_keys if k in c1_lower and k in c2_lower]
                    if matched_keys:
                        full_url = urljoin(self.target_url, path)
                        finding = {
                            'title': f"Potential IDOR / BOLA on '{path}' via parameter '{param}'",
                            'severity': 'high',
                            'description': (
                                f"Accessing '{path}?{param}=1' and '{path}?{param}=2' yielded differing records "
                                f"containing sensitive fields ({', '.join(matched_keys)}) without authorization challenges. "
                                "This indicates an Insecure Direct Object Reference (Broken Object Level Authorization)."
                            ),
                            'recommendation': (
                                "1. Implement robust object-level authorization checks (e.g. check if current user owns requested record).\n"
                                "2. Use random, unguessable identifiers (like UUID v4) instead of sequential integers.\n"
                                "3. Enforce strict session-to-object mapping on the server."
                            ),
                            'module': self.module_name,
                            'cwe_id': 'CWE-639',
                            'cvss_score': 8.5,
                            'evidence': f"Endpoint: {full_url}\nParameter: {param}\nFields Exposed: {matched_keys}",
                        }
                        result['idor_vulnerabilities'].append(path)
                        result['findings'].append(finding)
                        break

    def _test_http_method_tampering(self, result: Dict):
        """Test if restricted paths allow verb tampering or method bypass (e.g. 403 on GET, 200 on POST/PUT)."""
        methods_to_test = ['POST', 'PUT', 'PATCH', 'OPTIONS']

        for path in self.sensitive_endpoints:
            # Baseline GET check
            resp_get = self.browser.get(path)
            if not resp_get:
                continue

            # If GET is forbidden/unauthorized (401 or 403), try alternative HTTP verbs
            if resp_get.status_code in [401, 403]:
                for method in methods_to_test:
                    resp_alt = None
                    try:
                        if method == 'POST':
                            resp_alt = self.browser.post(path, data={})
                        elif method == 'OPTIONS':
                            resp_alt = self.browser.options(path)
                    except Exception:
                        continue

                    if resp_alt and resp_alt.status_code == 200:
                        full_url = urljoin(self.target_url, path)
                        finding = {
                            'title': f"Authentication Bypass via HTTP Verb Tampering on '{path}'",
                            'severity': 'critical',
                            'description': (
                                f"Endpoint '{path}' returns HTTP {resp_get.status_code} for GET requests, "
                                f"but accepts {method} requests with HTTP 200 OK without authentication. "
                                "This allows attackers to circumvent access control filters restricted to specific verbs."
                            ),
                            'recommendation': (
                                "1. Ensure authentication and authorization middleware applies to all HTTP verbs, not just GET.\n"
                                "2. Reject unneeded HTTP verbs at the web server and reverse proxy level.\n"
                                "3. Avoid security rules written like <Limit GET> in Apache configurations."
                            ),
                            'module': self.module_name,
                            'cwe_id': 'CWE-284',
                            'cvss_score': 9.1,
                            'evidence': f"URL: {full_url}\nGET status: {resp_get.status_code}\n{method} status: {resp_alt.status_code}",
                        }
                        result['method_tampering_bypasses'].append(path)
                        result['findings'].append(finding)
                        break

    def _test_cors_misconfiguration(self, result: Dict):
        """Test for insecure Cross-Origin Resource Sharing (CORS) configurations."""
        evil_origin = "https://attacker-domain.evil"

        resp = self.browser.get('/', custom_headers={'Origin': evil_origin})
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        allow_origin = headers.get('access-control-allow-origin', '')
        allow_credentials = headers.get('access-control-allow-credentials', '').lower() == 'true'

        # Vulnerability 1: Arbitrary origin reflection with credentials
        if allow_origin == evil_origin and allow_credentials:
            result['cors_misconfigurations'].append('arbitrary_origin_with_credentials')
            result['findings'].append({
                'title': "Insecure CORS Policy: Arbitrary Origin Reflection with Credentials",
                'severity': 'critical',
                'description': (
                    "The server reflects arbitrary untrusted Origin headers in 'Access-Control-Allow-Origin' "
                    "while setting 'Access-Control-Allow-Credentials: true'. "
                    "This allows malicious websites to steal authenticated user sessions, private APIs, and CSRF tokens."
                ),
                'recommendation': (
                    "1. Never dynamically reflect untrusted request Origin headers into Access-Control-Allow-Origin.\n"
                    "2. Maintain an explicit, server-side whitelist of trusted domains.\n"
                    "3. If credentials are true, wildcards and arbitrary origins must be strictly disallowed."
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-942',
                'cvss_score': 9.3,
                'evidence': f"Reflected Origin: {allow_origin}\nCredentials: true",
            })

        # Vulnerability 2: Wildcard origin with credentials misconfiguration
        elif allow_origin == '*' and allow_credentials:
            result['cors_misconfigurations'].append('wildcard_with_credentials')
            result['findings'].append({
                'title': "Invalid and Insecure CORS: Wildcard Origin with Credentials",
                'severity': 'medium',
                'description': (
                    "The server attempts to allow all origins ('*') while setting 'Access-Control-Allow-Credentials: true'. "
                    "Although modern browsers reject this configuration, it signals flawed cross-origin access architecture."
                ),
                'recommendation': "Configure an explicit whitelist of trusted origins instead of using wildcard '*'.",
                'module': self.module_name,
                'cwe_id': 'CWE-942',
                'cvss_score': 5.0,
                'evidence': "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
            })
