#!/usr/bin/env python3
"""
REST API Security Scanner Module.
Tests for common REST API security vulnerabilities.

References:
    - OWASP API Security Top 10: https://owasp.org/www-project-api-security/
    - REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
"""

import json
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from loguru import logger


class Scanner:
    """REST API security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize REST API scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "REST API Security Analysis"
        
        # Common API path prefixes
        self.api_prefixes = [
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/api/v3/',
            '/rest/',
            '/rest/v1/',
            '/v1/',
            '/v2/',
            '/api/public/',
            '/api/private/',
            '/services/',
            '/webservice/',
            '/webservices/',
        ]
        
        # Common API endpoints to test
        self.common_endpoints = [
            'users', 'user', 'accounts', 'account',
            'admin', 'admins', 'administrator',
            'config', 'configuration', 'settings',
            'logs', 'audit', 'debug',
            'health', 'status', 'info', 'version',
            'swagger', 'openapi', 'docs',
            'tokens', 'sessions', 'auth',
        ]
        
        # HTTP methods to test
        self.http_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
        
        # Sensitive endpoints
        self.sensitive_endpoints = [
            '/api/users',
            '/api/admin',
            '/api/config',
            '/api/logs',
            '/api/debug',
            '/api/backup',
            '/api/export',
            '/api/import',
        ]
        
        # API documentation paths
        self.doc_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/openapi.json',
            '/openapi.yaml',
            '/api-docs',
            '/api-docs/',
            '/docs',
            '/docs/',
            '/swagger-ui.html',
            '/swagger/index.html',
            '/redoc',
        ]
    
    def run(self) -> Dict:
        """
        Execute REST API security tests.
        
        Returns:
            Dict with findings and comprehensive analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'api_detected': False,
            'api_endpoints_found': [],
            'documentation_exposed': False,
            'cors_misconfigured': False,
            'http_methods_exposed': {},
            'missing_authentication': [],
            'version_disclosure': [],
            'findings': []
        }
        
        # Stage 1: Discover API endpoints
        endpoints = self._discover_api_endpoints()
        result['api_endpoints_found'] = endpoints
        
        if endpoints:
            result['api_detected'] = True
        
        # Stage 2: Check API documentation exposure
        doc_exposure = self._check_documentation_exposure()
        result['documentation_exposed'] = doc_exposure['exposed']
        
        if doc_exposure['exposed']:
            result['findings'].append({
                'title': 'API documentation publicly exposed',
                'severity': 'medium',
                'description': (
                    f"API documentation is publicly accessible at: "
                    f"{', '.join(doc_exposure['paths'][:5])}. This reveals all API "
                    "endpoints, parameters, and data structures to attackers."
                ),
                'recommendation': (
                    "1. Restrict API documentation access to authenticated developers\n"
                    "2. Use environment-based documentation visibility\n"
                    "3. Remove documentation from production environments\n"
                    "4. Use IP whitelisting for documentation access\n"
                    "5. Consider using a developer portal with authentication"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
                'evidence': f"Documentation: {doc_exposure['paths'][:5]}",
            })
        
        # Stage 3: Check CORS configuration
        cors_result = self._check_cors_configuration()
        result['cors_misconfigured'] = cors_result['misconfigured']
        
        if cors_result['misconfigured']:
            result['findings'].append({
                'title': 'CORS misconfiguration detected',
                'severity': 'high',
                'description': (
                    f"CORS headers allow requests from: {cors_result.get('allowed_origins', 'any')}. "
                    "This could allow malicious websites to make authenticated API requests."
                ),
                'recommendation': (
                    "1. Restrict Access-Control-Allow-Origin to specific trusted domains\n"
                    "2. Never use 'Access-Control-Allow-Origin: *' with credentials\n"
                    "3. Validate Origin header on the server side\n"
                    "4. Use Access-Control-Allow-Credentials only when necessary"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-942',
                'cvss_score': 7.5,
                'evidence': f"CORS: {cors_result.get('allowed_origins')}",
            })
        
        # Stage 4: Test HTTP methods
        methods_result = self._test_http_methods()
        result['http_methods_exposed'] = methods_result
        
        if methods_result.get('dangerous_methods'):
            result['findings'].append({
                'title': f"Dangerous HTTP methods enabled: {', '.join(methods_result['dangerous_methods'])}",
                'severity': 'medium',
                'description': (
                    f"HTTP methods that could be dangerous are enabled: "
                    f"{', '.join(methods_result['dangerous_methods'])}. Methods like PUT "
                    "and DELETE could allow unauthorized modifications."
                ),
                'recommendation': (
                    "1. Disable unnecessary HTTP methods (PUT, DELETE, TRACE, OPTIONS)\n"
                    "2. Implement proper method-based authorization\n"
                    "3. Use HTTP method allowlists\n"
                    "4. Return 405 Method Not Allowed for disabled methods"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-749',
                'cvss_score': 5.0,
                'evidence': f"Methods: {methods_result['dangerous_methods']}",
            })
        
        # Stage 5: Check for missing authentication
        auth_result = self._check_authentication(endpoints)
        result['missing_authentication'] = auth_result['unprotected']
        
        if auth_result['unprotected']:
            result['findings'].append({
                'title': f"API endpoints without authentication: {', '.join(auth_result['unprotected'][:5])}",
                'severity': 'critical',
                'description': (
                    f"API endpoints accessible without authentication: "
                    f"{', '.join(auth_result['unprotected'][:5])}. This allows "
                    "unauthorized access to potentially sensitive data and functionality."
                ),
                'recommendation': (
                    "1. Implement authentication for all API endpoints\n"
                    "2. Use JWT, OAuth2, or API keys for authentication\n"
                    "3. Implement authorization middleware\n"
                    "4. Return 401 for unauthenticated requests\n"
                    "5. Consider using API gateway for centralized auth"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-306',
                'cvss_score': 9.0,
                'evidence': f"Endpoints: {auth_result['unprotected'][:5]}",
            })
        
        # Stage 6: Check version disclosure
        version_result = self._check_version_disclosure()
        result['version_disclosure'] = version_result['disclosed']
        
        if version_result['disclosed']:
            result['findings'].append({
                'title': 'API version information disclosed',
                'severity': 'low',
                'description': (
                    f"API version information is exposed: {version_result['versions']}. "
                    "Version disclosure helps attackers identify known vulnerabilities."
                ),
                'recommendation': (
                    "1. Remove version information from response headers\n"
                    "2. Remove X-Powered-By and Server headers\n"
                    "3. Configure web server to hide version details\n"
                    "4. Use generic error responses"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 3.0,
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Endpoints: {len(endpoints)}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _discover_api_endpoints(self) -> List[Dict]:
        """Discover REST API endpoints."""
        endpoints = []
        
        for prefix in self.api_prefixes:
            resp = self.browser.get(prefix)
            if resp and resp.status_code in [200, 401, 403]:
                content_type = resp.headers.get('Content-Type', '')
                
                if 'application/json' in content_type:
                    endpoints.append({
                        'url': urljoin(self.target_url, prefix),
                        'prefix': prefix,
                        'status': resp.status_code,
                    })
        
        # Check specific endpoints
        for endpoint in self.common_endpoints:
            for prefix in self.api_prefixes[:3]:
                path = f"{prefix}{endpoint}"
                resp = self.browser.head(path)
                if resp and resp.status_code not in [404]:
                    endpoints.append({
                        'url': urljoin(self.target_url, path),
                        'prefix': prefix,
                        'endpoint': endpoint,
                        'status': resp.status_code,
                    })
        
        return endpoints[:20]
    
    def _check_documentation_exposure(self) -> Dict:
        """Check if API documentation is exposed."""
        result = {
            'exposed': False,
            'paths': [],
        }
        
        for path in self.doc_paths:
            full_path = urljoin(self.target_url, path)
            resp = self.browser.get(path)
            
            if resp and resp.status_code == 200:
                is_doc = False
                
                # Check for Swagger/OpenAPI indicators
                swagger_indicators = [
                    '"swagger"', '"openapi"',
                    'swagger-ui', 'swagger',
                    'api-docs', 'paths',
                    '"info"', '"version"',
                ]
                
                for indicator in swagger_indicators:
                    if indicator in resp.text.lower():
                        is_doc = True
                        break
                
                if is_doc:
                    result['exposed'] = True
                    result['paths'].append(path)
        
        return result
    
    def _check_cors_configuration(self) -> Dict:
        """Check CORS configuration for misconfigurations."""
        result = {
            'misconfigured': False,
            'allowed_origins': None,
        }
        
        # Send request with Origin header
        headers = {'Origin': 'https://evil.com'}
        resp = self.browser.get('/', custom_headers=headers)
        
        if not resp:
            return result
        
        allow_origin = resp.headers.get('Access-Control-Allow-Origin', '')
        allow_credentials = resp.headers.get('Access-Control-Allow-Credentials', '')
        
        # Check for wildcard with credentials
        if allow_origin == '*' and allow_credentials.lower() == 'true':
            result['misconfigured'] = True
            result['allowed_origins'] = '* (with credentials)'
        
        # Check if origin is reflected
        if allow_origin == 'https://evil.com':
            result['misconfigured'] = True
            result['allowed_origins'] = 'Reflected (any origin)'
        
        # Check for null origin
        resp2 = self.browser.get('/', custom_headers={'Origin': 'null'})
        if resp2 and resp2.headers.get('Access-Control-Allow-Origin') == 'null':
            result['misconfigured'] = True
            result['allowed_origins'] = 'null (dangerous)'
        
        return result
    
    def _test_http_methods(self) -> Dict:
        """Test which HTTP methods are allowed."""
        result = {
            'allowed_methods': [],
            'dangerous_methods': [],
        }
        
        # Send OPTIONS request
        resp = self.browser.options('/api/')
        if not resp:
            resp = self.browser.options('/')
        
        if resp:
            allow_header = resp.headers.get('Allow', '')
            if allow_header:
                methods = [m.strip() for m in allow_header.split(',')]
                result['allowed_methods'] = methods
                
                dangerous = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
                for method in dangerous:
                    if method in methods:
                        result['dangerous_methods'].append(method)
        
        return result
    
    def _check_authentication(self, endpoints: List[Dict]) -> Dict:
        """Check for API endpoints without authentication."""
        result = {
            'unprotected': [],
        }
        
        test_endpoints = [e['url'] for e in endpoints[:10]]
        
        # Also test sensitive endpoints
        for endpoint in self.sensitive_endpoints:
            test_endpoints.append(urljoin(self.target_url, endpoint))
        
        for url in test_endpoints:
            path = url.replace(self.target_url, '')
            resp = self.browser.get(path)
            
            if resp and resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '')
                
                # If JSON response without authentication
                if 'application/json' in content_type:
                    try:
                        data = json.loads(resp.text)
                        # Check if response contains actual data (not error)
                        if isinstance(data, (dict, list)) and len(str(data)) > 20:
                            result['unprotected'].append(path)
                    except:
                        pass
        
        return result
    
    def _check_version_disclosure(self) -> Dict:
        """Check for API version information disclosure."""
        result = {
            'disclosed': False,
            'versions': [],
        }
        
        resp = self.browser.get('/')
        if resp:
            # Check headers
            version_headers = [
                'X-API-Version',
                'X-Version',
                'X-Powered-By',
                'Server',
                'X-AspNet-Version',
                'X-AspNetMvc-Version',
            ]
            
            for header in version_headers:
                value = resp.headers.get(header, '')
                if value:
                    result['disclosed'] = True
                    result['versions'].append(f"{header}: {value}")
        
        return result
    
    def options(self, path: str = '/') -> Optional[Dict]:
        """Send OPTIONS request (helper method)."""
        try:
            import requests
            url = urljoin(self.target_url, path)
            resp = requests.options(url, timeout=10, verify=False)
            return resp
        except:
            return None