#!/usr/bin/env python3
"""
WordPress REST API Security Scanner.
Tests WordPress REST API endpoints for security issues.

References:
    - WordPress REST API Handbook: https://developer.wordpress.org/rest-api/
    - OWASP API Security: https://owasp.org/www-project-api-security/
"""

import json
from typing import Dict, List, Optional
from loguru import logger


class Scanner:
    """WordPress REST API security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress REST API Analysis"
    
    def run(self) -> Dict:
        """Execute REST API security tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'rest_api_accessible': False,
            'namespaces': [],
            'user_endpoint_accessible': False,
            'settings_exposed': False,
            'findings': []
        }
        
        # Check REST API accessibility
        resp = self.browser.get('/wp-json/')
        if resp and resp.status_code == 200:
            result['rest_api_accessible'] = True
            
            try:
                data = json.loads(resp.text)
                result['namespaces'] = data.get('namespaces', [])
            except json.JSONDecodeError:
                pass
        
        if not result['rest_api_accessible']:
            return result
        
        # Test user endpoint
        user_access = self._test_user_endpoint()
        result['user_endpoint_accessible'] = user_access
        
        if user_access:
            self.findings.append({
                'title': 'WordPress REST API user endpoint accessible',
                'severity': 'medium',
                'description': (
                    "The /wp-json/wp/v2/users endpoint is publicly accessible. "
                    "This allows username enumeration and user data exposure."
                ),
                'recommendation': (
                    "1. Add to functions.php:\n"
                    "   add_filter('rest_authentication_errors', function($result) {\n"
                    "       if (!is_user_logged_in()) {\n"
                    "           return new WP_Error('rest_not_logged_in', 'Not authenticated');\n"
                    "       }\n"
                    "       return $result;\n"
                    "   });\n"
                    "2. Use a security plugin to restrict REST API access"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _test_user_endpoint(self) -> bool:
        """Test if user endpoint is accessible without authentication."""
        resp = self.browser.get('/wp-json/wp/v2/users')
        
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if isinstance(data, list) and len(data) > 0:
                    return True
            except json.JSONDecodeError:
                pass
        
        return False