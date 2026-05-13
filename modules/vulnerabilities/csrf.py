#!/usr/bin/env python3
"""
Cross-Site Request Forgery (CSRF) vulnerability scanner.
Tests for missing or weak CSRF protections.

References:
    - OWASP: https://owasp.org/www-community/attacks/csrf
    - CWE-352: Cross-Site Request Forgery (CSRF)
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """Cross-Site Request Forgery (CSRF) vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize CSRF scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Cross-Site Request Forgery (CSRF)"
        
        # Common CSRF token names
        self.csrf_token_names = [
            'csrf', 'csrf_token', 'csrf-token', '_csrf', '_csrf_token',
            'xsrf', '_xsrf', 'token', 'authenticity_token',
            'nonce', '_token', 'request_token', 'form_token',
            'wpnonce', '_wpnonce', 'woocommerce', 'security',
            'synchronizer_token', 'anticsrf', '__RequestVerificationToken',
        ]
        
        # Sensitive actions that should be CSRF-protected
        self.sensitive_actions = [
            'delete', 'remove', 'update', 'edit', 'create',
            'add', 'change', 'modify', 'save', 'submit',
            'upload', 'transfer', 'send', 'post', 'publish',
            'activate', 'deactivate', 'enable', 'disable',
            'password', 'email', 'profile', 'settings',
        ]
    
    def run(self) -> Dict:
        """
        Execute CSRF vulnerability tests.
        
        Returns:
            Dict with findings and test results
        """
        logger.info(f"Starting {self.module_name} scan")
        
        result = {
            'module': self.module_name,
            'forms_tested': [],
            'vulnerable_forms': [],
            'cookie_analysis': {},
            'findings': []
        }
        
        # Find all forms
        forms = self._find_forms()
        
        for form in forms:
            result['forms_tested'].append({
                'action': form['action'],
                'method': form['method'],
            })
            
            # Test form for CSRF protection
            issues = self._analyze_form_protection(form)
            
            if issues:
                result['vulnerable_forms'].append({
                    'action': form['action'],
                    'method': form['method'],
                    'issues': issues
                })
        
        # Analyze cookies for SameSite attribute
        result['cookie_analysis'] = self._analyze_cookies()
        
        # Check SameSite cookie attribute
        if result['cookie_analysis'].get('missing_samesite'):
            self.findings.append({
                'title': 'Missing SameSite Cookie Attribute',
                'severity': 'medium',
                'description': (
                    f"Session cookies are missing the SameSite attribute. "
                    f"Affected cookies: {', '.join(result['cookie_analysis']['missing_samesite'])}"
                ),
                'recommendation': (
                    "Set SameSite=Lax or SameSite=Strict on all session cookies to prevent CSRF attacks."
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-1275',
                'cvss_score': 5.4,
                'references': [
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite',
                ]
            })
        
        # Generate findings for vulnerable forms
        for vuln in result['vulnerable_forms']:
            for issue in vuln['issues']:
                self.findings.append({
                    'title': f"Missing CSRF Protection in {vuln['method']} {vuln['action']}",
                    'severity': 'high' if any(
                        action in vuln['action'].lower() 
                        for action in self.sensitive_actions
                    ) else 'medium',
                    'description': (
                        f"The form at {vuln['action']} ({vuln['method']} method) "
                        f"lacks CSRF protection: {issue}"
                    ),
                    'recommendation': (
                        "1. Add unique CSRF tokens to all state-changing forms\n"
                        "2. Validate CSRF tokens on the server side\n"
                        "3. Set SameSite=Lax on session cookies\n"
                        "4. Use custom request headers for API calls\n"
                        "5. Implement origin verification (Origin/Referer headers)\n"
                        "6. Use double-submit cookie pattern for stateless APIs"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-352',
                    'cvss_score': 6.5,
                    'evidence': issue,
                    'references': [
                        'https://owasp.org/www-community/attacks/csrf',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
                    ]
                })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} issues")
        return result
    
    def _find_forms(self) -> List[Dict]:
        """Find all forms on the website."""
        forms = []
        visited_urls = set()
        urls_to_visit = [self.target_url]
        
        # Common paths to check
        paths_to_check = [
            '/', '/login', '/register', '/profile', '/settings',
            '/account', '/admin', '/dashboard', '/contact',
            '/checkout', '/cart', '/payment', '/transfer',
            '/password/reset', '/email/change',
        ]
        
        for path in paths_to_check:
            full_url = urljoin(self.target_url, path)
            if full_url not in visited_urls:
                urls_to_visit.append(full_url)
        
        for url in urls_to_visit[:10]:  # Limit to 10 pages
            if url in visited_urls:
                continue
            
            visited_urls.add(url)
            resp = self.browser.get(url)
            
            if not resp or resp.status_code != 200:
                continue
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                
                form_data = {
                    'action': urljoin(url, action) if action else url,
                    'method': method,
                    'inputs': [],
                    'has_csrf_token': False,
                    'csrf_token_name': None,
                }
                
                # Analyze inputs
                for input_tag in form.find_all('input'):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                    }
                    form_data['inputs'].append(input_data)
                    
                    # Check if this is a CSRF token
                    input_name = input_data['name'].lower()
                    for token_name in self.csrf_token_names:
                        if token_name in input_name:
                            form_data['has_csrf_token'] = True
                            form_data['csrf_token_name'] = input_data['name']
                            break
                
                forms.append(form_data)
        
        return forms
    
    def _analyze_form_protection(self, form: Dict) -> List[str]:
        """
        Analyze a form for CSRF protection.
        
        Args:
            form: Form data dictionary
        
        Returns:
            List of issues found
        """
        issues = []
        
        # Skip forms with no action
        if not form['action']:
            return issues
        
        # Skip GET forms (should not be used for state changes)
        if form['method'] == 'GET':
            return issues
        
        # Check for CSRF token
        if not form['has_csrf_token']:
            issues.append("No CSRF token found in form")
        
        # Check if token is guessable/predictable
        if form['has_csrf_token']:
            # Extract token value
            for input_field in form['inputs']:
                if input_field['name'] == form.get('csrf_token_name'):
                    token_value = input_field.get('value', '')
                    
                    # Check for weak tokens
                    if len(token_value) < 16:
                        issues.append(f"CSRF token too short ({len(token_value)} characters)")
                    
                    if token_value.isdigit():
                        issues.append("CSRF token appears to be a simple integer")
                    
                    if token_value.lower() in ['null', 'undefined', 'none', '']:
                        issues.append(f"CSRF token has invalid value: '{token_value}'")
                    
                    break
        
        # Check for sensitive actions without CSRF
        action_lower = form['action'].lower()
        for sensitive_action in self.sensitive_actions:
            if sensitive_action in action_lower and not form['has_csrf_token']:
                issues.append(
                    f"Sensitive action '{sensitive_action}' lacks CSRF protection"
                )
                break
        
        # Check for custom header requirement (alternative to CSRF tokens)
        # This is checked by looking at JavaScript that sets custom headers
        
        return issues
    
    def _analyze_cookies(self) -> Dict:
        """
        Analyze cookies for SameSite and Secure attributes.
        
        Returns:
            Dict with cookie analysis
        """
        analysis = {
            'total_cookies': 0,
            'session_cookies': [],
            'missing_samesite': [],
            'missing_secure': [],
            'samesite_lax': [],
            'samesite_strict': [],
            'samesite_none': [],
        }
        
        resp = self.browser.get('/')
        if not resp:
            return analysis
        
        # Parse Set-Cookie headers from response
        cookies = resp.headers.get('Set-Cookie', '')
        if not cookies:
            return analysis
        
        cookie_list = cookies.split(',')
        analysis['total_cookies'] = len(cookie_list)
        
        for cookie_str in cookie_list:
            cookie_str = cookie_str.strip()
            
            # Extract cookie name
            cookie_name = cookie_str.split('=')[0].strip().lower()
            
            # Check if it's a session cookie
            session_indicators = ['session', 'sess', 'sid', 'auth', 'token', 'jwt']
            is_session = any(indicator in cookie_name for indicator in session_indicators)
            
            if is_session:
                analysis['session_cookies'].append(cookie_name)
                
                # Check SameSite
                if 'samesite' not in cookie_str.lower():
                    analysis['missing_samesite'].append(cookie_name)
                elif 'samesite=lax' in cookie_str.lower():
                    analysis['samesite_lax'].append(cookie_name)
                elif 'samesite=strict' in cookie_str.lower():
                    analysis['samesite_strict'].append(cookie_name)
                elif 'samesite=none' in cookie_str.lower():
                    analysis['samesite_none'].append(cookie_name)
                
                # Check Secure flag
                if 'secure' not in cookie_str.lower():
                    analysis['missing_secure'].append(cookie_name)
        
        return analysis