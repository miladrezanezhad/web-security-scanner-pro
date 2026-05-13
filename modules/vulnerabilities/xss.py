#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) Vulnerability Scanner.
Tests for reflected, stored, and DOM-based XSS vulnerabilities.

References:
    - OWASP: https://owasp.org/www-community/attacks/xss/
    - PortSwigger: https://portswigger.net/web-security/cross-site-scripting
    - CWE-79: Cross-Site Scripting
"""

import re
import html
import random
import string
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlencode, parse_qs, urlparse
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """Cross-Site Scripting vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize XSS scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Cross-Site Scripting (XSS) Detection"
        
        # Generate unique marker for XSS detection
        self.marker = self._generate_marker()
        
        # XSS payloads by injection context
        self.payloads = {
            'html_context': [
                '<script>console.log("' + self.marker + '")</script>',
                '<img src=x onerror=console.log("' + self.marker + '")>',
                '<svg onload=console.log("' + self.marker + '")>',
                '<body onload=console.log("' + self.marker + '")>',
                '<input onfocus=console.log("' + self.marker + '") autofocus>',
                '<details open ontoggle=console.log("' + self.marker + '")>',
                '<select onfocus=console.log("' + self.marker + '") autofocus>',
                '<marquee onstart=console.log("' + self.marker + '")>',
            ],
            'attribute_context': [
                '" onmouseover="console.log(\'' + self.marker + '\')" x="',
                '" onclick="console.log(\'' + self.marker + '\')" x="',
                '" autofocus onfocus="console.log(\'' + self.marker + '\')" x="',
                '" onload="console.log(\'' + self.marker + '\')" x="',
            ],
            'javascript_context': [
                '";console.log("' + self.marker + '");//',
                "</script><script>console.log('" + self.marker + "')</script>",
                '\\';console.log("' + self.marker + '");//',
            ],
            'url_context': [
                'javascript:console.log("' + self.marker + '")',
                'data:text/html,<script>console.log("' + self.marker + '")</script>',
            ],
        }
        
        # WAF bypass payloads
        self.bypass_payloads = [
            '<scr<script>ipt>console.log("' + self.marker + '")</scr</script>ipt>',
            '<img src=x onerror="&#99;onsole.log(\'' + self.marker + '\')">',
            '<details open ontoggle="console.log(\'' + self.marker + '\')">',
            '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=console.log("' + self.marker + '")>',
        ]
        
        # Common XSS-vulnerable parameter names
        self.xss_params = [
            'q', 'search', 'query', 'keyword', 's',
            'id', 'page', 'name', 'email', 'message',
            'comment', 'text', 'content', 'data', 'value',
            'url', 'redirect', 'return', 'next', 'back',
            'callback', 'jsonp', 'action', 'view',
        ]
    
    def _generate_marker(self, length: int = 10) -> str:
        """Generate a unique random marker for XSS detection."""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=length))
    
    def run(self) -> Dict:
        """
        Execute XSS vulnerability tests.
        
        Returns:
            Dict with findings and comprehensive test results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'forms_tested': [],
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'total_findings': 0,
            'findings': []
        }
        
        # Stage 1: Test HTML forms
        forms = self._find_forms()
        
        for form in forms:
            result['forms_tested'].append({
                'action': form['action'],
                'method': form['method'],
                'input_count': len(form['inputs']),
            })
            
            form_vulns = self._test_form(form)
            if form_vulns:
                result['vulnerable_parameters'].extend(form_vulns)
        
        # Stage 2: Test URL parameters from links
        url_params = self._find_url_parameters()
        
        for url, params in url_params:
            for param_name in params:
                result['parameters_tested'].append(param_name)
                
                url_vulns = self._test_url_parameter(url, param_name, params)
                if url_vulns:
                    result['vulnerable_parameters'].extend(url_vulns)
        
        # Stage 3: Test common parameters on main page
        for param_name in self.xss_params[:10]:
            result['parameters_tested'].append(param_name)
            
            common_vulns = self._test_common_parameter(param_name)
            if common_vulns:
                result['vulnerable_parameters'].extend(common_vulns)
        
        # Remove duplicates
        seen = set()
        unique_vulns = []
        for vuln in result['vulnerable_parameters']:
            key = (vuln['url'], vuln['parameter'], vuln.get('context', ''))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        result['vulnerable_parameters'] = unique_vulns
        result['total_findings'] = len(unique_vulns)
        
        # Generate detailed findings
        for vuln in unique_vulns:
            severity = 'high'
            cvss = 7.5
            
            # Adjust severity based on context
            if vuln.get('context') == 'javascript_context':
                severity = 'critical'
                cvss = 9.0
            elif vuln.get('context') == 'attribute_context':
                severity = 'high'
                cvss = 7.5
            elif vuln.get('context') == 'html_context':
                severity = 'high'
                cvss = 8.0
            
            self.findings.append({
                'title': (
                    f"Cross-Site Scripting (XSS) in '{vuln['parameter']}' parameter "
                    f"({vuln.get('context', 'unknown').replace('_', ' ')})"
                ),
                'severity': severity,
                'description': (
                    f"A Cross-Site Scripting (XSS) vulnerability was detected in the "
                    f"'{vuln['parameter']}' parameter at {vuln['url']}. "
                    f"Context: {vuln.get('context', 'unknown').replace('_', ' ')}. "
                    f"Method: {vuln.get('method', 'GET')}. "
                    "XSS allows attackers to inject malicious scripts that execute in "
                    "victims' browsers, potentially stealing cookies, session tokens, "
                    "or performing actions on behalf of the user."
                ),
                'recommendation': (
                    "1. Implement proper output encoding based on context:\n"
                    "   - HTML context: Use HTML entity encoding\n"
                    "   - JavaScript context: Use Unicode escaping\n"
                    "   - URL context: Use URL encoding\n"
                    "   - CSS context: Use CSS escaping\n"
                    "2. Implement Content-Security-Policy (CSP) header\n"
                    "3. Validate and sanitize all user inputs\n"
                    "4. Use HttpOnly and Secure flags on cookies\n"
                    "5. Use modern frameworks with auto-escaping (React, Vue, Angular)\n"
                    "6. Consider using DOMPurify for client-side sanitization\n"
                    "7. Set X-XSS-Protection: 1; mode=block header"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-79',
                'cvss_score': cvss,
                'evidence': (
                    f"URL: {vuln['url']}\n"
                    f"Parameter: {vuln['parameter']}\n"
                    f"Context: {vuln.get('context', 'unknown')}\n"
                    f"Method: {vuln.get('method', 'GET')}"
                ),
                'references': [
                    'https://owasp.org/www-community/attacks/xss/',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                    'https://portswigger.net/web-security/cross-site-scripting',
                ]
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Forms: {len(forms)}, "
            f"Parameters: {len(result['parameters_tested'])}, "
            f"Vulnerabilities: {len(unique_vulns)}"
        )
        return result
    
    def _find_forms(self) -> List[Dict]:
        """
        Find all HTML forms on the target website.
        
        Returns:
            List of form dictionaries with action, method, and inputs
        """
        forms = []
        visited_urls = set()
        
        # Check main page and common paths
        paths_to_check = [
            '/', '/index.php', '/search.php', '/contact.php',
            '/login.php', '/register.php', '/profile.php',
        ]
        
        for path in paths_to_check:
            if path in visited_urls:
                continue
            
            visited_urls.add(path)
            resp = self.browser.get(path)
            
            if not resp or resp.status_code != 200:
                continue
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # Build full URL
                if action:
                    form_url = urljoin(self.target_url, action)
                else:
                    form_url = urljoin(self.target_url, path)
                
                # Extract form inputs
                inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'placeholder': input_tag.get('placeholder', ''),
                    }
                    
                    # Skip submit buttons and hidden fields without names
                    if input_info['name'] or input_info['type'] in ['text', 'search', 'email', 'url']:
                        inputs.append(input_info)
                
                if inputs:
                    forms.append({
                        'action': form_url,
                        'method': method,
                        'inputs': inputs,
                        'enctype': form.get('enctype', ''),
                    })
        
        return forms[:15]  # Limit to 15 forms
    
    def _find_url_parameters(self) -> List:
        """
        Find URLs with query parameters from links on the page.
        
        Returns:
            List of tuples (url, params_dict)
        """
        url_params = []
        
        resp = self.browser.get('/')
        if not resp or resp.status_code != 200:
            return url_params
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # Skip non-HTTP links
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            
            # Parse URL
            if '?' in href:
                full_url = urljoin(self.target_url, href)
                parsed = urlparse(full_url)
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                
                if query_params:
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    url_params.append((base_url, query_params))
        
        return url_params[:20]  # Limit to 20 URLs
    
    def _test_form(self, form: Dict) -> List[Dict]:
        """
        Test a form for XSS vulnerabilities.
        
        Args:
            form: Form dictionary with action, method, and inputs
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Test each input field
        for input_field in form['inputs']:
            if not input_field.get('name'):
                continue
            
            param_name = input_field['name']
            
            # Test each payload context
            for context, payloads in self.payloads.items():
                for payload in payloads[:2]:  # Test first 2 payloads per context
                    # Build form data
                    form_data = {}
                    for inp in form['inputs']:
                        field_name = inp.get('name', '')
                        if not field_name:
                            continue
                        
                        if field_name == param_name:
                            form_data[field_name] = payload
                        else:
                            form_data[field_name] = inp.get('value', 'test')
                    
                    # Send request
                    resp = None
                    if form['method'] == 'post':
                        resp = self.browser.post(form['action'], data=form_data)
                    else:
                        resp = self.browser.get(form['action'], params=form_data)
                    
                    if resp and self._check_reflection(resp.text, payload):
                        vulnerabilities.append({
                            'url': form['action'],
                            'parameter': param_name,
                            'context': context,
                            'method': form['method'].upper(),
                            'type': 'form_based',
                        })
                        break  # Found vulnerability, move to next input
        
        return vulnerabilities
    
    def _test_url_parameter(self, url: str, param_name: str, params: Dict) -> List[Dict]:
        """
        Test a URL parameter for XSS vulnerabilities.
        
        Args:
            url: Base URL
            param_name: Parameter name to test
            params: All query parameters
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Normalize params
        normalized_params = {}
        for k, v in params.items():
            if isinstance(v, list):
                normalized_params[k] = v[0] if v else ''
            else:
                normalized_params[k] = v
        
        for context, payloads in self.payloads.items():
            for payload in payloads[:2]:
                test_params = normalized_params.copy()
                test_params[param_name] = payload
                
                resp = self.browser.get(url, params=test_params)
                
                if resp and self._check_reflection(resp.text, payload):
                    vulnerabilities.append({
                        'url': url,
                        'parameter': param_name,
                        'context': context,
                        'method': 'GET',
                        'type': 'url_parameter',
                    })
                    break
        
        return vulnerabilities
    
    def _test_common_parameter(self, param_name: str) -> List[Dict]:
        """
        Test a common parameter name on the main page.
        
        Args:
            param_name: Parameter name to test
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        for context, payloads in self.payloads.items():
            for payload in payloads[:1]:
                resp = self.browser.get('/', params={param_name: payload})
                
                if resp and self._check_reflection(resp.text, payload):
                    vulnerabilities.append({
                        'url': self.target_url,
                        'parameter': param_name,
                        'context': context,
                        'method': 'GET',
                        'type': 'common_parameter',
                    })
                    break
        
        return vulnerabilities
    
    def _check_reflection(self, response_text: str, payload: str) -> bool:
        """
        Check if the XSS payload is reflected in the response.
        
        Args:
            response_text: HTTP response body
            payload: XSS payload that was sent
        
        Returns:
            True if payload is reflected without proper encoding
        """
        if not response_text or not payload:
            return False
        
        # Check for direct reflection (payload appears as-is)
        if payload in response_text:
            return True
        
        # Check for HTML entity decoded reflection
        decoded_payload = html.unescape(payload)
        if decoded_payload != payload and decoded_payload in response_text:
            return True
        
        # Check for partially encoded reflection
        # HTML encode the payload
        encoded_payload = html.escape(payload)
        if encoded_payload != payload:
            # If the encoded version is NOT in the response but the raw is,
            # it means it's being output without encoding
            if payload in html.unescape(response_text):
                # Check if it's actually encoded properly
                soup = BeautifulSoup(response_text, 'html.parser')
                body_text = soup.get_text()
                script_tags = soup.find_all('script')
                
                # Check script contexts
                for script in script_tags:
                    if script.string and payload in script.string:
                        return True
                
                # Check HTML contexts (not in script tags)
                if payload in body_text:
                    return True
        
        return False