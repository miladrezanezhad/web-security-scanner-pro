#!/usr/bin/env python3
"""
DOM-based Cross-Site Scripting (XSS) Vulnerability Scanner.
Tests for client-side XSS vulnerabilities in JavaScript code.

References:
    - OWASP: https://owasp.org/www-community/attacks/DOM_Based_XSS
    - PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based
    - CWE-79: Cross-Site Scripting
"""

import re
import random
import string
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from loguru import logger


class Scanner:
    """DOM-based Cross-Site Scripting vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize DOM-based XSS scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "DOM-based XSS Detection"
        
        # Unique marker for detection
        self.marker = self._generate_marker()
        
        # ============================================================================
        # DOM XSS Sources (user-controllable inputs)
        # ============================================================================
        self.dom_sources = [
            # URL-based sources
            'location.href',
            'location.search',
            'location.hash',
            'location.pathname',
            'document.URL',
            'document.documentURI',
            'document.baseURI',
            'window.location',
            
            # Referrer
            'document.referrer',
            
            # Window name
            'window.name',
            
            # PostMessage
            'event.data',
            'e.data',
            
            # WebSocket
            'websocket.message',
            
            # Storage
            'localStorage.getItem',
            'sessionStorage.getItem',
            'document.cookie',
            
            # History
            'history.pushState',
            'history.replaceState',
        ]
        
        # ============================================================================
        # DOM XSS Sinks (dangerous output points)
        # ============================================================================
        self.dom_sinks = {
            # HTML modification
            'innerHTML': {
                'severity': 'critical',
                'description': 'innerHTML directly injects HTML without sanitization',
            },
            'outerHTML': {
                'severity': 'critical',
                'description': 'outerHTML replaces element with unsanitized HTML',
            },
            'insertAdjacentHTML': {
                'severity': 'critical',
                'description': 'insertAdjacentHTML injects HTML without sanitization',
            },
            'document.write': {
                'severity': 'critical',
                'description': 'document.write() can inject malicious scripts',
            },
            'document.writeln': {
                'severity': 'critical',
                'description': 'document.writeln() can inject malicious scripts',
            },
            
            # jQuery sinks
            '$.html(': {
                'severity': 'critical',
                'description': 'jQuery html() can inject scripts if input is not sanitized',
            },
            '$.append(': {
                'severity': 'high',
                'description': 'jQuery append() can inject HTML elements',
            },
            '$.prepend(': {
                'severity': 'high',
                'description': 'jQuery prepend() can inject HTML elements',
            },
            '$.after(': {
                'severity': 'high',
                'description': 'jQuery after() can inject HTML elements',
            },
            '$.before(': {
                'severity': 'high',
                'description': 'jQuery before() can inject HTML elements',
            },
            '$.replaceWith(': {
                'severity': 'high',
                'description': 'jQuery replaceWith() can inject HTML elements',
            },
            '$.wrap(': {
                'severity': 'medium',
                'description': 'jQuery wrap() can manipulate DOM structure',
            },
            
            # JavaScript execution
            'eval(': {
                'severity': 'critical',
                'description': 'eval() can execute arbitrary JavaScript code',
            },
            'setTimeout(': {
                'severity': 'critical',
                'description': 'setTimeout with string argument can execute code',
            },
            'setInterval(': {
                'severity': 'critical',
                'description': 'setInterval with string argument can execute code',
            },
            'Function(': {
                'severity': 'critical',
                'description': 'Function constructor can execute arbitrary code',
            },
            'execScript(': {
                'severity': 'critical',
                'description': 'execScript can execute arbitrary JavaScript',
            },
            
            # URL modification
            'location.href': {
                'severity': 'high',
                'description': 'location.href modification can redirect to malicious URLs',
            },
            'location.replace': {
                'severity': 'high',
                'description': 'location.replace can redirect to malicious URLs',
            },
            'location.assign': {
                'severity': 'high',
                'description': 'location.assign can redirect to malicious URLs',
            },
            'window.open': {
                'severity': 'medium',
                'description': 'window.open can open malicious URLs',
            },
            
            # React/Vue dangerous patterns
            'dangerouslySetInnerHTML': {
                'severity': 'critical',
                'description': 'React dangerouslySetInnerHTML bypasses XSS protection',
            },
            'v-html': {
                'severity': 'critical',
                'description': 'Vue v-html directive renders raw HTML',
            },
            
            # Angular
            'bypassSecurityTrustHtml': {
                'severity': 'high',
                'description': 'Angular bypassSecurityTrustHtml disables sanitization',
            },
            'bypassSecurityTrustScript': {
                'severity': 'high',
                'description': 'Angular bypassSecurityTrustScript disables sanitization',
            },
        }
        
        # ============================================================================
        # DOM XSS Test Payloads
        # ============================================================================
        self.test_payloads = [
            # Standard XSS vectors
            '<img src=x onerror=console.log("' + self.marker + '")>',
            '<svg onload=console.log("' + self.marker + '")>',
            '<body onload=console.log("' + self.marker + '")>',
            '<script>console.log("' + self.marker + '")</script>',
            
            # Fragment-based (hash)
            '#<img src=x onerror=console.log("' + self.marker + '")>',
            '#<script>console.log("' + self.marker + '")</script>',
            
            # Event handlers
            '" onmouseover="console.log(\'' + self.marker + '\')"',
            '" onclick="console.log(\'' + self.marker + '\')"',
            
            # JavaScript protocol
            'javascript:console.log("' + self.marker + '")',
            
            # Template injection
            '{{constructor.constructor("console.log(\'' + self.marker + '\')")()}}',
        ]
    
    def _generate_marker(self, length: int = 10) -> str:
        """Generate unique random marker."""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=length))
    
    # ============================================================================
    # Main Scan Method
    # ============================================================================
    
    def run(self) -> Dict:
        """
        Execute DOM-based XSS tests.
        
        Returns:
            Dict with findings and test results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'scripts_analyzed': 0,
            'dom_sinks_found': [],
            'vulnerable_urls': [],
            'findings': []
        }
        
        # Get the main page
        resp = self.browser.get('/')
        if not resp or resp.status_code != 200:
            logger.warning(f"Cannot access {self.target_url}")
            return result
        
        html_content = resp.text
        
        # ============================================================
        # Stage 1: Static Analysis - Find DOM Sinks in JavaScript
        # ============================================================
        static_findings = self._analyze_javascript(html_content)
        result['dom_sinks_found'] = static_findings
        result['scripts_analyzed'] = len(self._extract_scripts(html_content))
        
        # ============================================================
        # Stage 2: Dynamic Test - URL Fragment Injection
        # ============================================================
        fragment_findings = self._test_url_fragment()
        result['vulnerable_urls'].extend(fragment_findings)
        
        # ============================================================
        # Stage 3: Dynamic Test - URL Parameter Reflection in JS
        # ============================================================
        param_findings = self._test_parameter_reflection()
        result['vulnerable_urls'].extend(param_findings)
        
        # ============================================================
        # Generate Findings
        # ============================================================
        
        # Findings from static analysis
        for sink in static_findings:
            sink_type = sink['sink']
            sink_info = self.dom_sinks.get(sink_type, {})
            
            self.findings.append({
                'title': f"DOM XSS Sink Found: {sink_type}",
                'severity': sink_info.get('severity', 'high'),
                'description': (
                    f"A potential DOM-based XSS sink was found in {sink['location']}. "
                    f"Sink: {sink_type}. "
                    f"Source: {sink.get('source', 'unknown')}. "
                    f"{sink_info.get('description', '')}"
                ),
                'recommendation': (
                    "1. Never pass user-controlled data to DOM sinks without sanitization\n"
                    "2. Use DOMPurify for HTML sanitization\n"
                    "3. Use textContent instead of innerHTML when possible\n"
                    "4. Avoid eval(), Function(), setTimeout with strings\n"
                    "5. Use CSP (Content Security Policy) to prevent inline scripts\n"
                    "6. Use frameworks with built-in XSS protection (React, Vue, Angular)\n"
                    "7. Sanitize URL fragments and parameters before use"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-79',
                'cvss_score': 7.5 if sink_info.get('severity') == 'critical' else 6.5,
                'evidence': (
                    f"File: {sink.get('file', 'inline')}\n"
                    f"Line: {sink.get('line', 'unknown')}\n"
                    f"Context: {sink.get('context', '')[:200]}"
                ),
                'references': [
                    'https://owasp.org/www-community/attacks/DOM_Based_XSS',
                    'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
                    'https://portswigger.net/web-security/cross-site-scripting/dom-based',
                ]
            })
        
        # Findings from dynamic tests
        for vuln in result['vulnerable_urls']:
            self.findings.append({
                'title': f"DOM XSS in {vuln['vector']}",
                'severity': 'high',
                'description': (
                    f"DOM-based XSS detected via {vuln['type']}. "
                    f"URL: {vuln['url']}. "
                    f"The application processes user input in client-side JavaScript "
                    f"without proper sanitization, allowing script injection."
                ),
                'recommendation': (
                    "Sanitize all user-controlled data before using in DOM operations. "
                    "Use safe APIs like textContent instead of innerHTML."
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-79',
                'cvss_score': 7.5,
                'evidence': f"URL: {vuln['url']}\nType: {vuln['type']}\nVector: {vuln['vector']}",
                'references': [
                    'https://owasp.org/www-community/attacks/DOM_Based_XSS',
                ]
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Scripts: {result['scripts_analyzed']}, "
            f"Sinks: {len(static_findings)}, "
            f"Vulnerable URLs: {len(result['vulnerable_urls'])}"
        )
        
        return result
    
    # ============================================================================
    # Static Analysis - JavaScript Code Review
    # ============================================================================
    
    def _extract_scripts(self, html_content: str) -> List[Dict]:
        """Extract JavaScript code from HTML (inline + external)."""
        scripts = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Inline scripts
        for i, script_tag in enumerate(soup.find_all('script')):
            if script_tag.string:
                scripts.append({
                    'type': 'inline',
                    'id': f'inline_{i}',
                    'content': script_tag.string,
                    'location': f'<script> tag #{i + 1}'
                })
        
        # External scripts - fetch and analyze
        for i, script_tag in enumerate(soup.find_all('script', src=True)):
            src = script_tag['src']
            if src.startswith('http') or src.startswith('//'):
                script_url = src if src.startswith('http') else 'https:' + src
            else:
                script_url = urljoin(self.target_url, src)
            
            scripts.append({
                'type': 'external',
                'id': f'external_{i}',
                'url': script_url,
                'location': f'<script src="{src}">'
            })
        
        return scripts
    
    def _analyze_javascript(self, html_content: str) -> List[Dict]:
        """Analyze JavaScript for DOM XSS sinks."""
        findings = []
        scripts = self._extract_scripts(html_content)
        
        for script in scripts:
            if script['type'] == 'inline':
                findings.extend(
                    self._find_sinks(script['content'], script['location'])
                )
            elif script['type'] == 'external':
                # Fetch external script
                resp = self.browser.get(script['url'])
                if resp and resp.status_code == 200:
                    findings.extend(
                        self._find_sinks(resp.text, script['location'])
                    )
        
        return findings
    
    def _find_sinks(self, js_code: str, location: str) -> List[Dict]:
        """Find DOM XSS sinks in JavaScript code."""
        findings = []
        lines = js_code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for sink_name in self.dom_sinks:
                if sink_name in line:
                    # Find if there's a source near the sink
                    source = self._find_source_in_context(lines, i)
                    
                    findings.append({
                        'sink': sink_name,
                        'source': source,
                        'location': location,
                        'line': i,
                        'context': line.strip()[:300],
                        'file': location.split('>')[0].strip() if '>' in location else location,
                    })
        
        return findings
    
    def _find_source_in_context(self, lines: List[str], sink_line: int) -> Optional[str]:
        """Find DOM source in context around the sink."""
        # Look 5 lines before and after for sources
        start = max(0, sink_line - 5)
        end = min(len(lines), sink_line + 5)
        
        context = '\n'.join(lines[start:end])
        
        for source in self.dom_sources:
            if source in context:
                return source
        
        return None
    
    # ============================================================================
    # Dynamic Testing - URL Fragment
    # ============================================================================
    
    def _test_url_fragment(self) -> List[Dict]:
        """Test for DOM XSS via URL fragment (#)."""
        findings = []
        
        for payload in self.test_payloads[:4]:
            # Test with fragment
            test_url = self.target_url + '#' + payload
            
            # We can't test fragment server-side, but we can check if page
            # has JavaScript that reads location.hash
            resp = self.browser.get('/')
            if resp and resp.status_code == 200:
                # Check if location.hash is used
                if 'location.hash' in resp.text or 'location.href' in resp.text:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    
                    for script in soup.find_all('script'):
                        if script.string:
                            if 'location.hash' in script.string or 'location.href' in script.string:
                                findings.append({
                                    'url': self.target_url,
                                    'type': 'url_fragment',
                                    'vector': 'URL hash (#)',
                                    'payload': payload,
                                })
                                break
        
        return findings
    
    # ============================================================================
    # Dynamic Testing - URL Parameters
    # ============================================================================
    
    def _test_parameter_reflection(self) -> List[Dict]:
        """Test for DOM XSS via URL parameters reflected in JavaScript."""
        findings = []
        
        # Common parameters that might be reflected in JS
        test_params = ['q', 'search', 'query', 'id', 'page', 'redirect', 'callback', 'jsonp', 'return']
        
        for param_name in test_params[:5]:
            for payload in self.test_payloads[:3]:
                resp = self.browser.get('/', params={param_name: payload})
                
                if resp and resp.status_code == 200:
                    # Check if payload is reflected in JavaScript
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    
                    for script in soup.find_all('script'):
                        if script.string and self.marker in script.string:
                            findings.append({
                                'url': self.target_url,
                                'type': 'parameter_reflection_in_js',
                                'vector': f'URL parameter: {param_name}',
                                'payload': payload,
                            })
                            break
        
        return findings