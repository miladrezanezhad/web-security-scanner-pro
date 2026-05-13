#!/usr/bin/env python3
"""
HTTP Headers Information Disclosure Module.
Detects information leakage through HTTP response headers.

References:
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
    - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    - NIST SP 800-53: SI-5 Security Alerts, Advisories, and Directives
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin
from loguru import logger

from modules.headers import DISCLOSURE_HEADERS


class Scanner:
    """HTTP headers information disclosure scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize information disclosure scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Headers Information Disclosure"
        
        # Headers that commonly disclose information
        self.disclosure_headers = {
            'Server': {
                'pattern': None,
                'severity': 'medium',
                'description': 'Reveals web server software and version',
                'cwe': 'CWE-200',
            },
            'X-Powered-By': {
                'pattern': None,
                'severity': 'medium',
                'description': 'Reveals technology stack and version (PHP, ASP.NET, etc.)',
                'cwe': 'CWE-200',
            },
            'X-AspNet-Version': {
                'pattern': None,
                'severity': 'medium',
                'description': 'Reveals ASP.NET framework version',
                'cwe': 'CWE-200',
            },
            'X-AspNetMvc-Version': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals ASP.NET MVC version',
                'cwe': 'CWE-200',
            },
            'X-Generator': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals the CMS or framework used to generate the page',
                'cwe': 'CWE-200',
            },
            'X-Drupal-Cache': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals Drupal caching configuration',
                'cwe': 'CWE-200',
            },
            'X-Drupal-Dynamic-Cache': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals Drupal dynamic cache configuration',
                'cwe': 'CWE-200',
            },
            'X-Varnish': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals Varnish cache server presence',
                'cwe': 'CWE-200',
            },
            'X-Cache': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals caching infrastructure details',
                'cwe': 'CWE-200',
            },
            'X-Cache-Hits': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals cache hit/miss statistics',
                'cwe': 'CWE-200',
            },
            'X-Backend-Server': {
                'pattern': None,
                'severity': 'medium',
                'description': 'Reveals backend server hostname or IP',
                'cwe': 'CWE-200',
            },
            'X-Runtime': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals application execution time',
                'cwe': 'CWE-200',
            },
            'X-Debug-Token': {
                'pattern': None,
                'severity': 'high',
                'description': 'Reveals debug token (may allow access to debug toolbar)',
                'cwe': 'CWE-200',
            },
            'X-Debug-Token-Link': {
                'pattern': None,
                'severity': 'high',
                'description': 'Reveals direct link to debug toolbar',
                'cwe': 'CWE-200',
            },
            'X-Symfony-Cache': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals Symfony cache information',
                'cwe': 'CWE-200',
            },
            'X-LiteSpeed-Cache': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals LiteSpeed cache status',
                'cwe': 'CWE-200',
            },
            'X-WP-Nonce': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals WordPress nonce (may indicate REST API availability)',
                'cwe': 'CWE-200',
            },
            'X-Redirect-By': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals redirect handling mechanism',
                'cwe': 'CWE-200',
            },
            'X-Pingback': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals WordPress XML-RPC pingback URL',
                'cwe': 'CWE-200',
            },
            'X-Request-ID': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals request tracking ID (may be used for log correlation)',
                'cwe': 'CWE-200',
            },
            'Via': {
                'pattern': None,
                'severity': 'medium',
                'description': 'Reveals proxy server information and versions',
                'cwe': 'CWE-200',
            },
            'X-Host': {
                'pattern': None,
                'severity': 'medium',
                'description': 'Reveals internal hostname',
                'cwe': 'CWE-200',
            },
            'X-Forwarded-For': {
                'pattern': None,
                'severity': 'low',
                'description': 'Reveals client IP address (privacy concern)',
                'cwe': 'CWE-200',
            },
            'Set-Cookie': {
                'pattern': r'\.asp\.net|ASP\.NET_SessionId|PHPSESSID|JSESSIONID',
                'severity': 'low',
                'description': 'Session cookie reveals technology stack',
                'cwe': 'CWE-200',
            },
        }
        
        # Technology detection from headers
        self.tech_signatures = {
            'Server': {
                'Apache': r'Apache(?:/([\d.]+))?',
                'Nginx': r'nginx(?:/([\d.]+))?',
                'IIS': r'Microsoft-IIS(?:/([\d.]+))?',
                'LiteSpeed': r'LiteSpeed(?:/([\d.]+))?',
                'Cloudflare': r'cloudflare',
                'Varnish': r'Varnish',
                'Caddy': r'Caddy',
            },
            'X-Powered-By': {
                'PHP': r'PHP(?:/([\d.]+))?',
                'ASP.NET': r'ASP\.NET',
                'Express': r'Express',
                'Next.js': r'Next\.js',
                'Nuxt': r'Nuxt',
            },
        }
        
        # Multiple paths to test
        self.test_paths = [
            '/',
            '/index.html',
            '/index.php',
            '/robots.txt',
            '/404-nonexistent-page',
            '/wp-login.php',
            '/api/',
        ]
    
    def run(self) -> Dict:
        """
        Execute information disclosure analysis.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'headers_disclosing_info': [],
            'technologies_detected': {},
            'versions_detected': {},
            'debug_endpoints_found': [],
            'findings': []
        }
        
        # Collect headers from multiple paths
        all_headers = {}
        for path in self.test_paths[:5]:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 301, 302, 304, 404, 403, 500]:
                for header_name, header_value in resp.headers.items():
                    if header_name not in all_headers:
                        all_headers[header_name] = []
                    
                    all_headers[header_name].append({
                        'path': path,
                        'value': header_value,
                        'status': resp.status_code,
                    })
        
        # Analyze each disclosure header
        for header_name, header_config in self.disclosure_headers.items():
            if header_name in all_headers:
                header_instances = all_headers[header_name]
                
                for instance in header_instances:
                    value = instance['value']
                    
                    result['headers_disclosing_info'].append({
                        'header': header_name,
                        'value': value,
                        'path': instance['path'],
                    })
                    
                    # Check for specific patterns
                    if header_config.get('pattern'):
                        if re.search(header_config['pattern'], value, re.IGNORECASE):
                            self.findings.append({
                                'title': f"Information disclosure via {header_name} header",
                                'severity': header_config['severity'],
                                'description': (
                                    f"The {header_name} header reveals: {value}\n"
                                    f"{header_config['description']}\n"
                                    f"Found at: {instance['path']} (HTTP {instance['status']})"
                                ),
                                'recommendation': self._get_remediation(header_name),
                                'module': self.module_name,
                                'cwe_id': header_config.get('cwe', 'CWE-200'),
                                'evidence': f"{header_name}: {value}",
                            })
                    else:
                        # Generic disclosure
                        if len(value) > 0:
                            self.findings.append({
                                'title': f"Information disclosure via {header_name} header",
                                'severity': header_config['severity'],
                                'description': (
                                    f"The {header_name} header reveals: {value}\n"
                                    f"{header_config['description']}\n"
                                    f"Found at: {instance['path']} (HTTP {instance['status']})"
                                ),
                                'recommendation': self._get_remediation(header_name),
                                'module': self.module_name,
                                'cwe_id': header_config.get('cwe', 'CWE-200'),
                                'evidence': f"{header_name}: {value}",
                            })
        
        # Detect technologies from headers
        tech_detected = self._detect_technologies(all_headers)
        result['technologies_detected'] = tech_detected['technologies']
        result['versions_detected'] = tech_detected['versions']
        
        for tech, info in tech_detected['technologies'].items():
            version_info = ''
            if tech in tech_detected['versions']:
                version_info = f" (version: {tech_detected['versions'][tech]})"
            
            self.findings.append({
                'title': f"Technology detected: {tech}{version_info}",
                'severity': 'low',
                'description': (
                    f"The {tech} technology was detected through HTTP headers.\n"
                    f"Source header: {info['header']}\n"
                    f"Value: {info['value']}"
                ),
                'recommendation': (
                    "Consider hiding technology information by:\n"
                    "1. Configuring ServerTokens to minimal\n"
                    "2. Removing X-Powered-By header\n"
                    "3. Using ServerSignature Off"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'evidence': f"{info['header']}: {info['value']}",
            })
        
        # Check for debug endpoints from headers
        debug_endpoints = self._check_debug_endpoints(all_headers)
        result['debug_endpoints_found'] = debug_endpoints
        
        for debug_info in debug_endpoints:
            self.findings.append({
                'title': f"Debug endpoint exposed via header: {debug_info['header']}",
                'severity': 'high',
                'description': (
                    f"A debug endpoint was found through the {debug_info['header']} header.\n"
                    f"URL: {debug_info['url']}\n"
                    "Debug endpoints expose application internals and sensitive data."
                ),
                'recommendation': (
                    "1. Disable debug mode in production immediately\n"
                    "2. Remove debug headers from responses\n"
                    "3. Verify debug endpoints are not accessible\n"
                    "4. Check framework debug configuration"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-489',
                'cvss_score': 7.5,
                'evidence': f"{debug_info['header']}: {debug_info['value']}",
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Disclosing headers: {len(result['headers_disclosing_info'])}, "
            f"Technologies: {len(result['technologies_detected'])}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _detect_technologies(self, all_headers: Dict) -> Dict:
        """
        Detect technologies from HTTP headers.
        
        Args:
            all_headers: Collected headers from responses
        
        Returns:
            Dict with detected technologies and versions
        """
        technologies = {}
        versions = {}
        
        for header_name, signatures in self.tech_signatures.items():
            if header_name in all_headers:
                header_value = all_headers[header_name][0]['value']
                
                for tech_name, pattern in signatures.items():
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        technologies[tech_name] = {
                            'header': header_name,
                            'value': header_value,
                        }
                        
                        # Extract version if present
                        if match.lastindex and match.lastindex >= 1:
                            version = match.group(1)
                            if version:
                                versions[tech_name] = version
                        
                        break
        
        return {
            'technologies': technologies,
            'versions': versions,
        }
    
    def _check_debug_endpoints(self, all_headers: Dict) -> List[Dict]:
        """
        Check for debug endpoints from headers.
        
        Args:
            all_headers: Collected headers from responses
        
        Returns:
            List of debug endpoint information
        """
        debug_endpoints = []
        
        # Symfony debug toolbar
        if 'X-Debug-Token' in all_headers and 'X-Debug-Token-Link' in all_headers:
            token = all_headers['X-Debug-Token'][0]['value']
            link = all_headers['X-Debug-Token-Link'][0]['value']
            
            debug_endpoints.append({
                'header': 'X-Debug-Token-Link',
                'value': link,
                'url': link,
                'type': 'symfony_profiler',
                'token': token,
            })
        
        # Laravel debug
        if 'X-Debug-Token' in all_headers:
            token = all_headers['X-Debug-Token'][0]['value']
            # Laravel debug bar is typically at /_debugbar/
            debug_endpoints.append({
                'header': 'X-Debug-Token',
                'value': token,
                'url': urljoin(self.target_url, '/_debugbar/open?token=' + token),
                'type': 'laravel_debugbar',
                'token': token,
            })
        
        # WordPress debug
        if 'X-WP-Nonce' in all_headers:
            debug_endpoints.append({
                'header': 'X-WP-Nonce',
                'value': all_headers['X-WP-Nonce'][0]['value'],
                'url': urljoin(self.target_url, '/wp-admin/admin-ajax.php'),
                'type': 'wordpress_ajax',
            })
        
        return debug_endpoints
    
    def _get_remediation(self, header_name: str) -> str:
        """Get remediation advice for a specific disclosure header."""
        remediations = {
            'Server': (
                "Remove or minimize the Server header:\n\n"
                "Apache:\n"
                "  ServerTokens Prod\n"
                "  ServerSignature Off\n\n"
                "Nginx:\n"
                "  server_tokens off;\n\n"
                "IIS:\n"
                "  Use URL Rewrite module to remove Server header"
            ),
            'X-Powered-By': (
                "Remove the X-Powered-By header:\n\n"
                "PHP:\n"
                '  expose_php = Off (in php.ini)\n\n'
                "Apache:\n"
                '  Header unset X-Powered-By\n\n'
                "Nginx:\n"
                '  proxy_hide_header X-Powered-By;\n\n'
                "IIS:\n"
                "  Remove via web.config customHeaders section"
            ),
            'X-AspNet-Version': (
                "Remove ASP.NET version header:\n\n"
                "Add to web.config:\n"
                '<httpRuntime enableVersionHeader="false" />'
            ),
            'X-AspNetMvc-Version': (
                "Remove ASP.NET MVC version header:\n\n"
                "In Global.asax.cs Application_Start():\n"
                "  MvcHandler.DisableMvcResponseHeader = true;"
            ),
            'X-Generator': (
                "Remove the X-Generator header:\n\n"
                "WordPress:\n"
                "  Add to functions.php:\n"
                "  remove_action('wp_head', 'wp_generator');\n\n"
                "Joomla:\n"
                "  Set $generator to empty in template\n\n"
                "Drupal:\n"
                "  Configure via admin settings or remove from theme"
            ),
            'X-Debug-Token': (
                "Disable debug mode in production immediately:\n\n"
                "Symfony:\n"
                '  APP_DEBUG=0 in .env\n\n'
                "Laravel:\n"
                '  APP_DEBUG=false in .env\n'
                '  DEBUGBAR_ENABLED=false'
            ),
            'X-Debug-Token-Link': (
                "Same as X-Debug-Token - disable debug mode in production immediately."
            ),
            'Via': (
                "Consider removing the Via header if proxy information is sensitive.\n"
                "Some proxies allow configuring header removal."
            ),
        }
        
        default = (
            f"Remove or minimize the {header_name} header to reduce information disclosure.\n"
            "Check your web server, framework, and application documentation for specific "
            "configuration options to control this header."
        )
        
        return remediations.get(header_name, default)