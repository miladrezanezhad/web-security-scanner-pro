#!/usr/bin/env python3
"""
HTTP Headers Information Disclosure Module.
Detects information leakage through HTTP response headers.

References:
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
    - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


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
        
        # Headers that commonly disclose sensitive information
        self.disclosure_headers = {
            'Server': {
                'severity': 'medium',
                'description': 'Reveals web server software and version',
                'recommendation': 'Configure ServerTokens to minimal (Prod) in Apache, or server_tokens off in Nginx.',
                'cwe': 'CWE-200',
            },
            'X-Powered-By': {
                'severity': 'medium',
                'description': 'Reveals technology stack and version (PHP, ASP.NET, etc.)',
                'recommendation': 'Remove this header: In PHP set expose_php=Off, in Apache use "Header unset X-Powered-By".',
                'cwe': 'CWE-200',
            },
            'X-AspNet-Version': {
                'severity': 'medium',
                'description': 'Reveals ASP.NET framework version',
                'recommendation': 'Set <httpRuntime enableVersionHeader="false"/> in web.config.',
                'cwe': 'CWE-200',
            },
            'X-AspNetMvc-Version': {
                'severity': 'low',
                'description': 'Reveals ASP.NET MVC version',
                'recommendation': 'Set MvcHandler.DisableMvcResponseHeader = true in Global.asax.',
                'cwe': 'CWE-200',
            },
            'X-Generator': {
                'severity': 'low',
                'description': 'Reveals the CMS or framework used to generate the page',
                'recommendation': 'Remove via CMS settings or server configuration.',
                'cwe': 'CWE-200',
            },
            'X-Drupal-Cache': {
                'severity': 'low',
                'description': 'Reveals Drupal caching configuration',
                'recommendation': 'Disable via Drupal configuration if not needed.',
                'cwe': 'CWE-200',
            },
            'X-Drupal-Dynamic-Cache': {
                'severity': 'low',
                'description': 'Reveals Drupal dynamic cache configuration',
                'recommendation': 'Disable via Drupal configuration if not needed.',
                'cwe': 'CWE-200',
            },
            'X-Debug-Token': {
                'severity': 'high',
                'description': 'Reveals debug token - may allow access to debug toolbar',
                'recommendation': 'Disable debug mode in production immediately. Set APP_DEBUG=false in .env.',
                'cwe': 'CWE-489',
            },
            'X-Debug-Token-Link': {
                'severity': 'high',
                'description': 'Reveals direct link to Symfony/Laravel debug toolbar',
                'recommendation': 'Disable debug mode in production immediately.',
                'cwe': 'CWE-489',
            },
            'Via': {
                'severity': 'medium',
                'description': 'Reveals proxy server information and versions',
                'recommendation': 'Configure proxy to remove or minimize Via header.',
                'cwe': 'CWE-200',
            },
            'X-Backend-Server': {
                'severity': 'medium',
                'description': 'Reveals backend server hostname or IP',
                'recommendation': 'Remove this header from backend responses.',
                'cwe': 'CWE-200',
            },
            'X-Runtime': {
                'severity': 'low',
                'description': 'Reveals application execution time',
                'recommendation': 'Remove X-Runtime header in production.',
                'cwe': 'CWE-200',
            },
        }
        
        # Technology detection signatures from headers
        self.tech_signatures = {
            'Server': {
                'Apache': r'Apache(?:/([\d.]+))?',
                'Nginx': r'nginx(?:/([\d.]+))?',
                'IIS': r'Microsoft-IIS(?:/([\d.]+))?',
                'LiteSpeed': r'LiteSpeed(?:/([\d.]+))?',
                'Cloudflare': r'cloudflare',
                'Caddy': r'Caddy',
            },
            'X-Powered-By': {
                'PHP': r'PHP(?:/([\d.]+))?',
                'ASP.NET': r'ASP\.NET',
                'Express': r'Express',
                'Next.js': r'Next\.js',
            },
        }
        
        # Paths to test for headers
        self.test_paths = [
            '/',
            '/index.php',
            '/wp-login.php',
            '/api/',
            '/robots.txt',
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
        for path in self.test_paths[:3]:
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
        
        # Check each disclosure header
        for header_name, header_config in self.disclosure_headers.items():
            if header_name in all_headers:
                for instance in all_headers[header_name]:
                    value = instance['value']
                    
                    if value:
                        result['headers_disclosing_info'].append({
                            'header': header_name,
                            'value': value,
                            'path': instance['path'],
                        })
                        
                        result['findings'].append({
                            'title': f"Information disclosure via {header_name} header",
                            'severity': header_config['severity'],
                            'description': (
                                f"The {header_name} header reveals: {value}\n"
                                f"{header_config['description']}\n"
                                f"Found at: {instance['path']} (HTTP {instance['status']})"
                            ),
                            'recommendation': header_config['recommendation'],
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
            
            result['findings'].append({
                'title': f"Technology detected via headers: {tech}{version_info}",
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
            result['findings'].append({
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
                    "3. Verify debug endpoints are not accessible"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-489',
                'cvss_score': 7.5,
                'evidence': f"{debug_info['header']}: {debug_info['value']}",
            })
        
        # Add info if no issues found
        if not result['findings']:
            result['findings'].append({
                'title': 'No sensitive information disclosure via headers',
                'severity': 'info',
                'description': 'No sensitive information was found in HTTP response headers.',
                'recommendation': 'Continue monitoring headers for information disclosure.',
                'module': self.module_name,
            })
        
        logger.info(
            f"{self.module_name} complete. "
            f"Disclosing headers: {len(result['headers_disclosing_info'])}, "
            f"Technologies: {len(result['technologies_detected'])}"
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
        
        # Symfony/Laravel debug toolbar
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
        
        # Laravel debugbar
        if 'X-Debug-Token' in all_headers:
            token = all_headers['X-Debug-Token'][0]['value']
            debug_endpoints.append({
                'header': 'X-Debug-Token',
                'value': token,
                'url': urljoin(self.target_url, '/_debugbar/open?token=' + token),
                'type': 'laravel_debugbar',
                'token': token,
            })
        
        return debug_endpoints