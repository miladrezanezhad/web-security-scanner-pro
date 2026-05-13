#!/usr/bin/env python3
"""
Security Headers Analysis Module.
Analyzes HTTP security headers for presence and proper configuration.

References:
    - OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
    - Mozilla Observatory: https://observatory.mozilla.org/
    - securityheaders.com: https://securityheaders.com/
    - MDN Web Docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
from loguru import logger

from modules.headers import SECURITY_HEADERS_REFERENCE


class Scanner:
    """HTTP security headers analysis scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize security headers scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Security Headers Analysis"
        
        # Headers to analyze with their expected values
        self.security_headers = {
            'Strict-Transport-Security': {
                'expected': 'max-age=',
                'validate': self._validate_hsts,
                'severity': 'medium',
                'title': 'HTTP Strict Transport Security (HSTS)',
                'description': 'Enforces HTTPS connections and prevents SSL stripping attacks',
            },
            'Content-Security-Policy': {
                'expected': None,
                'validate': self._validate_csp,
                'severity': 'high',
                'title': 'Content Security Policy (CSP)',
                'description': 'Prevents XSS, clickjacking, and code injection attacks',
            },
            'X-Content-Type-Options': {
                'expected': 'nosniff',
                'validate': self._validate_exact,
                'severity': 'low',
                'title': 'X-Content-Type-Options',
                'description': 'Prevents MIME type sniffing attacks',
            },
            'X-Frame-Options': {
                'expected': None,
                'validate': self._validate_frame_options,
                'severity': 'medium',
                'title': 'X-Frame-Options',
                'description': 'Prevents clickjacking by controlling iframe embedding',
            },
            'Referrer-Policy': {
                'expected': None,
                'validate': self._validate_referrer_policy,
                'severity': 'low',
                'title': 'Referrer-Policy',
                'description': 'Controls how much referrer information is sent with requests',
            },
            'Permissions-Policy': {
                'expected': None,
                'validate': self._validate_permissions_policy,
                'severity': 'low',
                'title': 'Permissions-Policy (Feature-Policy)',
                'description': 'Controls which browser features and APIs can be used',
            },
            'Cross-Origin-Resource-Policy': {
                'expected': None,
                'validate': self._validate_cross_origin,
                'severity': 'medium',
                'title': 'Cross-Origin-Resource-Policy',
                'description': 'Prevents other origins from loading resources',
            },
            'Cross-Origin-Opener-Policy': {
                'expected': None,
                'validate': self._validate_cross_origin,
                'severity': 'medium',
                'title': 'Cross-Origin-Opener-Policy',
                'description': 'Prevents cross-origin attacks via window.opener',
            },
            'Cross-Origin-Embedder-Policy': {
                'expected': None,
                'validate': self._validate_cross_origin,
                'severity': 'low',
                'title': 'Cross-Origin-Embedder-Policy',
                'description': 'Controls cross-origin resource embedding',
            },
            'Cache-Control': {
                'expected': None,
                'validate': self._validate_cache_control,
                'severity': 'low',
                'title': 'Cache-Control',
                'description': 'Controls caching of sensitive content',
            },
        }
        
        # CSP directives that indicate security issues
        self.csp_issues = {
            'unsafe-inline': {
                'pattern': r"'unsafe-inline'",
                'severity': 'medium',
                'message': "Allows inline scripts/styles (reduces XSS protection)",
            },
            'unsafe-eval': {
                'pattern': r"'unsafe-eval'",
                'severity': 'high',
                'message': "Allows eval() and similar functions (dangerous)",
            },
            'wildcard-src': {
                'pattern': r"default-src\s+\*",
                'severity': 'high',
                'message': "Wildcard source allows content from any origin",
            },
            'data-src': {
                'pattern': r"script-src[^;]*data:",
                'severity': 'medium',
                'message': "Allows data: URIs for scripts (XSS vector)",
            },
            'http-src': {
                'pattern': r"(?:script|style|img|connect)-src[^;]*http:",
                'severity': 'low',
                'message': "Allows loading resources over HTTP instead of HTTPS",
            },
        }
        
        # Multiple paths to test headers on
        self.test_paths = [
            '/',
            '/index.html',
            '/index.php',
            '/robots.txt',
            '/wp-login.php',
            '/login',
        ]
    
    def run(self) -> Dict:
        """
        Execute security headers analysis.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'headers_found': {},
            'headers_missing': [],
            'headers_weak': [],
            'headers_secure': [],
            'grade': 'F',
            'score': 0,
            'max_score': 100,
            'findings': []
        }
        
        # Test headers on multiple paths for consistency
        all_headers = {}
        for path in self.test_paths[:3]:  # Test first 3 paths
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 301, 302, 304]:
                for header_name, header_value in resp.headers.items():
                    if header_name not in all_headers:
                        all_headers[header_name] = []
                    all_headers[header_name].append({
                        'path': path,
                        'value': header_value,
                    })
        
        # Analyze each security header
        for header_name, header_config in self.security_headers.items():
            if header_name in all_headers:
                header_values = all_headers[header_name]
                value = header_values[0]['value']
                
                validation = header_config['validate'](value)
                
                result['headers_found'][header_name] = {
                    'value': value,
                    'valid': validation['valid'],
                    'issues': validation.get('issues', []),
                    'paths_tested': [h['path'] for h in header_values],
                }
                
                if validation['valid']:
                    result['headers_secure'].append(header_name)
                else:
                    result['headers_weak'].append(header_name)
                    
                    self.findings.append({
                        'title': f"{header_config['title']} is misconfigured",
                        'severity': header_config['severity'],
                        'description': (
                            f"The {header_config['title']} header is present but misconfigured.\n"
                            f"Current value: {value}\n"
                            f"Issues: {', '.join(validation.get('issues', []))}"
                        ),
                        'recommendation': self._get_header_recommendation(header_name, value),
                        'module': self.module_name,
                        'cwe_id': SECURITY_HEADERS_REFERENCE.get(header_name, {}).get('cwe'),
                        'evidence': f"Header: {header_name}: {value}",
                    })
            else:
                result['headers_missing'].append(header_name)
                
                self.findings.append({
                    'title': f"Missing security header: {header_config['title']}",
                    'severity': header_config['severity'],
                    'description': (
                        f"The {header_config['title']} header is missing. "
                        f"{header_config['description']}."
                    ),
                    'recommendation': self._get_header_recommendation(header_name, None),
                    'module': self.module_name,
                    'cwe_id': SECURITY_HEADERS_REFERENCE.get(header_name, {}).get('cwe'),
                    'evidence': f"Header '{header_name}' not found in response",
                    'references': [
                        f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                    ]
                })
        
        # Calculate score and grade
        result['score'] = self._calculate_score(result)
        result['grade'] = self._calculate_grade(result['score'])
        
        # Overall grade finding
        self.findings.append({
            'title': f"Security Headers Grade: {result['grade']} (Score: {result['score']}/100)",
            'severity': 'info' if result['grade'] in ['A+', 'A', 'B'] else 'medium',
            'description': (
                f"Overall security headers score: {result['score']}/100.\n"
                f"Headers present: {len(result['headers_found'])}/{len(self.security_headers)}\n"
                f"Headers secure: {len(result['headers_secure'])}\n"
                f"Headers weak: {len(result['headers_weak'])}\n"
                f"Headers missing: {len(result['headers_missing'])}"
            ),
            'recommendation': (
                "Review the security headers configuration and implement the missing "
                "or misconfigured headers to improve the security posture."
            ),
            'module': self.module_name,
        })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Grade: {result['grade']}, "
            f"Score: {result['score']}/100"
        )
        return result
    
    # =========================================================================
    # Validation methods
    # =========================================================================
    
    def _validate_hsts(self, value: str) -> Dict:
        """Validate HSTS header."""
        result = {'valid': True, 'issues': []}
        
        if 'max-age=' not in value.lower():
            result['valid'] = False
            result['issues'].append("Missing max-age directive")
            return result
        
        # Extract max-age value
        match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
        if match:
            max_age = int(match.group(1))
            if max_age < 31536000:  # Less than 1 year
                result['valid'] = False
                result['issues'].append(f"max-age is too short ({max_age} seconds, recommended: 31536000)")
        
        if 'includeSubDomains' not in value:
            result['issues'].append("Missing includeSubDomains directive")
            # Don't mark invalid, just a warning
        
        if 'preload' not in value:
            result['issues'].append("Missing preload directive (for HSTS preload list)")
        
        return result
    
    def _validate_csp(self, value: str) -> Dict:
        """Validate Content-Security-Policy header."""
        result = {'valid': True, 'issues': []}
        
        # Check for common issues
        for issue_name, issue_config in self.csp_issues.items():
            if re.search(issue_config['pattern'], value, re.IGNORECASE):
                result['issues'].append(issue_config['message'])
                if issue_config['severity'] in ['high', 'critical']:
                    result['valid'] = False
        
        # Check for missing directives
        important_directives = ['default-src', 'script-src', 'object-src']
        for directive in important_directives:
            if directive not in value.lower():
                result['issues'].append(f"Missing recommended directive: {directive}")
                if directive == 'default-src':
                    result['valid'] = False
        
        # Check for report-only
        if 'report-only' in value.lower():
            result['issues'].append("CSP is in report-only mode (not enforced)")
            result['valid'] = False
        
        return result
    
    def _validate_exact(self, value: str) -> Dict:
        """Validate header with exact value match."""
        result = {'valid': True, 'issues': []}
        
        if value.strip().lower() != 'nosniff':
            result['valid'] = False
            result['issues'].append(f"Expected 'nosniff', got '{value}'")
        
        return result
    
    def _validate_frame_options(self, value: str) -> Dict:
        """Validate X-Frame-Options header."""
        result = {'valid': True, 'issues': []}
        
        valid_values = ['DENY', 'SAMEORIGIN']
        value_upper = value.strip().upper()
        
        if value_upper not in valid_values:
            result['valid'] = False
            result['issues'].append(f"Expected DENY or SAMEORIGIN, got '{value}'")
        
        if 'ALLOW-FROM' in value_upper:
            result['issues'].append("ALLOW-FROM is deprecated and not supported by most browsers")
            result['valid'] = False
        
        return result
    
    def _validate_referrer_policy(self, value: str) -> Dict:
        """Validate Referrer-Policy header."""
        result = {'valid': True, 'issues': []}
        
        # Recommended values
        recommended = [
            'strict-origin-when-cross-origin',
            'strict-origin',
            'no-referrer',
            'same-origin',
        ]
        
        value_lower = value.strip().lower()
        
        if value_lower not in recommended:
            if 'unsafe-url' in value_lower:
                result['valid'] = False
                result['issues'].append("unsafe-url sends full URL to all sites (dangerous)")
            else:
                result['issues'].append(f"Consider using 'strict-origin-when-cross-origin' instead of '{value}'")
        
        return result
    
    def _validate_permissions_policy(self, value: str) -> Dict:
        """Validate Permissions-Policy header."""
        result = {'valid': True, 'issues': []}
        
        # Check for wildcard permissions
        if '*' in value:
            result['issues'].append("Wildcard (*) allows all origins to use browser features")
        
        return result
    
    def _validate_cross_origin(self, value: str) -> Dict:
        """Validate Cross-Origin headers."""
        result = {'valid': True, 'issues': []}
        
        valid_values = ['same-origin', 'same-site', 'cross-origin']
        value_lower = value.strip().lower()
        
        if value_lower not in valid_values:
            result['valid'] = False
            result['issues'].append(f"Expected one of: {', '.join(valid_values)}, got '{value}'")
        
        return result
    
    def _validate_cache_control(self, value: str) -> Dict:
        """Validate Cache-Control header."""
        result = {'valid': True, 'issues': []}
        
        value_lower = value.strip().lower()
        
        # For login/sensitive pages, caching should be disabled
        if 'public' in value_lower:
            result['issues'].append("'public' allows caching by intermediaries")
        
        return result
    
    # =========================================================================
    # Scoring and grading
    # =========================================================================
    
    def _calculate_score(self, result: Dict) -> int:
        """Calculate security headers score."""
        score = 100
        
        # Deductions for missing headers
        deduction_map = {
            'Content-Security-Policy': 25,
            'Strict-Transport-Security': 15,
            'X-Frame-Options': 10,
            'X-Content-Type-Options': 5,
            'Referrer-Policy': 5,
            'Permissions-Policy': 3,
            'Cross-Origin-Resource-Policy': 5,
            'Cross-Origin-Opener-Policy': 5,
            'Cross-Origin-Embedder-Policy': 3,
            'Cache-Control': 2,
        }
        
        for header in result['headers_missing']:
            score -= deduction_map.get(header, 5)
        
        # Deductions for weak/misconfigured headers (half the missing deduction)
        for header in result['headers_weak']:
            score -= deduction_map.get(header, 5) // 2
        
        return max(0, min(100, score))
    
    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade from score."""
        if score >= 95:
            return 'A+'
        elif score >= 85:
            return 'A'
        elif score >= 75:
            return 'B'
        elif score >= 65:
            return 'C'
        elif score >= 50:
            return 'D'
        elif score >= 30:
            return 'E'
        else:
            return 'F'
    
    def _get_header_recommendation(self, header_name: str, current_value: Optional[str]) -> str:
        """Get specific recommendation for a header."""
        recommendations = {
            'Strict-Transport-Security': (
                "Add the following header to your server configuration:\n\n"
                "Apache:\n"
                'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n\n'
                "Nginx:\n"
                'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n\n'
                "IIS:\n"
                "<system.webServer>\n"
                "  <httpProtocol>\n"
                '    <customHeaders>\n'
                '      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload"/>\n'
                "    </customHeaders>\n"
                "  </httpProtocol>\n"
                "</system.webServer>"
            ),
            'Content-Security-Policy': (
                "Implement a Content Security Policy. Start with a report-only policy:\n\n"
                "Content-Security-Policy-Report-Only: default-src 'self'; "
                "script-src 'self'; style-src 'self'; img-src 'self'; "
                "font-src 'self'; connect-src 'self'; frame-ancestors 'self'; "
                "form-action 'self'; report-uri /csp-report-endpoint\n\n"
                "After testing, switch to enforcing mode by removing '-Report-Only'."
            ),
            'X-Content-Type-Options': (
                'Add the header: X-Content-Type-Options: nosniff\n\n'
                "Apache: Header set X-Content-Type-Options 'nosniff'\n"
                "Nginx: add_header X-Content-Type-Options 'nosniff' always;"
            ),
            'X-Frame-Options': (
                "Add the header: X-Frame-Options: DENY (or SAMEORIGIN if frames are needed)\n\n"
                "Note: Consider using CSP frame-ancestors directive instead for better browser support."
            ),
            'Referrer-Policy': (
                'Add the header: Referrer-Policy: strict-origin-when-cross-origin\n\n'
                "This sends full URL for same-origin requests and only origin for cross-origin requests."
            ),
            'Permissions-Policy': (
                "Add the header to restrict browser features:\n"
                'Permissions-Policy: camera=(), microphone=(), geolocation=(), '
                'interest-cohort=(), payment=(), usb=()'
            ),
            'Cross-Origin-Resource-Policy': (
                'Add the header: Cross-Origin-Resource-Policy: same-origin\n\n'
                "This prevents other websites from loading your resources."
            ),
            'Cross-Origin-Opener-Policy': (
                'Add the header: Cross-Origin-Opener-Policy: same-origin\n\n'
                "This prevents cross-origin attacks via window.opener."
            ),
            'Cross-Origin-Embedder-Policy': (
                'Add the header: Cross-Origin-Embedder-Policy: require-corp\n\n'
                "This controls which cross-origin resources can be embedded."
            ),
            'Cache-Control': (
                "For sensitive pages, add:\n"
                'Cache-Control: no-store, no-cache, must-revalidate, private\n\n'
                "This prevents caching of sensitive content."
            ),
        }
        
        return recommendations.get(
            header_name,
            f"Review the {header_name} header configuration and implement it according to best practices."
        )