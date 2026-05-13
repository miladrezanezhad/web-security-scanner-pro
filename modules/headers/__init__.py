"""
HTTP Headers Security Scanner Modules Package
Version: 3.0.0

This package contains modules for HTTP header security analysis.

Modules:
    security_headers.py        - Security headers presence and configuration analysis
    information_disclosure.py  - Information disclosure via HTTP headers detection

Security headers are the first line of defense against common web attacks.
Proper header configuration can prevent:
    - Cross-Site Scripting (XSS)
    - Clickjacking
    - MIME type sniffing
    - Man-in-the-middle attacks
    - Information leakage

References:
    - OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
    - Mozilla Observatory: https://observatory.mozilla.org/
    - Security Headers: https://securityheaders.com/
"""

__version__ = "3.0.0"

# Security headers reference
SECURITY_HEADERS_REFERENCE = {
    'Strict-Transport-Security': {
        'description': 'Enforces HTTPS connections',
        'recommended': 'max-age=31536000; includeSubDomains; preload',
        'severity_if_missing': 'medium',
        'cwe': 'CWE-319',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'Content-Security-Policy': {
        'description': 'Prevents XSS, clickjacking, and code injection',
        'recommended': "default-src 'self'; script-src 'self'; style-src 'self'",
        'severity_if_missing': 'high',
        'cwe': 'CWE-1021',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME type sniffing',
        'recommended': 'nosniff',
        'severity_if_missing': 'low',
        'cwe': 'CWE-116',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'X-Frame-Options': {
        'description': 'Prevents clickjacking attacks',
        'recommended': 'DENY or SAMEORIGIN',
        'severity_if_missing': 'medium',
        'cwe': 'CWE-1021',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'X-XSS-Protection': {
        'description': 'Legacy XSS filter (deprecated in modern browsers)',
        'recommended': '0 (disable - use CSP instead)',
        'severity_if_missing': 'info',
        'cwe': 'CWE-79',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'Referrer-Policy': {
        'description': 'Controls referrer information sent with requests',
        'recommended': 'strict-origin-when-cross-origin',
        'severity_if_missing': 'low',
        'cwe': 'CWE-200',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'Permissions-Policy': {
        'description': 'Controls browser features and APIs',
        'recommended': 'camera=(), microphone=(), geolocation=()',
        'severity_if_missing': 'low',
        'cwe': 'CWE-693',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'Cross-Origin-Resource-Policy': {
        'description': 'Prevents other sites from loading resources',
        'recommended': 'same-origin',
        'severity_if_missing': 'medium',
        'cwe': 'CWE-942',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'Cross-Origin-Opener-Policy': {
        'description': 'Prevents cross-origin attacks via window.opener',
        'recommended': 'same-origin',
        'severity_if_missing': 'medium',
        'cwe': 'CWE-942',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'Cross-Origin-Embedder-Policy': {
        'description': 'Controls cross-origin resource embedding',
        'recommended': 'require-corp',
        'severity_if_missing': 'low',
        'cwe': 'CWE-942',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'Cache-Control': {
        'description': 'Controls caching of sensitive pages',
        'recommended': 'no-store, no-cache, must-revalidate',
        'severity_if_missing': 'low',
        'cwe': 'CWE-525',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
    'Clear-Site-Data': {
        'description': 'Clears browsing data on logout',
        'recommended': '"cache", "cookies", "storage"',
        'severity_if_missing': 'low',
        'cwe': 'CWE-613',
        'owasp_category': 'A05:2021 - Security Misconfiguration',
    },
}

# Headers that disclose sensitive information
DISCLOSURE_HEADERS = {
    'Server': {
        'description': 'Reveals web server software and version',
        'severity': 'medium',
        'cwe': 'CWE-200',
        'recommendation': 'Configure ServerTokens to minimal or use ServerSignature Off',
    },
    'X-Powered-By': {
        'description': 'Reveals technology stack and version',
        'severity': 'medium',
        'cwe': 'CWE-200',
        'recommendation': 'Remove this header via server configuration',
    },
    'X-AspNet-Version': {
        'description': 'Reveals ASP.NET version',
        'severity': 'medium',
        'cwe': 'CWE-200',
        'recommendation': 'Remove via web.config: <httpRuntime enableVersionHeader="false"/>',
    },
    'X-AspNetMvc-Version': {
        'description': 'Reveals ASP.NET MVC version',
        'severity': 'low',
        'cwe': 'CWE-200',
        'recommendation': 'Set MvcHandler.DisableMvcResponseHeader = true',
    },
    'X-Generator': {
        'description': 'Reveals CMS or framework used',
        'severity': 'low',
        'cwe': 'CWE-200',
        'recommendation': 'Remove via CMS settings or server configuration',
    },
    'X-Drupal-Cache': {
        'description': 'Reveals Drupal caching status',
        'severity': 'low',
        'cwe': 'CWE-200',
        'recommendation': 'Disable via Drupal configuration',
    },
    'X-Drupal-Dynamic-Cache': {
        'description': 'Reveals Drupal cache configuration',
        'severity': 'low',
        'cwe': 'CWE-200',
        'recommendation': 'Disable via Drupal configuration',
    },
}