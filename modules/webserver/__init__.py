"""
Web Server Security Scanner Modules Package
Version: 3.0.0

This package contains modules for web server security analysis including
version detection, configuration analysis, and vulnerability assessment.

Modules:
    apache.py      - Apache HTTP Server security scanner
    nginx.py       - Nginx web server security scanner
    litespeed.py   - LiteSpeed Web Server security scanner
    iis.py         - Microsoft IIS security scanner
    tomcat.py      - Apache Tomcat security scanner

Common web server security issues include:
    - Outdated server versions with known vulnerabilities
    - Exposed server-status and server-info pages
    - Directory listing enabled
    - Default files and configurations
    - Missing security headers
    - TRACE method enabled (Cross-Site Tracing)
    - WebDAV misconfiguration
    - Exposed configuration files
    - Default credentials on admin interfaces

References:
    - OWASP Web Server Security: https://owasp.org/www-project-web-security-testing-guide/
    - CWE-200: Exposure of Sensitive Information
    - CWE-16: Configuration
    - Apache Security Tips: https://httpd.apache.org/docs/2.4/misc/security_tips.html
    - Nginx Security: https://nginx.org/en/docs/control.html
"""

__version__ = "3.0.0"

# Web server signatures for detection
WEBSERVER_SIGNATURES = {
    'apache': {
        'name': 'Apache HTTP Server',
        'header_pattern': r'Apache(?:/([\d.]+))?',
        'default_ports': [80, 443, 8080, 8443],
        'paths': [
            '/server-status',
            '/server-info',
            '/icons/',
            '/manual/',
            '/.htaccess',
            '/cgi-bin/',
        ],
    },
    'nginx': {
        'name': 'Nginx',
        'header_pattern': r'nginx(?:/([\d.]+))?',
        'default_ports': [80, 443, 8080, 8443],
        'paths': [
            '/nginx-status',
            '/nginx_status',
            '/.nginx/',
        ],
    },
    'litespeed': {
        'name': 'LiteSpeed Web Server',
        'header_pattern': r'LiteSpeed(?:/([\d.]+))?',
        'default_ports': [80, 443, 8088, 7080],
        'paths': [
            '/phpinfo.php',
            '/status/',
        ],
    },
    'iis': {
        'name': 'Microsoft IIS',
        'header_pattern': r'Microsoft-IIS(?:/([\d.]+))?',
        'default_ports': [80, 443, 8080, 8443],
        'paths': [
            '/iisstart.htm',
            '/welcome.png',
            '/trace.axd',
            '/aspnet_client/',
        ],
    },
    'tomcat': {
        'name': 'Apache Tomcat',
        'header_pattern': r'Apache-Coyote(?:/([\d.]+))?',
        'default_ports': [8080, 8443, 8009],
        'paths': [
            '/manager/html',
            '/manager/status',
            '/host-manager/html',
            '/examples/',
            '/docs/',
        ],
    },
}

# Common sensitive paths across web servers
COMMON_SENSITIVE_PATHS = [
    '/.git/HEAD',
    '/.svn/entries',
    '/.env',
    '/backup/',
    '/bak/',
    '/old/',
    '/test/',
    '/debug/',
    '/phpinfo.php',
    '/info.php',
    '/config.php',
    '/wp-config.php',
    '/admin/',
    '/administrator/',
    '/phpmyadmin/',
    '/.htaccess',
    '/.htpasswd',
]