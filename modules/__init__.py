"""
Web Security Scanner Pro - Modules Package
Version: 3.0.0

This is the main modules package that contains all security testing modules
organized by category.

Module Categories:
    cms/              - CMS-specific security tests (WordPress, Joomla, Drupal)
    webserver/        - Web server security tests (Apache, Nginx, LiteSpeed, IIS, Tomcat)
    php/              - PHP version, configuration, and security analysis
    database/         - Database security tests (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch)
    control_panels/   - Hosting control panel security tests (cPanel, DirectAdmin, Plesk, Virtualmin)
    vulnerabilities/  - Generic vulnerability scanners (XSS, SQLi, LFI, RFI, XXE, SSTI, CSRF, etc.)
    ssl_tls/          - SSL/TLS certificate and protocol analysis
    headers/          - HTTP security headers and information disclosure analysis
    api_security/     - API security testing (GraphQL, REST, JWT)

Total Modules: 50+

Usage:
    from modules.cms.wordpress.detector import Scanner as WPDetector
    from modules.vulnerabilities.xss import Scanner as XSSScanner
    from modules.webserver.apache import Scanner as ApacheScanner

Adding a new module:
    1. Create a new file in the appropriate category directory
    2. Implement a Scanner class with __init__(browser, target_url, config) and run() method
    3. Register the module in core/scanner.py MODULE_MAP
    4. Add configuration in config.yaml

Module Interface:
    class Scanner:
        def __init__(self, browser, target_url: str, config: Dict):
            ...
        
        def run(self) -> Dict:
            '''
            Returns:
                {
                    'module': str,
                    'findings': [
                        {
                            'title': str,
                            'severity': str,  # critical, high, medium, low, info
                            'description': str,
                            'recommendation': str,
                            'module': str,
                            'cwe_id': str (optional),
                            'cvss_score': float (optional),
                            'evidence': str (optional),
                            'references': List[str] (optional),
                        }
                    ]
                }
            '''
"""

__version__ = "3.0.0"
__author__ = "Security Research Team"
__all__ = [
    'cms',
    'webserver',
    'php',
    'database',
    'control_panels',
    'vulnerabilities',
    'ssl_tls',
    'headers',
    'api_security',
]


def get_module_version() -> str:
    """Get the modules package version."""
    return __version__


def list_categories() -> list:
    """List all module categories."""
    return [
        'cms',
        'webserver',
        'php',
        'database',
        'control_panels',
        'vulnerabilities',
        'ssl_tls',
        'headers',
        'api_security',
    ]


def get_category_description(category: str) -> str:
    """Get description of a module category."""
    descriptions = {
        'cms': 'Content Management System security scanners',
        'webserver': 'Web server security analysis',
        'php': 'PHP security testing and configuration analysis',
        'database': 'Database security and exposure detection',
        'control_panels': 'Hosting control panel security assessment',
        'vulnerabilities': 'Generic web vulnerability scanners',
        'ssl_tls': 'SSL/TLS certificate and protocol analysis',
        'headers': 'HTTP security headers and information disclosure',
        'api_security': 'API security testing (GraphQL, REST, JWT)',
    }
    return descriptions.get(category, 'Unknown category')