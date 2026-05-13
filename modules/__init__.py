"""
Web Security Analyzer Pro - Security Modules Package
Version: 3.0.0

This package contains all security testing modules organized by category.

Module Categories:
    cms/           - CMS-specific tests (WordPress, Joomla, Drupal)
    webserver/     - Web server security tests
    php/           - PHP version and configuration tests
    database/      - Database security tests
    control_panels/- Hosting control panel tests
    vulnerabilities/- Generic vulnerability scanners (XSS, SQLi, etc.)
    ssl_tls/       - SSL/TLS certificate analysis
    headers/       - HTTP security headers checks
    api_security/  - API security testing (GraphQL, REST, JWT)

Adding a New Module:
    1. Create your module in the appropriate category directory
    2. Implement the Scanner class with run() method
    3. Register in core/scanner.py MODULE_MAP
    4. Add configuration in config.yaml
"""

__version__ = "3.0.0"

# Module registry
AVAILABLE_MODULES = {
    # CMS
    "wordpress": "modules.cms.wordpress.detector",
    "joomla": "modules.cms.joomla.scanner",
    "drupal": "modules.cms.drupal.scanner",
    
    # Web Servers
    "apache": "modules.webserver.apache",
    "nginx": "modules.webserver.nginx",
    "litespeed": "modules.webserver.litespeed",
    "iis": "modules.webserver.iis",
    "tomcat": "modules.webserver.tomcat",
    
    # PHP
    "php_version": "modules.php.version",
    "php_config": "modules.php.configuration",
    "php_functions": "modules.php.dangerous_functions",
    "php_info": "modules.php.info_disclosure",
    
    # Databases
    "mysql": "modules.database.mysql",
    "postgresql": "modules.database.postgresql",
    "redis": "modules.database.redis",
    "mongodb": "modules.database.mongodb",
    "elasticsearch": "modules.database.elasticsearch",
    
    # Control Panels
    "cpanel": "modules.control_panels.cpanel",
    "directadmin": "modules.control_panels.directadmin",
    "plesk": "modules.control_panels.plesk",
    "virtualmin": "modules.control_panels.virtualmin",
    
    # Vulnerabilities
    "xss": "modules.vulnerabilities.xss",
    "sqli": "modules.vulnerabilities.sqli",
    "lfi": "modules.vulnerabilities.lfi",
    "rfi": "modules.vulnerabilities.rfi",
    "xxe": "modules.vulnerabilities.xxe",
    "ssti": "modules.vulnerabilities.ssti",
    "csrf": "modules.vulnerabilities.csrf",
    "command_injection": "modules.vulnerabilities.command_injection",
    "file_upload": "modules.vulnerabilities.file_upload",
    "deserialization": "modules.vulnerabilities.deserialization",
    "ssrf": "modules.vulnerabilities.ssrf",
    
    # SSL/TLS
    "ssl_cert": "modules.ssl_tls.certificate",
    "ssl_proto": "modules.ssl_tls.protocols",
    "ssl_cipher": "modules.ssl_tls.ciphers",
    
    # Headers
    "security_headers": "modules.headers.security_headers",
    "info_disclosure": "modules.headers.information_disclosure",
    
    # API Security
    "graphql": "modules.api_security.graphql",
    "rest_api": "modules.api_security.rest_api",
    "jwt": "modules.api_security.jwt",
}


def get_module_info(module_name: str) -> dict:
    """
    Get information about a module.
    
    Args:
        module_name: Name of the module
    
    Returns:
        Dict with module information
    """
    if module_name in AVAILABLE_MODULES:
        return {
            "name": module_name,
            "path": AVAILABLE_MODULES[module_name],
            "available": True
        }
    
    return {
        "name": module_name,
        "available": False,
        "error": f"Module '{module_name}' not found"
    }


def list_available_modules() -> list:
    """
    List all available modules.
    
    Returns:
        List of module names
    """
    return list(AVAILABLE_MODULES.keys())


def get_modules_by_category(category: str) -> list:
    """
    Get modules filtered by category.
    
    Args:
        category: Category name (cms, webserver, php, etc.)
    
    Returns:
        List of module names in the category
    """
    return [name for name, path in AVAILABLE_MODULES.items() if category in path]