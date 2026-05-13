"""
CMS Security Scanner Modules Package
Version: 3.0.0

This package contains modules for Content Management System (CMS) security analysis.

Modules:
    wordpress/    - WordPress security scanner (detector, version, plugins, themes, users, etc.)
    joomla/       - Joomla security scanner
    drupal/       - Drupal security scanner

Each CMS module includes:
    - CMS detection and fingerprinting
    - Version enumeration and vulnerability matching
    - Plugin/extension enumeration
    - Theme/template detection
    - User enumeration
    - Configuration analysis
    - Backup file detection
    - Security hardening checks
"""

__version__ = "3.0.0"

# CMS detection signatures
CMS_SIGNATURES = {
    'wordpress': {
        'paths': ['/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-login.php'],
        'meta': ['<meta name="generator" content="WordPress'],
        'headers': ['X-Powered-By: WordPress'],
        'files': ['/readme.html', '/license.txt', '/wp-config.php'],
    },
    'joomla': {
        'paths': ['/administrator/', '/components/', '/modules/', '/plugins/'],
        'meta': ['<meta name="generator" content="Joomla'],
        'headers': ['X-Content-Encoded-By: Joomla'],
        'files': ['/htaccess.txt', '/web.config.txt', '/configuration.php'],
    },
    'drupal': {
        'paths': ['/core/', '/modules/', '/themes/', '/sites/default/'],
        'meta': ['<meta name="Generator" content="Drupal'],
        'headers': ['X-Generator: Drupal'],
        'files': ['/core/COPYRIGHT.txt', '/core/MAINTAINERS.txt', '/sites/default/settings.php'],
    },
}