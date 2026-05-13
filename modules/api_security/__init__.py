"""
API Security Scanner Modules Package
Version: 3.0.0

This package contains modules for API security testing and analysis.

Modules:
    graphql.py       - GraphQL API security scanner (introspection, queries, mutations)
    rest_api.py      - REST API security scanner (endpoints, methods, authentication)
    jwt.py           - JWT (JSON Web Token) security analyzer

Each module is designed to identify common API security vulnerabilities including:
    - Missing or weak authentication
    - Excessive data exposure
    - Mass assignment vulnerabilities
    - Rate limiting issues
    - Injection vulnerabilities
    - Insecure direct object references (IDOR)
    - Security misconfiguration
"""

__version__ = "3.0.0"

# Module metadata for dynamic loading
MODULE_METADATA = {
    'graphql': {
        'name': 'GraphQL Security Scanner',
        'description': 'Analyzes GraphQL endpoints for security vulnerabilities',
        'category': 'api_security',
        'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
        'owasp_category': 'API10:2023 - Unsafe Consumption of APIs',
    },
    'rest_api': {
        'name': 'REST API Security Scanner',
        'description': 'Analyzes REST API endpoints for security vulnerabilities',
        'category': 'api_security',
        'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
        'owasp_category': 'API1:2023 - Broken Object Level Authorization',
    },
    'jwt': {
        'name': 'JWT Security Analyzer',
        'description': 'Analyzes JSON Web Tokens for security weaknesses',
        'category': 'api_security',
        'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
        'owasp_category': 'API2:2023 - Broken Authentication',
    },
}