"""
PHP Security Scanner Modules Package
Version: 3.0.0

This package contains modules for PHP security analysis including version detection,
configuration analysis, dangerous function detection, and information disclosure checks.

Modules:
    version.py              - PHP version detection and vulnerability matching
    configuration.py        - PHP configuration security analysis (php.ini settings)
    dangerous_functions.py  - Detection of dangerous PHP functions and settings
    info_disclosure.py      - PHP information disclosure detection (phpinfo, errors, etc.)

PHP remains one of the most widely used server-side languages, powering over 75% of websites.
Common PHP security issues include:
    - Outdated PHP versions with known vulnerabilities
    - Dangerous functions enabled (exec, system, eval, etc.)
    - Information disclosure via phpinfo() and error messages
    - Weak php.ini configuration settings
    - Remote/ Local File Inclusion vulnerabilities
    - Insecure session management

References:
    - PHP Security Manual: https://www.php.net/manual/en/security.php
    - OWASP PHP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/PHP_Security_Cheat_Sheet.html
    - PHP Security Consortium: https://phpsec.org/
    - CWE-200: Exposure of Sensitive Information
    - CWE-94: Improper Control of Generation of Code (Eval Injection)
    - CWE-78: OS Command Injection
"""

__version__ = "3.0.0"

# PHP configuration directives and their security implications
PHP_SECURITY_DIRECTIVES = {
    # High risk - should be disabled in production
    'allow_url_fopen': {
        'recommended': 'Off',
        'severity': 'high',
        'description': 'Allows PHP to open remote files via URLs (RFI vulnerability)',
        'cwe': 'CWE-829',
    },
    'allow_url_include': {
        'recommended': 'Off',
        'severity': 'critical',
        'description': 'Allows including remote files via include/require (RFI vulnerability)',
        'cwe': 'CWE-829',
    },
    'display_errors': {
        'recommended': 'Off',
        'severity': 'high',
        'description': 'Displays PHP errors to users (information disclosure)',
        'cwe': 'CWE-209',
    },
    'display_startup_errors': {
        'recommended': 'Off',
        'severity': 'high',
        'description': 'Displays PHP startup errors (information disclosure)',
        'cwe': 'CWE-209',
    },
    'expose_php': {
        'recommended': 'Off',
        'severity': 'medium',
        'description': 'Exposes PHP version in X-Powered-By header',
        'cwe': 'CWE-200',
    },
    'enable_dl': {
        'recommended': 'Off',
        'severity': 'high',
        'description': 'Allows dynamic loading of PHP extensions at runtime',
        'cwe': 'CWE-676',
    },
    
    # Session security
    'session.cookie_httponly': {
        'recommended': 'On',
        'severity': 'medium',
        'description': 'Prevents JavaScript access to session cookies (XSS protection)',
        'cwe': 'CWE-1004',
    },
    'session.cookie_secure': {
        'recommended': 'On',
        'severity': 'medium',
        'description': 'Only sends session cookies over HTTPS',
        'cwe': 'CWE-614',
    },
    'session.cookie_samesite': {
        'recommended': 'Strict',
        'severity': 'medium',
        'description': 'Prevents CSRF attacks via SameSite cookie attribute',
        'cwe': 'CWE-1275',
    },
    'session.use_strict_mode': {
        'recommended': 'On',
        'severity': 'medium',
        'description': 'Prevents session fixation attacks',
        'cwe': 'CWE-384',
    },
    'session.use_only_cookies': {
        'recommended': 'On',
        'severity': 'low',
        'description': 'Prevents session ID in URLs',
        'cwe': 'CWE-598',
    },
    
    # Error handling
    'log_errors': {
        'recommended': 'On',
        'severity': 'low',
        'description': 'Logs errors to file instead of displaying them',
        'cwe': 'CWE-778',
    },
    'error_reporting': {
        'recommended': 'E_ALL & ~E_DEPRECATED & ~E_STRICT',
        'severity': 'medium',
        'description': 'Controls which errors are reported (should be strict in dev, minimal in prod)',
        'cwe': 'CWE-209',
    },
    
    # File uploads
    'file_uploads': {
        'recommended': 'On (with limits)',
        'severity': 'low',
        'description': 'Controls whether file uploads are allowed',
        'cwe': 'CWE-434',
    },
    'upload_max_filesize': {
        'recommended': '10M or less',
        'severity': 'low',
        'description': 'Maximum upload file size (DoS protection)',
        'cwe': 'CWE-770',
    },
    'max_file_uploads': {
        'recommended': '20 or less',
        'severity': 'low',
        'description': 'Maximum number of files per upload (DoS protection)',
        'cwe': 'CWE-770',
    },
    
    # Execution limits (DoS protection)
    'max_execution_time': {
        'recommended': '30 or less',
        'severity': 'low',
        'description': 'Maximum script execution time (DoS protection)',
        'cwe': 'CWE-770',
    },
    'max_input_time': {
        'recommended': '60 or less',
        'severity': 'low',
        'description': 'Maximum time for parsing input data',
        'cwe': 'CWE-770',
    },
    'memory_limit': {
        'recommended': '128M or less',
        'severity': 'low',
        'description': 'Maximum memory per script (DoS protection)',
        'cwe': 'CWE-770',
    },
    'post_max_size': {
        'recommended': '8M or less',
        'severity': 'low',
        'description': 'Maximum POST data size (DoS protection)',
        'cwe': 'CWE-770',
    },
    
    # Open_basedir restriction
    'open_basedir': {
        'recommended': 'Set to web root',
        'severity': 'high',
        'description': 'Restricts PHP file access to specified directories',
        'cwe': 'CWE-22',
    },
    'disable_functions': {
        'recommended': 'exec, system, passthru, shell_exec, etc.',
        'severity': 'critical',
        'description': 'Disables dangerous PHP functions',
        'cwe': 'CWE-78',
    },
}

# Dangerous PHP functions by category
DANGEROUS_FUNCTIONS = {
    'command_execution': {
        'functions': [
            'exec', 'system', 'passthru', 'shell_exec', 'popen',
            'proc_open', 'pcntl_exec', 'expect_popen',
        ],
        'severity': 'critical',
        'description': 'Functions that execute system commands',
        'cwe': 'CWE-78',
    },
    'code_execution': {
        'functions': [
            'eval', 'assert', 'preg_replace_with_eval',
            'create_function', 'include', 'require',
            'include_once', 'require_once',
        ],
        'severity': 'critical',
        'description': 'Functions that can execute arbitrary PHP code',
        'cwe': 'CWE-94',
    },
    'file_operations': {
        'functions': [
            'fopen', 'file_get_contents', 'file_put_contents',
            'fwrite', 'fputs', 'fread', 'file',
            'readfile', 'move_uploaded_file', 'copy',
            'rename', 'unlink', 'mkdir', 'rmdir',
            'symlink', 'link', 'tmpfile', 'tempnam',
        ],
        'severity': 'high',
        'description': 'Functions for file system operations',
        'cwe': 'CWE-73',
    },
    'information_disclosure': {
        'functions': [
            'phpinfo', 'phpversion', 'getenv',
            'get_cfg_var', 'ini_get', 'ini_get_all',
            'get_loaded_extensions', 'get_defined_functions',
            'get_defined_constants', 'get_declared_classes',
            'debug_backtrace', 'debug_print_backtrace',
        ],
        'severity': 'medium',
        'description': 'Functions that expose system/configuration information',
        'cwe': 'CWE-200',
    },
    'network_operations': {
        'functions': [
            'fsockopen', 'pfsockopen', 'socket_create',
            'socket_connect', 'curl_exec', 'curl_multi_exec',
            'stream_socket_client', 'stream_socket_server',
        ],
        'severity': 'medium',
        'description': 'Functions for network operations (SSRF potential)',
        'cwe': 'CWE-918',
    },
    'serialization': {
        'functions': [
            'unserialize', 'serialize',
            'wddx_serialize_value', 'wddx_deserialize',
        ],
        'severity': 'high',
        'description': 'Functions for object serialization (deserialization attacks)',
        'cwe': 'CWE-502',
    },
    'mail': {
        'functions': [
            'mail', 'mb_send_mail', 'imap_mail',
        ],
        'severity': 'medium',
        'description': 'Mail functions (email injection potential)',
        'cwe': 'CWE-94',
    },
    'database': {
        'functions': [
            'mysql_query', 'mysql_db_query', 'mysql_unbuffered_query',
            'mysqli_query', 'mysqli_multi_query',
            'pg_query', 'pg_send_query',
            'sqlite_query', 'sqlite_single_query',
            'odbc_exec', 'odbc_execute',
        ],
        'severity': 'high',
        'description': 'Database query functions (SQL injection potential)',
        'cwe': 'CWE-89',
    },
}