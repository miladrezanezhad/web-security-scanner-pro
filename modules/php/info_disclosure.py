#!/usr/bin/env python3
"""
PHP Information Disclosure Detection Module.
Detects various forms of PHP information leakage.

References:
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
    - CWE-200: Exposure of Sensitive Information
    - CWE-209: Generation of Error Message Containing Sensitive Information
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """PHP information disclosure detection scanner."""
    
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
        self.module_name = "PHP Information Disclosure"
        
        # Files that might disclose PHP version or configuration
        self.version_files = [
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/phpinfo',
            '/info',
            '/phpversion.php',
            '/version.php',
        ]
        
        # PHP error log paths
        self.error_log_paths = [
            '/error_log',
            '/error.log',
            '/php_error.log',
            '/php_errors.log',
            '/debug.log',
            '/php_errorlog',
            '/wp-content/debug.log',
            '/logs/error.log',
            '/log/error.log',
            '/tmp/php-errors.log',
        ]
        
        # PHP configuration file paths
        self.config_paths = [
            '/php.ini',
            '/php.ini.bak',
            '/php.ini~',
            '/php.ini.old',
            '/php.ini.orig',
            '/.user.ini',
            '/.user.ini.bak',
            '/usr/local/php.ini',
            '/etc/php.ini',
        ]
        
        # PHP session file paths
        self.session_paths = [
            '/tmp/sess_',
            '/var/lib/php/sessions/',
            '/var/lib/php/session/',
        ]
        
        # PHP error patterns for version detection
        self.version_error_patterns = [
            r'PHP ([\d.]+)',
            r'PHP Version ([\d.]+)',
            r'PHP/([\d.]+)',
            r'php-([\d.]+)',
        ]
        
        # Stack trace patterns
        self.stack_trace_patterns = [
            r'Stack trace:',
            r'#\d+\s+/[^(]+\(\d+\):',
            r'at /[^:]+:\d+',
            r'called in /[^:]+:\d+',
            r'Traceback',
            r'Debug Backtrace',
        ]
        
        # Database connection error patterns
        self.db_error_patterns = [
            r'SQLSTATE\[\d+\]',
            r'mysql_connect\(\)',
            r'mysqli_connect\(\)',
            r'pg_connect\(\)',
            r'PDOException',
            r'Access denied for user',
            r'Unknown database',
            r'connection refused',
        ]
        
        # Composer/vendor exposure
        self.composer_paths = [
            '/composer.json',
            '/composer.lock',
            '/vendor/composer/installed.json',
            '/vendor/autoload.php',
            '/vendor/',
        ]
        
        # Environment file paths
        self.env_paths = [
            '/.env',
            '/.env.local',
            '/.env.production',
            '/.env.development',
            '/.env.staging',
            '/.env.example',
            '/.env.backup',
            '/.env.bak',
            '/.env~',
        ]
    
    def run(self) -> Dict:
        """
        Execute PHP information disclosure detection.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'php_version_exposed': False,
            'php_version': None,
            'error_logs_exposed': [],
            'config_files_exposed': [],
            'stack_traces_exposed': False,
            'db_errors_exposed': False,
            'composer_files_exposed': [],
            'env_files_exposed': [],
            'findings': []
        }
        
        # Stage 1: Check PHP version exposure
        version_info = self._check_version_exposure()
        result['php_version_exposed'] = version_info['exposed']
        result['php_version'] = version_info['version']
        
        if version_info['exposed']:
            self.findings.append({
                'title': f"PHP version exposed: {version_info['version']}",
                'severity': 'medium',
                'description': (
                    f"PHP version {version_info['version']} is exposed through "
                    f"{version_info.get('method', 'unknown')}. "
                    "Version disclosure helps attackers identify known vulnerabilities."
                ),
                'recommendation': (
                    "1. Set expose_php = Off in php.ini\n"
                    "2. Remove X-Powered-By header via web server config\n"
                    "3. Hide version in error pages\n"
                    "4. Use generic error messages"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
                'evidence': f"Version: {version_info['version']}, Method: {version_info.get('method')}",
            })
        
        # Stage 2: Check error logs exposure
        error_logs = self._check_error_logs()
        result['error_logs_exposed'] = error_logs
        
        for log_info in error_logs:
            self.findings.append({
                'title': f"PHP error log publicly accessible: {log_info['path']}",
                'severity': 'high',
                'description': (
                    f"A PHP error log file is accessible at {log_info['path']}. "
                    f"Size: {log_info.get('size', 'unknown')} bytes. "
                    "Error logs may contain sensitive information including:\n"
                    "- File paths and directory structure\n"
                    "- Database queries and credentials\n"
                    "- Stack traces with code snippets\n"
                    "- User input and request data"
                ),
                'recommendation': (
                    "1. Move error logs outside web root\n"
                    "2. Set proper file permissions (640)\n"
                    "3. Configure PHP error_log to a non-web-accessible path\n"
                    "4. Add to .htaccess: <Files error_log> Deny from all </Files>"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-532',
                'cvss_score': 7.5,
                'evidence': f"Path: {log_info['path']}, Size: {log_info.get('size', 0)} bytes",
            })
        
        # Stage 3: Check configuration file exposure
        config_files = self._check_config_files()
        result['config_files_exposed'] = config_files
        
        for config_info in config_files:
            self.findings.append({
                'title': f"PHP configuration file exposed: {config_info['path']}",
                'severity': 'critical' if 'php.ini' in config_info['path'] else 'high',
                'description': (
                    f"A PHP configuration file is accessible at {config_info['path']}. "
                    "This file may contain:\n"
                    "- Database credentials\n"
                    "- API keys and secrets\n"
                    "- Full PHP configuration\n"
                    "- Security settings"
                ),
                'recommendation': (
                    "1. Remove configuration files from web root immediately\n"
                    "2. Set file permissions to 600\n"
                    "3. Add to .htaccess: <Files php.ini> Deny from all </Files>"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.0 if 'php.ini' in config_info['path'] else 7.5,
                'evidence': f"Path: {config_info['path']}, Status: {config_info['status']}",
            })
        
        # Stage 4: Check stack trace exposure
        stack_result = self._check_stack_traces()
        result['stack_traces_exposed'] = stack_result
        
        if stack_result:
            self.findings.append({
                'title': 'PHP stack traces exposed in error messages',
                'severity': 'high',
                'description': (
                    "PHP stack traces are being displayed to users. "
                    "Stack traces reveal:\n"
                    "- Exact file paths on the server\n"
                    "- Function and class names\n"
                    "- Line numbers\n"
                    "- Code snippets\n"
                    "- Database queries"
                ),
                'recommendation': (
                    "1. Set display_errors = Off in php.ini\n"
                    "2. Set log_errors = On\n"
                    "3. Use custom error/exception handler\n"
                    "4. Display generic error messages to users"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-209',
                'cvss_score': 7.5,
                'evidence': 'Stack traces found in HTTP responses',
            })
        
        # Stage 5: Check database error exposure
        db_result = self._check_db_errors()
        result['db_errors_exposed'] = db_result
        
        if db_result:
            self.findings.append({
                'title': 'Database connection errors exposed',
                'severity': 'critical',
                'description': (
                    "Database error messages are being displayed. These may reveal:\n"
                    "- Database hostname and port\n"
                    "- Database username\n"
                    "- Database name\n"
                    "- Table and column names\n"
                    "- Query structure"
                ),
                'recommendation': (
                    "1. Catch all database exceptions\n"
                    "2. Log detailed errors server-side only\n"
                    "3. Display generic 'Service unavailable' to users\n"
                    "4. Use PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION\n"
                    "5. Set PDO::ATTR_ERRMODE_SILENT in production"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-209',
                'cvss_score': 8.5,
                'evidence': 'Database error messages found in responses',
            })
        
        # Stage 6: Check composer files exposure
        composer_files = self._check_composer_files()
        result['composer_files_exposed'] = composer_files
        
        for comp_info in composer_files:
            severity = 'high' if comp_info['path'].endswith('.lock') else 'medium'
            self.findings.append({
                'title': f"Composer file exposed: {comp_info['path']}",
                'severity': severity,
                'description': (
                    f"A Composer file is accessible at {comp_info['path']}. "
                    "This reveals:\n"
                    "- All installed PHP packages and versions\n"
                    "- Application dependencies\n"
                    "- Development requirements"
                ),
                'recommendation': (
                    "1. Block access to composer files:\n"
                    "   Apache: <Files composer.*> Deny from all </Files>\n"
                    "   Nginx: location ~ /composer\.(json|lock) { deny all; }\n"
                    "2. Never deploy composer files to production\n"
                    "3. Add composer.json and composer.lock to deployment exclude list"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 7.0 if comp_info['path'].endswith('.lock') else 5.0,
                'evidence': f"Path: {comp_info['path']}, Status: {comp_info['status']}",
            })
        
        # Stage 7: Check .env file exposure
        env_files = self._check_env_files()
        result['env_files_exposed'] = env_files
        
        for env_info in env_files:
            self.findings.append({
                'title': f"Environment file exposed: {env_info['path']}",
                'severity': 'critical',
                'description': (
                    f"An environment configuration file is accessible at {env_info['path']}. "
                    "These files typically contain:\n"
                    "- Database credentials (DB_HOST, DB_USER, DB_PASS)\n"
                    "- API keys and secrets\n"
                    "- Mail server credentials\n"
                    "- Application encryption keys\n"
                    "- Third-party service credentials"
                ),
                'recommendation': (
                    "1. DELETE the exposed .env file immediately\n"
                    "2. Rotate all exposed credentials and API keys\n"
                    "3. Add to .htaccess: <Files .env> Deny from all </Files>\n"
                    "4. Ensure .env is in .gitignore\n"
                    "5. Never store .env files in web root\n"
                    "6. Use server-level environment variables instead"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 9.5,
                'evidence': f"Path: {env_info['path']}, Status: {env_info['status']}",
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Version exposed: {result['php_version_exposed']}, "
            f"Error logs: {len(error_logs)}, "
            f"Config files: {len(config_files)}, "
            f"Env files: {len(env_files)}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _check_version_exposure(self) -> Dict:
        """Check for PHP version exposure."""
        result = {
            'exposed': False,
            'version': None,
            'method': None,
        }
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        # Method 1: X-Powered-By header
        powered_by = resp.headers.get('X-Powered-By', '')
        if 'PHP/' in powered_by:
            match = re.search(r'PHP/([\d.]+)', powered_by)
            if match:
                result['exposed'] = True
                result['version'] = match.group(1)
                result['method'] = 'X-Powered-By header'
                return result
        
        # Method 2: Server header
        server = resp.headers.get('Server', '')
        if 'PHP' in server:
            match = re.search(r'PHP/([\d.]+)', server)
            if match:
                result['exposed'] = True
                result['version'] = match.group(1)
                result['method'] = 'Server header'
                return result
        
        return result
    
    def _check_error_logs(self) -> List[Dict]:
        """Check for exposed error log files."""
        exposed = []
        
        for path in self.error_log_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                content_length = len(resp.text) if hasattr(resp, 'text') else 0
                
                if content_length > 0:
                    # Verify it's an error log
                    php_indicators = [
                        'PHP Warning',
                        'PHP Notice',
                        'PHP Fatal error',
                        'PHP Parse error',
                        'Stack trace',
                        'on line',
                    ]
                    
                    is_error_log = any(indicator in resp.text for indicator in php_indicators)
                    
                    if is_error_log or 'error' in path.lower() or 'debug' in path.lower():
                        exposed.append({
                            'path': path,
                            'size': content_length,
                            'status': resp.status_code,
                        })
        
        return exposed
    
    def _check_config_files(self) -> List[Dict]:
        """Check for exposed PHP configuration files."""
        exposed = []
        
        for path in self.config_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                content = resp.text[:500]
                
                # Check if it's a PHP config file
                ini_indicators = [
                    '[PHP]',
                    'engine =',
                    'max_execution_time',
                    'memory_limit',
                    'error_reporting',
                    'display_errors',
                    'post_max_size',
                    'upload_max_filesize',
                ]
                
                is_config = any(indicator in content for indicator in ini_indicators)
                
                if is_config:
                    exposed.append({
                        'path': path,
                        'status': resp.status_code,
                        'size': len(resp.text),
                    })
        
        return exposed
    
    def _check_stack_traces(self) -> bool:
        """Check for stack trace exposure in error responses."""
        test_paths = [
            '/?test[]=1',
            '/wp-content/plugins/nonexistent/',
            '/api/nonexistent',
        ]
        
        for path in test_paths:
            resp = self.browser.get(path)
            if not resp:
                continue
            
            for pattern in self.stack_trace_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return True
        
        return False
    
    def _check_db_errors(self) -> bool:
        """Check for database error exposure."""
        test_paths = [
            '/?id=1\'',
            '/wp-content/plugins/nonexistent/',
            '/api/users?id=1\'',
        ]
        
        for path in test_paths:
            resp = self.browser.get(path)
            if not resp:
                continue
            
            for pattern in self.db_error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return True
        
        return False
    
    def _check_composer_files(self) -> List[Dict]:
        """Check for exposed Composer files."""
        exposed = []
        
        for path in self.composer_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                # Verify it's a Composer file
                if path.endswith('.json'):
                    try:
                        import json
                        data = json.loads(resp.text)
                        if 'require' in data or 'autoload' in data:
                            exposed.append({
                                'path': path,
                                'status': resp.status_code,
                            })
                    except:
                        pass
                elif path.endswith('.lock'):
                    if '"packages"' in resp.text or '"content-hash"' in resp.text:
                        exposed.append({
                            'path': path,
                            'status': resp.status_code,
                        })
        
        return exposed
    
    def _check_env_files(self) -> List[Dict]:
        """Check for exposed .env files."""
        exposed = []
        
        for path in self.env_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                content = resp.text[:500]
                
                env_indicators = [
                    'APP_ENV=',
                    'DB_HOST=',
                    'DB_DATABASE=',
                    'DB_USERNAME=',
                    'DB_PASSWORD=',
                    'APP_KEY=',
                    'JWT_SECRET=',
                    'MAIL_HOST=',
                    'REDIS_HOST=',
                ]
                
                for indicator in env_indicators:
                    if indicator in content:
                        exposed.append({
                            'path': path,
                            'status': resp.status_code,
                            'size': len(resp.text),
                            'content_preview': content[:200],
                        })
                        break
        
        return exposed