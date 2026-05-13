#!/usr/bin/env python3
"""
WordPress Backup File Detection Module.
Scans for exposed backup files, database dumps, and archive files
that may contain sensitive information.

References:
    - WordPress Security: https://wordpress.org/documentation/article/hardening-wordpress/
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
    - CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory
"""

import re
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin
from datetime import datetime
from loguru import logger


class Scanner:
    """WordPress backup file detection scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize WordPress backup scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress Backup File Detection"
        
        # Common backup file extensions
        self.backup_extensions = [
            '.bak', '.backup', '.old', '.save', '.swp',
            '.zip', '.tar', '.tar.gz', '.tgz', '.gz',
            '.sql', '.sql.gz', '.dump', '.sql.zip',
            '.7z', '.rar', '.bz2',
            '.orig', '.original', '.copy', '.tmp',
            '.log', '.debug',
            '~', '.1', '.2', '-old', '-backup',
        ]
        
        # WordPress-specific backup patterns
        self.wp_backup_patterns = [
            # wp-config backups
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.php.backup',
            '/wp-config.php.old',
            '/wp-config.php.orig',
            '/wp-config.php.save',
            '/wp-config.php.swp',
            '/wp-config.php.tmp',
            '/wp-config.php~',
            '/wp-config.php.txt',
            '/wp-config.bak',
            '/wp-config.backup',
            '/wp-config.old',
            '/wp-config.txt',
            '/.wp-config.php.swp',
            
            # Database dumps
            '/db_backup.sql',
            '/database.sql',
            '/dump.sql',
            '/backup.sql',
            '/mysql.sql',
            '/wp-database-backup.sql',
            '/db.sql',
            '/export.sql',
            '/site.sql',
            '/wordpress.sql',
            '/wp_backup.sql',
            '/database_backup.sql',
            '/db_backup.sql.gz',
            '/database.sql.gz',
            '/backup.sql.zip',
            
            # Full site backups
            '/backup.zip',
            '/backup.tar.gz',
            '/backup.tar',
            '/site_backup.zip',
            '/site_backup.tar.gz',
            '/wp_backup.zip',
            '/wordpress_backup.zip',
            '/full_backup.zip',
            '/www_backup.tar.gz',
            '/public_html_backup.zip',
            '/html_backup.tar.gz',
            '/htdocs_backup.zip',
            
            # Plugin-specific backups
            '/wp-content/backups/',
            '/wp-content/backup-wordpress/',
            '/wp-content/backups/backup.zip',
            '/wp-content/updraft/',
            '/wp-content/updraft/backup.zip',
            '/wp-content/ai1wm-backups/',
            '/wp-content/backups-dup-lite/',
            '/wp-content/backup-migration/',
            '/wp-content/plugins/backup/backups/',
            '/wp-content/uploads/backupbuddy_backups/',
            '/wp-content/uploads/backups/',
            
            # wp-content backups
            '/wp-content.zip',
            '/wp-content.tar.gz',
            '/wp-content.bak',
            '/wp-content.backup',
            
            # Upload directory archives
            '/wp-content/uploads.zip',
            '/wp-content/uploads.tar.gz',
            '/wp-content/uploads.bak',
            
            # Theme backups
            '/wp-content/themes/backup.zip',
            '/wp-content/themes.tar.gz',
            
            # Plugin backups
            '/wp-content/plugins.zip',
            '/wp-content/plugins.tar.gz',
            
            # Server configuration backups
            '/.htaccess.bak',
            '/.htaccess.backup',
            '/.htaccess.old',
            '/.htaccess.orig',
            '/.htaccess~',
            '/.htpasswd.bak',
            '/.htpasswd.old',
            
            # Version control exposure
            '/.git/HEAD',
            '/.git/config',
            '/.git/index',
            '/.git/description',
            '/.gitignore',
            '/.svn/entries',
            '/.svn/wc.db',
            '/.hg/store/',
            
            # Environment files
            '/.env',
            '/.env.bak',
            '/.env.backup',
            '/.env.old',
            '/.env.example',
            '/.env.local',
            '/.env.production',
            '/.env.development',
            
            # Debug logs
            '/wp-content/debug.log',
            '/debug.log',
            '/error.log',
            '/error_log',
            '/php_error.log',
            '/wp-content/error.log',
            
            # Cache files
            '/wp-content/cache/',
            '/wp-content/w3tc/',
            '/wp-content/wp-rocket-config/',
            
            # Security plugin backups
            '/wp-content/wordfence/',
            '/wp-content/wflogs/',
            '/wp-content/uploads/sucuri/',
            
            # Maintenance files
            '/.maintenance',
            '/maintenance.php',
        ]
        
        # Duplicator specific paths
        self.duplicator_paths = [
            '/installer.php',
            '/installer-backup.php',
            '/dup-installer/',
            '/dup-installer/main.installer.php',
        ]
        
        # All-in-One WP Migration specific paths
        self.ai1wm_paths = [
            '/wp-content/ai1wm-backups/',
            '/wp-content/plugins/all-in-one-wp-migration/storage/',
        ]
        
        # BackupBuddy specific paths
        self.backupbuddy_paths = [
            '/wp-content/uploads/backupbuddy_backups/',
            '/wp-content/uploads/pb_backupbuddy/',
            '/wp-content/uploads/temp_backupbuddy/',
        ]
        
        # UpdraftPlus specific paths
        self.updraftplus_paths = [
            '/wp-content/updraft/',
            '/wp-content/updraft/backup_*.zip',
        ]
        
        # File content indicators
        self.content_indicators = {
            'database': [
                'CREATE TABLE',
                'INSERT INTO',
                'DROP TABLE',
                '-- phpMyAdmin SQL Dump',
                '-- MySQL dump',
                '-- WordPress database',
                'Database:',
                'mysqldump',
                'MariaDB dump',
                'SQLite format',
            ],
            'wp_config': [
                'DB_NAME',
                'DB_USER',
                'DB_PASSWORD',
                'DB_HOST',
                'AUTH_KEY',
                'SECURE_AUTH_KEY',
                'LOGGED_IN_KEY',
                'NONCE_KEY',
                'AUTH_SALT',
                'table_prefix',
                'WP_DEBUG',
            ],
            'archive': [
                'PK',  # ZIP file signature
                '\x1f\x8b',  # GZIP signature
                'ustar',  # TAR signature
                'Rar!',  # RAR signature
                '7z\xbc\xaf\x27\x1c',  # 7Z signature
            ],
            'env_file': [
                'APP_ENV=',
                'APP_KEY=',
                'DB_DATABASE=',
                'DB_USERNAME=',
                'DB_PASSWORD=',
                'MAIL_USERNAME=',
                'MAIL_PASSWORD=',
                'AWS_ACCESS_KEY',
                'AWS_SECRET_KEY',
                'JWT_SECRET=',
                'API_KEY=',
                'SECRET_KEY=',
            ],
        }
        
        # File size thresholds for different types
        self.size_thresholds = {
            'config': 100,       # Config files are usually small
            'database': 1024,    # Database dumps are usually larger
            'archive': 10240,    # Archives are usually > 10KB
            'log': 100,          # Logs can be any size
        }
    
    def run(self) -> Dict:
        """
        Execute backup file detection scan.
        
        Returns:
            Dict with findings and comprehensive analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'total_files_scanned': 0,
            'exposed_files': [],
            'exposed_database_dumps': [],
            'exposed_config_files': [],
            'exposed_archives': [],
            'exposed_logs': [],
            'exposed_env_files': [],
            'exposed_vcs': [],
            'critical_findings_count': 0,
            'high_findings_count': 0,
            'medium_findings_count': 0,
            'low_findings_count': 0,
            'findings': []
        }
        
        # Stage 1: Scan WordPress-specific backup patterns
        wp_backups = self._scan_patterns(self.wp_backup_patterns)
        
        # Stage 2: Scan plugin-specific backup directories
        plugin_backups = self._scan_plugin_backups()
        
        # Stage 3: Scan for Duplicator installers
        duplicator_files = self._scan_patterns(self.duplicator_paths)
        
        # Stage 4: Scan numbered/dated backup patterns
        dated_backups = self._scan_dated_backups()
        
        # Combine all findings
        all_exposed = wp_backups + plugin_backups + duplicator_files + dated_backups
        
        # Remove duplicates based on URL
        seen_urls = set()
        unique_findings = []
        for finding in all_exposed:
            if finding['url'] not in seen_urls:
                seen_urls.add(finding['url'])
                unique_findings.append(finding)
        
        result['total_files_scanned'] = len(self.wp_backup_patterns) + len(dated_backups)
        result['exposed_files'] = unique_findings
        
        # Categorize findings
        for exposed in unique_findings:
            file_type = exposed.get('file_type', 'unknown')
            category = exposed.get('category', 'other')
            
            if category == 'database':
                result['exposed_database_dumps'].append(exposed)
            elif category == 'config':
                result['exposed_config_files'].append(exposed)
            elif category == 'archive':
                result['exposed_archives'].append(exposed)
            elif category == 'log':
                result['exposed_logs'].append(exposed)
            elif category == 'env':
                result['exposed_env_files'].append(exposed)
            elif category == 'vcs':
                result['exposed_vcs'].append(exposed)
        
        # ===================================================================
        # Generate security findings
        # ===================================================================
        
        # Critical: Database dumps exposed
        if result['exposed_database_dumps']:
            result['critical_findings_count'] += len(result['exposed_database_dumps'])
            
            for db_dump in result['exposed_database_dumps']:
                self.findings.append({
                    'title': f"Database dump publicly accessible: {db_dump['path']}",
                    'severity': 'critical',
                    'description': (
                        f"A database dump file was found at {db_dump['path']}. "
                        f"File size: {db_dump.get('size', 'unknown')} bytes. "
                        "Database dumps contain all website data including user credentials, "
                        "email addresses, private content, and potentially password hashes "
                        "that can be cracked offline."
                    ),
                    'recommendation': (
                        "1. DELETE the exposed database dump file immediately\n"
                        "2. Move all backups outside the web root directory\n"
                        "3. Store backups in a secure, encrypted location\n"
                        "4. Change all database passwords immediately\n"
                        "5. Force password reset for all users\n"
                        "6. Review database for any unauthorized changes\n"
                        "7. Check access logs for unauthorized downloads\n"
                        "8. Implement proper backup retention policy\n"
                        "9. Never store .sql files in web-accessible directories"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-538',
                    'cvss_score': 9.8,
                    'evidence': (
                        f"Path: {db_dump['path']}\n"
                        f"Size: {db_dump.get('size', 'unknown')} bytes\n"
                        f"Status: {db_dump['status']}"
                    ),
                    'references': [
                        'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Test_Backup_and_Unreferenced_Files_for_Sensitive_Information',
                    ]
                })
        
        # Critical: wp-config.php exposed
        for config_file in result['exposed_config_files']:
            if 'wp-config' in config_file.get('path', '') or 'DB_PASSWORD' in config_file.get('content_preview', ''):
                result['critical_findings_count'] += 1
                
                self.findings.append({
                    'title': f"WordPress configuration file exposed: {config_file['path']}",
                    'severity': 'critical',
                    'description': (
                        f"The WordPress configuration file {config_file['path']} is "
                        "publicly accessible. This file contains database credentials, "
                        "authentication salts, and API keys. With these credentials, "
                        "an attacker can access the database directly and completely "
                        "compromise the website."
                    ),
                    'recommendation': (
                        "1. DELETE the exposed configuration file immediately\n"
                        "2. Change all database credentials immediately\n"
                        "3. Generate new authentication salts from:\n"
                        "   https://api.wordpress.org/secret-key/1.1/salt/\n"
                        "4. Update wp-config.php with new credentials\n"
                        "5. Move wp-config.php to the directory above web root\n"
                        "6. Set file permissions to 400 or 440\n"
                        "7. Add to .htaccess:\n"
                        "   <Files wp-config.php>\n"
                        "       Order deny,allow\n"
                        "       Deny from all\n"
                        "   </Files>"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-538',
                    'cvss_score': 10.0,
                    'evidence': (
                        f"Path: {config_file['path']}\n"
                        f"Content preview: {config_file.get('content_preview', 'N/A')[:100]}"
                    ),
                })
        
        # High: Archive files exposed
        for archive in result['exposed_archives']:
            result['high_findings_count'] += 1
            
            self.findings.append({
                'title': f"Backup archive publicly accessible: {archive['path']}",
                'severity': 'high',
                'description': (
                    f"A backup archive was found at {archive['path']}. "
                    f"Size: {archive.get('size', 'unknown')} bytes. "
                    "This may contain the entire website including configuration files, "
                    "database dumps, and source code."
                ),
                'recommendation': (
                    "1. Remove the backup file from web root\n"
                    "2. Store backups outside public_html/www directory\n"
                    "3. Use encrypted backup storage\n"
                    "4. Set up automated backup cleanup\n"
                    "5. Password-protect backup files if they must be web-accessible"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 8.0,
                'evidence': f"Path: {archive['path']}\nSize: {archive.get('size', 'unknown')} bytes",
            })
        
        # Medium: Log files exposed
        for log_file in result['exposed_logs']:
            result['medium_findings_count'] += 1
            
            self.findings.append({
                'title': f"Debug/error log publicly accessible: {log_file['path']}",
                'severity': 'medium',
                'description': (
                    f"A log file was found at {log_file['path']}. "
                    "Log files may contain error messages, file paths, database errors, "
                    "plugin information, and potentially sensitive debugging data."
                ),
                'recommendation': (
                    "1. Disable WordPress debug mode in production\n"
                    "2. Set WP_DEBUG to false in wp-config.php\n"
                    "3. Remove debug.log from web root\n"
                    "4. Configure logging to write outside web root\n"
                    "5. Add debug.log to .gitignore"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-532',
                'cvss_score': 5.0,
                'evidence': f"Path: {log_file['path']}\nSize: {log_file.get('size', 'unknown')} bytes",
            })
        
        # Medium: VCS files exposed
        for vcs_file in result['exposed_vcs']:
            result['medium_findings_count'] += 1
            
            self.findings.append({
                'title': f"Version control files exposed: {vcs_file['path']}",
                'severity': 'medium',
                'description': (
                    f"Version control directory found at {vcs_file['path']}. "
                    "Git/SVN repositories may contain source code history, "
                    "configuration files, and sensitive data that was previously committed."
                ),
                'recommendation': (
                    "1. Add to .htaccess:\n"
                    "   RedirectMatch 404 /\\.git\n"
                    "   RedirectMatch 404 /\\.svn\n"
                    "2. Ensure .git directory is not deployed to production\n"
                    "3. Use .gitignore to exclude sensitive files\n"
                    "4. Scan git history for accidentally committed secrets"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-527',
                'cvss_score': 6.5,
                'evidence': f"Path: {vcs_file['path']}\nStatus: {vcs_file['status']}",
            })
        
        # Medium: Environment files exposed
        for env_file in result['exposed_env_files']:
            result['high_findings_count'] += 1
            
            self.findings.append({
                'title': f"Environment configuration file exposed: {env_file['path']}",
                'severity': 'high',
                'description': (
                    f"An environment configuration file was found at {env_file['path']}. "
                    "These files often contain API keys, database credentials, "
                    "mail server passwords, and other sensitive configuration."
                ),
                'recommendation': (
                    "1. Remove .env file from web root immediately\n"
                    "2. Add .env to .gitignore\n"
                    "3. Rotate any exposed API keys and credentials\n"
                    "4. Use environment variables via server configuration\n"
                    "5. Add to .htaccess: <Files .env> Deny from all </Files>"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-538',
                'cvss_score': 8.5,
                'evidence': (
                    f"Path: {env_file['path']}\n"
                    f"Content preview: {env_file.get('content_preview', 'N/A')[:100]}"
                ),
            })
        
        # Low: Duplicator installer files
        for dup_file in duplicator_files:
            result['low_findings_count'] += 1
            
            self.findings.append({
                'title': f"Duplicator installer file exposed: {dup_file['path']}",
                'severity': 'low',
                'description': (
                    "A Duplicator installer file is still present. "
                    "This could allow an attacker to overwrite the WordPress installation."
                ),
                'recommendation': (
                    "1. Delete all installer files after migration:\n"
                    "   - installer.php\n"
                    "   - installer-backup.php\n"
                    "   - dup-installer/ directory\n"
                    "2. Set up automatic cleanup after Duplicator operations"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-749',
                'cvss_score': 3.0,
                'evidence': f"Path: {dup_file['path']}",
            })
        
        result['findings'] = self.findings
        
        # Summary statistics
        result['critical_findings_count'] = len(
            [f for f in self.findings if f['severity'] == 'critical']
        )
        result['high_findings_count'] = len(
            [f for f in self.findings if f['severity'] == 'high']
        )
        result['medium_findings_count'] = len(
            [f for f in self.findings if f['severity'] == 'medium']
        )
        result['low_findings_count'] = len(
            [f for f in self.findings if f['severity'] == 'low']
        )
        
        logger.info(
            f"{self.module_name} complete. "
            f"Scanned: {result['total_files_scanned']} files, "
            f"Exposed: {len(result['exposed_files'])} files, "
            f"Critical: {result['critical_findings_count']}"
        )
        return result
    
    def _scan_patterns(self, patterns: List[str]) -> List[Dict]:
        """
        Scan a list of file patterns for exposure.
        
        Args:
            patterns: List of file paths to check
        
        Returns:
            List of exposed file information
        """
        exposed = []
        
        for path in patterns:
            # Skip wildcard patterns for direct scanning
            if '*' in path:
                continue
            
            # Try HEAD request first (faster)
            head_resp = self.browser.head(path)
            
            if head_resp and head_resp.status_code == 200:
                content_length = int(head_resp.headers.get('Content-Length', 0))
                
                # If file is accessible, do GET to analyze content
                get_resp = self.browser.get(path)
                
                if get_resp and get_resp.status_code == 200:
                    file_info = self._analyze_exposed_file(
                        path=path,
                        response=get_resp,
                        content_length=content_length or len(get_resp.text)
                    )
                    exposed.append(file_info)
            
            # Also check for 403 (forbidden but confirms existence)
            elif head_resp and head_resp.status_code == 403:
                exposed.append({
                    'url': urljoin(self.target_url, path),
                    'path': path,
                    'status': 403,
                    'size': 0,
                    'content_preview': '',
                    'file_type': 'unknown',
                    'category': 'other',
                    'accessible': False,
                })
        
        return exposed
    
    def _scan_plugin_backups(self) -> List[Dict]:
        """
        Scan plugin-specific backup directories.
        
        Returns:
            List of exposed backup files
        """
        exposed = []
        
        # Check All-in-One WP Migration backups
        for path in self.ai1wm_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                # Parse directory listing or JSON response
                if 'Index of' in resp.text or 'backup-' in resp.text:
                    # Try to extract file links
                    file_pattern = r'href="([^"]+\.(?:wpress|zip))"'
                    matches = re.findall(file_pattern, resp.text)
                    
                    for match in matches:
                        file_url = urljoin(urljoin(self.target_url, path), match)
                        exposed.append({
                            'url': file_url,
                            'path': file_url.replace(self.target_url, ''),
                            'status': 200,
                            'size': 0,
                            'content_preview': 'AI1WM backup file detected',
                            'file_type': 'backup',
                            'category': 'archive',
                            'accessible': True,
                        })
        
        # Check BackupBuddy backups
        for path in self.backupbuddy_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                file_pattern = r'href="([^"]+\.(?:zip|gz|tar))"'
                matches = re.findall(file_pattern, resp.text)
                
                for match in matches:
                    file_url = urljoin(urljoin(self.target_url, path), match)
                    exposed.append({
                        'url': file_url,
                        'path': file_url.replace(self.target_url, ''),
                        'status': 200,
                        'size': 0,
                        'content_preview': 'BackupBuddy backup file detected',
                        'file_type': 'backup',
                        'category': 'archive',
                        'accessible': True,
                    })
        
        return exposed
    
    def _scan_dated_backups(self) -> List[Dict]:
        """
        Scan for backups with date-based naming patterns.
        
        Returns:
            List of exposed dated backup files
        """
        exposed = []
        
        # Common date patterns in backup names
        date_patterns = [
            # YYYY-MM-DD format
            '/backup-{date}.sql',
            '/backup_{date}.sql',
            '/db_backup_{date}.sql',
            '/wordpress_{date}.sql',
            '/site_{date}.sql',
            '/backup-{date}.zip',
            '/backup_{date}.zip',
            '/site_{date}.zip',
            '/{date}_backup.zip',
            '/{date}_backup.sql',
            '/{date}_wordpress.zip',
        ]
        
        # Generate recent dates to check
        from datetime import datetime, timedelta
        
        dates_to_check = []
        today = datetime.now()
        
        # Check last 7 days
        for i in range(7):
            date = today - timedelta(days=i)
            dates_to_check.append(date.strftime('%Y-%m-%d'))
            dates_to_check.append(date.strftime('%Y%m%d'))
            dates_to_check.append(date.strftime('%d-%m-%Y'))
        
        # Check first day of recent months
        for i in range(6):
            date = today.replace(day=1) - timedelta(days=i*30)
            dates_to_check.append(date.strftime('%Y-%m'))
            dates_to_check.append(date.strftime('%Y%m'))
        
        for pattern in date_patterns:
            for date_str in dates_to_check:
                path = pattern.format(date=date_str)
                resp = self.browser.head(path)
                
                if resp and resp.status_code == 200:
                    exposed.append({
                        'url': urljoin(self.target_url, path),
                        'path': path,
                        'status': 200,
                        'size': int(resp.headers.get('Content-Length', 0)),
                        'content_preview': 'Dated backup file detected',
                        'file_type': self._determine_file_type(path),
                        'category': self._categorize_file(path),
                        'accessible': True,
                    })
        
        return exposed
    
    def _analyze_exposed_file(
        self,
        path: str,
        response,
        content_length: int
    ) -> Dict:
        """
        Analyze an exposed file to determine its type and content.
        
        Args:
            path: File path
            response: HTTP response object
            content_length: Content length in bytes
        
        Returns:
            Dict with file analysis
        """
        content_preview = ''
        if hasattr(response, 'text'):
            content_preview = response.text[:500]
        
        file_info = {
            'url': urljoin(self.target_url, path),
            'path': path,
            'status': response.status_code,
            'size': content_length,
            'content_preview': content_preview,
            'file_type': self._determine_file_type(path),
            'category': self._categorize_file(path),
            'accessible': True,
        }
        
        # Refine category based on content analysis
        if content_preview:
            for category, indicators in self.content_indicators.items():
                for indicator in indicators:
                    if indicator in content_preview:
                        if category == 'database':
                            file_info['category'] = 'database'
                        elif category == 'wp_config':
                            file_info['category'] = 'config'
                            file_info['file_type'] = 'config'
                        elif category == 'env_file':
                            file_info['category'] = 'env'
                        elif category == 'archive':
                            file_info['category'] = 'archive'
                        break
                if file_info['category'] != 'other':
                    break
        
        # Check for binary content indicators
        if content_preview and len(content_preview) > 0:
            if ord(content_preview[0]) < 32 and content_preview[0] not in '\n\r\t':
                file_info['category'] = 'archive'
                file_info['file_type'] = 'binary'
        
        return file_info
    
    def _determine_file_type(self, path: str) -> str:
        """
        Determine file type from extension.
        
        Args:
            path: File path
        
        Returns:
            File type string
        """
        path_lower = path.lower()
        
        if any(path_lower.endswith(ext) for ext in ['.sql', '.sql.gz', '.dump']):
            return 'database'
        elif any(path_lower.endswith(ext) for ext in ['.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.7z', '.rar']):
            return 'archive'
        elif path_lower.endswith('.php') or 'config' in path_lower:
            return 'config'
        elif path_lower.endswith('.log') or 'debug' in path_lower or 'error' in path_lower:
            return 'log'
        elif path_lower.endswith('.env') or '.env.' in path_lower:
            return 'env'
        elif '.git' in path_lower or '.svn' in path_lower:
            return 'vcs'
        elif path_lower.endswith('.htaccess') or path_lower.endswith('.htpasswd'):
            return 'config'
        else:
            return 'unknown'
    
    def _categorize_file(self, path: str) -> str:
        """
        Categorize file for severity classification.
        
        Args:
            path: File path
        
        Returns:
            Category string
        """
        file_type = self._determine_file_type(path)
        
        if file_type == 'database':
            return 'database'
        elif file_type == 'config':
            if 'wp-config' in path.lower():
                return 'config'
            elif 'env' in path.lower():
                return 'env'
            return 'config'
        elif file_type == 'archive':
            return 'archive'
        elif file_type == 'log':
            return 'log'
        elif file_type == 'vcs':
            return 'vcs'
        elif file_type == 'env':
            return 'env'
        else:
            # Check for backup indicators
            backup_indicators = ['backup', 'back', 'bak', 'old', 'dump', 'export']
            if any(indicator in path.lower() for indicator in backup_indicators):
                return 'archive'
            
            return 'other'
    
    def _calculate_hash(self, content: str) -> str:
        """Calculate SHA-256 hash of content."""
        if not content:
            return ''
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]