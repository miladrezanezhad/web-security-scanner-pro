#!/usr/bin/env python3
"""
Sensitive Information & Source Code Disclosure Scanner.
Detects exposed environment files, version control metadata (.git, .svn),
database backups, CI/CD configs, cloud credentials, and exposed admin/debug endpoints.

References:
    - OWASP A01:2021 - Broken Access Control
    - OWASP A05:2021 - Security Misconfiguration
    - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    - CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """Scanner for discovering exposed sensitive files and secrets."""

    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize sensitive files scanner.

        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Sensitive Files & Secrets Disclosure"

        # Categorized sensitive paths with validation signatures
        self.sensitive_targets = [
            # Environment & Configurations
            {
                'path': '/.env',
                'name': '.env configuration file',
                'category': 'config',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-538',
                'patterns': [r'(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|DATABASE_URL|AWS_SECRET|JWT_SECRET|REDIS_PASSWORD)'],
            },
            {
                'path': '/.env.local',
                'name': '.env.local configuration file',
                'category': 'config',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-538',
                'patterns': [r'(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|DATABASE_URL)'],
            },
            {
                'path': '/.env.production',
                'name': '.env.production file',
                'category': 'config',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-538',
                'patterns': [r'(?i)(DB_PASSWORD|APP_KEY|SECRET_KEY|DATABASE_URL)'],
            },
            {
                'path': '/config.json',
                'name': 'config.json file',
                'category': 'config',
                'severity': 'high',
                'cvss': 7.5,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)("password"|"secret"|"apiKey"|"connectionString")'],
            },

            # Version Control System (VCS)
            {
                'path': '/.git/HEAD',
                'name': 'Exposed Git repository (.git/HEAD)',
                'category': 'vcs',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-538',
                'patterns': [r'ref: refs/heads/'],
            },
            {
                'path': '/.git/config',
                'name': 'Exposed Git config (.git/config)',
                'category': 'vcs',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-538',
                'patterns': [r'\[core\]', r'repositoryformatversion'],
            },
            {
                'path': '/.svn/entries',
                'name': 'Exposed SVN repository (.svn/entries)',
                'category': 'vcs',
                'severity': 'high',
                'cvss': 8.5,
                'cwe': 'CWE-538',
                'patterns': [r'(?i)(dir|svn)'],
            },

            # Database & Backups
            {
                'path': '/dump.sql',
                'name': 'Database SQL dump (dump.sql)',
                'category': 'backup',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)(CREATE TABLE|INSERT INTO|MySQL dump|PostgreSQL database dump)'],
            },
            {
                'path': '/backup.sql',
                'name': 'Database backup file (backup.sql)',
                'category': 'backup',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)(CREATE TABLE|INSERT INTO|MySQL dump)'],
            },
            {
                'path': '/database.sqlite',
                'name': 'SQLite database file',
                'category': 'backup',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-200',
                'patterns': [r'SQLite format 3'],
            },

            # Framework Debug & Monitoring
            {
                'path': '/actuator/env',
                'name': 'Spring Boot Actuator environment endpoint',
                'category': 'monitoring',
                'severity': 'critical',
                'cvss': 9.8,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)(activeProfiles|propertySources|systemProperties)'],
            },
            {
                'path': '/actuator/health',
                'name': 'Spring Boot Actuator health endpoint',
                'category': 'monitoring',
                'severity': 'low',
                'cvss': 3.5,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)"status"\s*:\s*"(UP|DOWN)"'],
            },
            {
                'path': '/swagger.json',
                'name': 'Swagger/OpenAPI API documentation',
                'category': 'api_docs',
                'severity': 'low',
                'cvss': 3.5,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)("swagger"|"openapi"|"paths")'],
            },
            {
                'path': '/openapi.json',
                'name': 'OpenAPI JSON documentation',
                'category': 'api_docs',
                'severity': 'low',
                'cvss': 3.5,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)("openapi"|"paths"|"components")'],
            },

            # Server & Container Configuration
            {
                'path': '/docker-compose.yml',
                'name': 'Docker Compose configuration file',
                'category': 'container',
                'severity': 'high',
                'cvss': 8.0,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)(version:\s*[\'"]?\d|services:)'],
            },
            {
                'path': '/Dockerfile',
                'name': 'Dockerfile exposed',
                'category': 'container',
                'severity': 'medium',
                'cvss': 5.5,
                'cwe': 'CWE-200',
                'patterns': [r'(?i)^FROM\s+[a-zA-Z0-9_\-\./:]+'],
            },
        ]

        # Regex patterns for detecting leaked secrets in page bodies
        self.secret_patterns = [
            (r'(?i)AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'high', 8.0),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', 'critical', 9.5),
            (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack API Token', 'high', 8.5),
            (r'(?i)AIza[0-9A-Za-z-_]{35}', 'Google API Key', 'medium', 6.5),
            (r'bearer\s+[a-zA-Z0-9_\-\.]{50,}', 'Exposed Bearer Token', 'high', 7.5),
        ]

    def run(self) -> Dict:
        """
        Execute sensitive files and secrets scan.

        Returns:
            Dict containing discovered files, secrets, and structured findings.
        """
        logger.info(f"Starting {self.module_name} scan for {self.target_url}")

        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'files_tested': len(self.sensitive_targets),
            'exposed_files': [],
            'leaked_secrets': [],
            'findings': []
        }

        # 1. Test for exposed sensitive files
        for target in self.sensitive_targets:
            finding = self._check_path(target)
            if finding:
                result['exposed_files'].append(target['path'])
                result['findings'].append(finding)

        # 2. Inspect root page and scripts for exposed API secrets
        secrets_found = self._check_secret_leaks()
        if secrets_found:
            for sec in secrets_found:
                result['leaked_secrets'].append(sec['type'])
                result['findings'].append(sec['finding'])

        self.findings = result['findings']
        logger.info(
            f"{self.module_name} finished. "
            f"Exposed files: {len(result['exposed_files'])}, "
            f"Secrets: {len(result['leaked_secrets'])}"
        )
        return result

    def _check_path(self, target: Dict) -> Optional[Dict]:
        """Request path and validate whether contents match the sensitive signature."""
        resp = self.browser.get(target['path'])
        if not resp or resp.status_code != 200:
            return None

        # Ignore generic 200 soft-404 error pages
        content = resp.text
        if len(content.strip()) == 0:
            return None

        content_lower = content.lower()
        if '<!doctype html>' in content_lower and target['category'] in ['config', 'vcs', 'backup']:
            # Typical custom 404 HTML page returned with HTTP 200 status
            return None

        # Check content against expected patterns
        matched = False
        evidence_snippet = ""
        for pattern in target['patterns']:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                matched = True
                start = max(0, match.start() - 20)
                end = min(len(content), match.end() + 40)
                evidence_snippet = content[start:end].replace('\n', ' ')
                break

        if not matched:
            return None

        full_url = urljoin(self.target_url, target['path'])
        return {
            'title': f"{target['name']} is publicly accessible",
            'severity': target['severity'],
            'description': (
                f"The sensitive resource at '{target['path']}' was found publicly accessible without authentication. "
                "This may expose source code, database credentials, server configuration, or proprietary business logic."
            ),
            'recommendation': (
                f"1. Immediately deny public access to '{target['path']}' via web server configuration.\n"
                "2. Remove sensitive backup or VCS files from the web root.\n"
                "3. In Apache: add RewriteRule or FilesMatch directives to block access.\n"
                "4. In Nginx: add 'location ~ /\\.(?!well-known).* { deny all; }'\n"
                "5. Rotate any credentials or tokens exposed in this file."
            ),
            'module': self.module_name,
            'cwe_id': target['cwe'],
            'cvss_score': target['cvss'],
            'evidence': f"URL: {full_url}\nMatch Snippet: {evidence_snippet[:120]}...",
        }

    def _check_secret_leaks(self) -> List[Dict]:
        """Check homepage and embedded scripts for exposed API keys and secrets."""
        leaks = []
        resp = self.browser.get('/')
        if not resp or resp.status_code != 200:
            return leaks

        content = resp.text
        for pattern, secret_type, severity, cvss in self.secret_patterns:
            matches = re.findall(pattern, content)
            if matches:
                sample = str(matches[0])
                masked = sample[:4] + '*' * (len(sample) - 8) + sample[-4:] if len(sample) > 8 else '***'
                leaks.append({
                    'type': secret_type,
                    'finding': {
                        'title': f"Exposed {secret_type} in web response",
                        'severity': severity,
                        'description': (
                            f"A potential hardcoded secret ({secret_type}) was discovered in the HTTP response. "
                            "Exposing authentication credentials in client-accessible resources violates confidentiality."
                        ),
                        'recommendation': (
                            "1. Revoke and rotate the exposed secret immediately.\n"
                            "2. Move all API secrets to server-side environment variables.\n"
                            "3. Ensure client-side scripts do not include private credentials."
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-798',
                        'cvss_score': cvss,
                        'evidence': f"Type: {secret_type}, Masked Token: {masked}",
                    }
                })

        return leaks
