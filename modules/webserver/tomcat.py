#!/usr/bin/env python3
"""
Apache Tomcat Security Scanner Module.
Tests for common Tomcat security misconfigurations and vulnerabilities.

References:
    - Tomcat Security: https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
"""

import re
from typing import Dict, List, Optional
from loguru import logger


class Scanner:
    """Apache Tomcat security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Tomcat Security Analysis"
        
        self.tomcat_paths = {
            'manager': '/manager/html',
            'manager_status': '/manager/status',
            'host_manager': '/host-manager/html',
            'examples': '/examples/',
            'docs': '/docs/',
            'server_info': '/server-info',
        }
        
        self.default_credentials = [
            ('admin', 'admin'),
            ('tomcat', 'tomcat'),
            ('admin', 'password'),
            ('manager', 'manager'),
            ('tomcat', 's3cret'),
        ]
    
    def run(self) -> Dict:
        """Execute Tomcat security tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'tomcat_detected': False,
            'version': None,
            'manager_exposed': False,
            'examples_exposed': False,
            'default_credentials': False,
            'findings': []
        }
        
        # Detect Tomcat
        detection = self._detect_tomcat()
        result['tomcat_detected'] = detection['detected']
        result['version'] = detection.get('version')
        
        if not result['tomcat_detected']:
            result['findings'].append({
                'title': 'No Apache Tomcat detected',
                'severity': 'info',
                'description': 'No evidence of Tomcat was found.',
                'module': self.module_name,
            })
            return result
        
        # Check Manager application
        if self._check_manager():
            result['manager_exposed'] = True
            self.findings.append({
                'title': 'Tomcat Manager application is exposed',
                'severity': 'critical',
                'description': (
                    "The Tomcat Manager application is accessible. This allows "
                    "deployment of WAR files and application management."
                ),
                'recommendation': (
                    "1. Restrict manager access by IP in context.xml\n"
                    "2. Use strong passwords\n"
                    "3. Consider disabling manager in production"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 9.0,
            })
        
        # Check default credentials
        if self._check_default_credentials():
            result['default_credentials'] = True
            self.findings.append({
                'title': 'Tomcat may be using default credentials',
                'severity': 'critical',
                'description': 'Default credentials may be in use for Tomcat Manager.',
                'recommendation': (
                    "Change default passwords in tomcat-users.xml immediately."
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-1392',
                'cvss_score': 10.0,
            })
        
        # Check examples
        if self._check_examples():
            result['examples_exposed'] = True
            self.findings.append({
                'title': 'Tomcat examples application is deployed',
                'severity': 'medium',
                'description': (
                    "The examples application contains sample code that may reveal "
                    "server information or have known vulnerabilities."
                ),
                'recommendation': 'Remove the examples webapp from production deployments.',
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
            })
        
        result['findings'] = self.findings
        return result
    
    def _detect_tomcat(self) -> Dict:
        """Detect Apache Tomcat."""
        result = {'detected': False, 'version': None}
        
        resp = self.browser.get('/')
        if not resp:
            return result
        
        # Check Server header
        server = resp.headers.get('Server', '')
        if 'Apache-Coyote' in server or 'Tomcat' in server:
            result['detected'] = True
        
        # Check for Tomcat default page
        tomcat_indicators = [
            'Apache Tomcat',
            'tomcat',
            'Catalina',
            'Jasper',
        ]
        
        for indicator in tomcat_indicators:
            if indicator in resp.text:
                result['detected'] = True
                # Try to extract version
                version_match = re.search(r'Tomcat\s+([\d.]+)', resp.text)
                if version_match:
                    result['version'] = version_match.group(1)
                break
        
        # Check for Tomcat paths
        for name, path in self.tomcat_paths.items():
            check = self.browser.head(path)
            if check and check.status_code in [200, 401, 403]:
                result['detected'] = True
                break
        
        return result
    
    def _check_manager(self) -> bool:
        """Check if Manager app is accessible."""
        resp = self.browser.get('/manager/html')
        if resp and resp.status_code in [200, 401]:
            return True
        return False
    
    def _check_default_credentials(self) -> bool:
        """Check if default credentials work."""
        import base64
        
        for username, password in self.default_credentials:
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers = {'Authorization': f'Basic {auth}'}
            
            resp = self.browser.get('/manager/html', custom_headers=headers)
            if resp and resp.status_code == 200:
                return True
        
        return False
    
    def _check_examples(self) -> bool:
        """Check if examples are deployed."""
        resp = self.browser.get('/examples/')
        return resp is not None and resp.status_code == 200