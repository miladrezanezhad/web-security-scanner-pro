#!/usr/bin/env python3
"""
WordPress User Enumeration Module.
Enumerates WordPress users through multiple methods.

References:
    - WPScan User Enumeration: https://github.com/wpscanteam/wpscan
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
"""

import re
import json
from typing import Dict, List, Optional
from loguru import logger


class Scanner:
    """WordPress user enumeration scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "WordPress User Enumeration"
        
        # Common WordPress usernames
        self.common_usernames = [
            'admin', 'administrator', 'root', 'test',
            'user', 'wp', 'wordpress', 'demo', 'guest',
            'manager', 'editor', 'support', 'info',
        ]
    
    def run(self) -> Dict:
        """Execute user enumeration."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'users_found': [],
            'total_users': 0,
            'enumeration_methods': [],
            'admin_user_detected': False,
            'findings': []
        }
        
        all_users = {}
        
        # Method 1: REST API user enumeration
        api_users = self._enumerate_via_rest_api()
        for user in api_users:
            if user['username'] not in all_users:
                all_users[user['username']] = user
        if api_users:
            result['enumeration_methods'].append('rest_api')
        
        # Method 2: Author archive enumeration
        archive_users = self._enumerate_via_author_archives()
        for user in archive_users:
            if user['username'] not in all_users:
                all_users[user['username']] = user
        if archive_users:
            result['enumeration_methods'].append('author_archives')
        
        # Method 3: Login error messages
        login_users = self._enumerate_via_login_errors()
        for user in login_users:
            if user['username'] not in all_users:
                all_users[user['username']] = user
        if login_users:
            result['enumeration_methods'].append('login_errors')
        
        result['users_found'] = list(all_users.values())
        result['total_users'] = len(result['users_found'])
        result['admin_user_detected'] = any(
            u.get('roles') and 'administrator' in u.get('roles', [])
            for u in result['users_found']
        )
        
        # Generate findings
        if result['users_found']:
            usernames = [u['username'] for u in result['users_found'][:10]]
            
            self.findings.append({
                'title': f"WordPress user enumeration successful: {len(usernames)} users found",
                'severity': 'medium',
                'description': (
                    f"Enumerated users: {', '.join(usernames)}. "
                    f"Methods: {', '.join(result['enumeration_methods'])}. "
                    "User enumeration aids brute-force attacks."
                ),
                'recommendation': (
                    "1. Disable REST API user endpoint\n"
                    "2. Block author archives\n"
                    "3. Use generic login error messages\n"
                    "4. Implement rate limiting on login\n"
                    "5. Consider using a security plugin"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-200',
                'cvss_score': 5.0,
                'evidence': f"Users: {usernames}",
            })
        
        result['findings'] = self.findings
        return result
    
    def _enumerate_via_rest_api(self) -> List[Dict]:
        """Enumerate users via WordPress REST API."""
        users = []
        
        resp = self.browser.get('/wp-json/wp/v2/users')
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if isinstance(data, list):
                    for user in data:
                        if isinstance(user, dict):
                            users.append({
                                'username': user.get('slug', user.get('name', '')),
                                'name': user.get('name', ''),
                                'id': user.get('id'),
                                'roles': user.get('roles', []),
                                'method': 'rest_api',
                            })
            except json.JSONDecodeError:
                pass
        
        return users
    
    def _enumerate_via_author_archives(self) -> List[Dict]:
        """Enumerate users via author archive pages."""
        users = []
        
        for author_id in range(1, 20):
            resp = self.browser.get(f'/?author={author_id}')
            if resp and resp.status_code in [200, 301]:
                # Extract username from redirect URL or page content
                if 'Location' in resp.headers:
                    location = resp.headers['Location']
                    username_match = re.search(r'/author/([^/]+)/', location)
                    if username_match:
                        users.append({
                            'username': username_match.group(1),
                            'id': author_id,
                            'method': 'author_archive',
                        })
                else:
                    # Check page content for author info
                    username_match = re.search(r'author-(\w+)', resp.text)
                    if username_match:
                        users.append({
                            'username': username_match.group(1),
                            'id': author_id,
                            'method': 'author_archive',
                        })
        
        return users
    
    def _enumerate_via_login_errors(self) -> List[Dict]:
        """Enumerate users via login error messages."""
        users = []
        
        for username in self.common_usernames:
            resp = self.browser.post('/wp-login.php', data={
                'log': username,
                'pwd': 'invalid_password_test',
                'wp-submit': 'Log In',
            })
            
            if resp and resp.status_code == 200:
                # Check error message
                if 'The password you entered for' in resp.text:
                    # Username exists
                    users.append({
                        'username': username,
                        'method': 'login_error',
                    })
                elif 'Unknown username' in resp.text:
                    # Username doesn't exist
                    pass
        
        return users