#!/usr/bin/env python3
"""
Elasticsearch Security Scanner Module.
Tests for common Elasticsearch security misconfigurations and exposures.

References:
    - Elasticsearch Security: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-basic-setup.html
    - OWASP: https://owasp.org/www-project-web-security-testing-guide/
    - CWE-306: Missing Authentication for Critical Function
    - CWE-200: Exposure of Sensitive Information
"""

import re
import json
import socket
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from loguru import logger


class Scanner:
    """Elasticsearch security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize Elasticsearch scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Elasticsearch Security Analysis"
        
        # Parse hostname from URL
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # Default Elasticsearch ports
        self.es_ports = [9200, 9201, 9202, 9300, 9301]
        
        # Common Elasticsearch paths
        self.es_paths = [
            '/',
            '/_cat/',
            '/_cat/nodes',
            '/_cat/indices',
            '/_cat/health',
            '/_cluster/health',
            '/_cluster/state',
            '/_cluster/settings',
            '/_nodes',
            '/_nodes/stats',
            '/_nodes/process',
            '/_search',
            '/_all/_search',
            '/_count',
            '/_stats',
            '/_mapping',
            '/_settings',
            '/_aliases',
            '/_snapshot',
            '/_license',
            '/_xpack',
            '/_security/',
            '/_security/user',
            '/_security/role',
            '/.kibana/',
            '/.security/',
        ]
        
        # Elasticsearch version patterns
        self.version_patterns = [
            r'"number"\s*:\s*"([\d.]+)"',
            r'"version"\s*:\s*"([\d.]+)"',
            r'"lucene_version"\s*:\s*"([\d.]+)"',
            r'version:\s*([\d.]+)',
            r'build_hash:\s*"([^"]+)"',
        ]
        
        # Sensitive indices that should not be exposed
        self.sensitive_indices = [
            '.security',
            '.security-7',
            '.kibana',
            '.kibana_1',
            '.kibana_task_manager',
            '.reporting',
            '.monitoring',
            '.watches',
            '.triggered_watches',
            '.watcher-history',
            '.logstash',
            '.apm',
            '.fleet',
        ]
        
        # Authentication indicators
        self.auth_indicators = [
            'security_exception',
            'authentication required',
            'missing authentication token',
            'unable to authenticate',
            'no auth header',
            'unauthorized',
            'forbidden',
        ]
    
    def run(self) -> Dict:
        """
        Execute Elasticsearch security tests.
        
        Returns:
            Dict with findings and analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'elasticsearch_detected': False,
            'version': None,
            'cluster_name': None,
            'authentication_enabled': False,
            'xpack_enabled': False,
            'indices_exposed': [],
            'sensitive_indices_exposed': [],
            'unauthorized_access': False,
            'node_info': {},
            'findings': []
        }
        
        # Stage 1: Check Elasticsearch on standard web port
        web_info = self._check_es_endpoint('/')
        if web_info.get('detected'):
            result['elasticsearch_detected'] = True
            result['version'] = web_info.get('version')
            result['cluster_name'] = web_info.get('cluster_name')
            result['node_info'] = web_info
        
        # Stage 2: Check Elasticsearch on default port 9200
        es_info = self._check_es_port()
        if es_info.get('detected'):
            result['elasticsearch_detected'] = True
            if not result['version']:
                result['version'] = es_info.get('version')
            if not result['cluster_name']:
                result['cluster_name'] = es_info.get('cluster_name')
            result['node_info'].update(es_info)
        
        # Stage 3: Enumerate indices
        indices = self._enumerate_indices()
        if indices:
            result['indices_exposed'] = indices
            result['elasticsearch_detected'] = True
            
            # Check for sensitive indices
            for index in indices:
                if index.get('index') in self.sensitive_indices:
                    result['sensitive_indices_exposed'].append(index)
        
        # Stage 4: Check authentication
        auth_info = self._check_authentication()
        result['authentication_enabled'] = auth_info.get('enabled', False)
        result['xpack_enabled'] = auth_info.get('xpack', False)
        result['unauthorized_access'] = not auth_info.get('enabled', False) and result['elasticsearch_detected']
        
        # Stage 5: Check cluster settings exposure
        settings_info = self._check_cluster_settings()
        
        # ===================================================================
        # Generate security findings
        # ===================================================================
        
        # Finding: Elasticsearch detected
        if result['elasticsearch_detected']:
            # Finding: No authentication
            if result['unauthorized_access']:
                self.findings.append({
                    'title': 'Elasticsearch accessible without authentication',
                    'severity': 'critical',
                    'description': (
                        "Elasticsearch is accessible without any authentication. "
                        "This allows anyone to read, modify, and delete all data stored "
                        "in the Elasticsearch cluster. Attackers can enumerate all indices, "
                        "search all documents, and potentially execute scripts on the server."
                    ),
                    'recommendation': (
                        "1. Enable X-Pack Security (built-in in Elasticsearch 7.x+):\n"
                        "   xpack.security.enabled: true\n"
                        "2. Set passwords for built-in users:\n"
                        "   elasticsearch-setup-passwords interactive\n"
                        "3. Bind Elasticsearch to localhost (network.host: 127.0.0.1)\n"
                        "4. Use firewall to restrict access to port 9200/9300\n"
                        "5. Enable HTTPS with TLS certificates\n"
                        "6. Implement role-based access control (RBAC)\n"
                        "7. Enable audit logging"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-306',
                    'cvss_score': 10.0,
                    'evidence': 'Unauthenticated access confirmed via API',
                    'references': [
                        'https://www.elastic.co/guide/en/elasticsearch/reference/current/security-basic-setup.html',
                        'https://www.cisa.gov/uscert/ncas/alerts/TA18-123A',
                    ]
                })
            
            # Finding: Version exposed
            if result['version']:
                self.findings.append({
                    'title': f"Elasticsearch version disclosed: {result['version']}",
                    'severity': 'medium',
                    'description': (
                        f"Elasticsearch version {result['version']} is publicly visible. "
                        "Elasticsearch has had critical vulnerabilities "
                        "(CVE-2015-1427, CVE-2015-5531, CVE-2021-22145) that allow "
                        "remote code execution on unpatched versions."
                    ),
                    'recommendation': (
                        "1. Update to the latest Elasticsearch version\n"
                        "2. Check elastic.co/community/security for advisories\n"
                        "3. Subscribe to Elastic security announcements"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 5.0,
                    'evidence': f"Version: {result['version']}, Cluster: {result.get('cluster_name', 'N/A')}",
                })
            
            # Finding: Cluster name exposed
            if result['cluster_name']:
                self.findings.append({
                    'title': f"Elasticsearch cluster name disclosed: {result['cluster_name']}",
                    'severity': 'low',
                    'description': (
                        f"Elasticsearch cluster name '{result['cluster_name']}' is exposed. "
                        "While not directly exploitable, this provides reconnaissance information."
                    ),
                    'recommendation': "Consider using a non-descriptive cluster name.",
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 2.0,
                })
            
            # Finding: Sensitive indices exposed
            if result['sensitive_indices_exposed']:
                index_names = [i.get('index', '') for i in result['sensitive_indices_exposed']]
                self.findings.append({
                    'title': f"Sensitive Elasticsearch indices exposed: {', '.join(index_names[:10])}",
                    'severity': 'critical',
                    'description': (
                        f"The following sensitive system indices are accessible: "
                        f"{', '.join(index_names)}. These may contain security credentials, "
                        "user data, Kibana dashboards, and monitoring data."
                    ),
                    'recommendation': (
                        "1. Restrict access to system indices (.security, .kibana, etc.)\n"
                        "2. Enable field-level and document-level security\n"
                        "3. Use index-level privileges to control access\n"
                        "4. Never expose system indices to unauthenticated users"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 9.0,
                    'evidence': f"Indices: {index_names}",
                })
            
            # Finding: Indices enumerated
            if len(result['indices_exposed']) > 0:
                index_names = [i.get('index', '') for i in result['indices_exposed'][:20]]
                self.findings.append({
                    'title': f"{len(result['indices_exposed'])} Elasticsearch indices exposed",
                    'severity': 'high',
                    'description': (
                        f"Enumerated {len(result['indices_exposed'])} Elasticsearch indices: "
                        f"{', '.join(index_names[:15])}. "
                        "Index names reveal data structure and business logic."
                    ),
                    'recommendation': (
                        "1. Enable authentication to restrict index access\n"
                        "2. Use index-level security\n"
                        "3. Disable wildcard index access\n"
                        "4. Implement proper access controls"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 7.0,
                    'evidence': f"Total indices: {len(result['indices_exposed'])}",
                })
            
            # Finding: X-Pack not enabled
            if not result['xpack_enabled']:
                self.findings.append({
                    'title': 'Elasticsearch X-Pack security not enabled',
                    'severity': 'high',
                    'description': (
                        "X-Pack (Security features) is not enabled. This means "
                        "Elasticsearch is running without authentication, authorization, "
                        "or encryption features."
                    ),
                    'recommendation': (
                        "1. Enable X-Pack security: xpack.security.enabled: true\n"
                        "2. Enable TLS: xpack.security.transport.ssl.enabled: true\n"
                        "3. Enable audit logging: xpack.security.audit.enabled: true"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-306',
                    'cvss_score': 8.0,
                })
        
        else:
            result['findings'].append({
                'title': 'No Elasticsearch instance detected',
                'severity': 'info',
                'description': 'No evidence of Elasticsearch was found on the target.',
                'recommendation': 'If Elasticsearch is installed, ensure it is properly secured.',
                'module': self.module_name,
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Detected: {result['elasticsearch_detected']}, "
            f"Indices: {len(result['indices_exposed'])}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _check_es_endpoint(self, path: str) -> Dict:
        """
        Check an endpoint for Elasticsearch.
        
        Args:
            path: URL path to check
        
        Returns:
            Dict with Elasticsearch info
        """
        result = {
            'detected': False,
            'version': None,
            'cluster_name': None,
            'node_name': None,
            'tagline': None,
        }
        
        resp = self.browser.get(path)
        if not resp or resp.status_code != 200:
            return result
        
        try:
            data = json.loads(resp.text)
            
            # Check for Elasticsearch signature in response
            if 'tagline' in data and 'You Know, for Search' in data.get('tagline', ''):
                result['detected'] = True
                result['tagline'] = data['tagline']
            
            if 'version' in data:
                version_info = data['version']
                result['version'] = version_info.get('number')
                result['detected'] = True
            
            if 'cluster_name' in data:
                result['cluster_name'] = data['cluster_name']
                result['detected'] = True
            
            if 'name' in data:
                result['node_name'] = data['name']
                result['detected'] = True
            
            # Check for cluster UUID
            if 'cluster_uuid' in data:
                result['detected'] = True
            
        except json.JSONDecodeError:
            # Check for text-based Elasticsearch response
            if 'You Know, for Search' in resp.text or 'elasticsearch' in resp.text.lower():
                result['detected'] = True
                
                for pattern in self.version_patterns:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        result['version'] = match.group(1)
                        break
        
        return result
    
    def _check_es_port(self) -> Dict:
        """
        Check Elasticsearch on default port 9200.
        
        Returns:
            Dict with Elasticsearch info from port scan
        """
        result = {
            'detected': False,
        }
        
        # Check if port is open
        if not self._is_port_open(9200):
            return result
        
        # Try to get Elasticsearch info from port 9200
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
            
            es_url = f"http://{self.hostname}:9200/"
            resp = requests.get(es_url, timeout=5)
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    
                    if 'tagline' in data or 'cluster_name' in data:
                        result['detected'] = True
                        result['version'] = data.get('version', {}).get('number')
                        result['cluster_name'] = data.get('cluster_name')
                        result['node_name'] = data.get('name')
                except:
                    pass
        except:
            pass
        
        return result
    
    def _enumerate_indices(self) -> List[Dict]:
        """
        Enumerate Elasticsearch indices.
        
        Returns:
            List of index information
        """
        indices = []
        
        # Try _cat/indices endpoint
        paths = ['/_cat/indices?format=json', '/_cat/indices', '/_aliases']
        
        for path in paths:
            resp = self.browser.get(path)
            if not resp or resp.status_code != 200:
                continue
            
            try:
                data = json.loads(resp.text)
                
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            indices.append({
                                'index': item.get('index', ''),
                                'health': item.get('health', ''),
                                'status': item.get('status', ''),
                                'docs_count': item.get('docs.count', item.get('docsCount', 0)),
                                'store_size': item.get('store.size', item.get('storeSize', '')),
                            })
                
                elif isinstance(data, dict):
                    for index_name in data.keys():
                        indices.append({
                            'index': index_name,
                            'aliases': data[index_name].get('aliases', {}),
                        })
                
            except json.JSONDecodeError:
                # Parse text format
                lines = resp.text.strip().split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('health'):
                        parts = line.split()
                        if len(parts) >= 3:
                            indices.append({
                                'index': parts[2] if len(parts) > 2 else '',
                                'health': parts[0] if parts else '',
                                'status': parts[1] if len(parts) > 1 else '',
                            })
        
        return indices
    
    def _check_authentication(self) -> Dict:
        """
        Check if authentication is enabled.
        
        Returns:
            Dict with authentication info
        """
        result = {
            'enabled': False,
            'xpack': False,
        }
        
        # Try to access _security endpoint
        resp = self.browser.get('/_security/user')
        
        if resp:
            if resp.status_code == 401 or resp.status_code == 403:
                result['enabled'] = True
                result['xpack'] = True
            
            elif resp.status_code == 200:
                # Security endpoint accessible without auth
                result['enabled'] = False
        
        # Check for X-Pack license
        resp = self.browser.get('/_license')
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                if 'license' in data:
                    result['xpack'] = True
            except:
                pass
        
        # Check headers for security indicators
        resp = self.browser.get('/')
        if resp:
            www_auth = resp.headers.get('WWW-Authenticate', '')
            if 'Basic' in www_auth or 'Bearer' in www_auth:
                result['enabled'] = True
        
        return result
    
    def _check_cluster_settings(self) -> Dict:
        """
        Check cluster settings for security issues.
        
        Returns:
            Dict with cluster settings info
        """
        result = {
            'accessible': False,
            'persistent': {},
            'transient': {},
        }
        
        resp = self.browser.get('/_cluster/settings?include_defaults=false')
        
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.text)
                result['accessible'] = True
                result['persistent'] = data.get('persistent', {})
                result['transient'] = data.get('transient', {})
            except:
                pass
        
        return result
    
    def _is_port_open(self, port: int) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.hostname, port))
            sock.close()
            return result == 0
        except:
            return False