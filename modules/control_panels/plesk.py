#!/usr/bin/env python3
"""
Plesk Control Panel Security Scanner Module.
Tests for common Plesk security misconfigurations and exposures.

References:
    - Plesk Security: https://docs.plesk.com/en-US/obsidian/administrator-guide/server-administration/protecting-plesk/
    - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    - OWASP: Testing for Admin Interfaces
"""

import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from loguru import logger


class Scanner:
    """Plesk security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize Plesk scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Plesk Security Analysis"
        
        # Parse hostname from URL
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # Plesk default ports and their services
        self.plesk_ports = {
            8443: 'Plesk Control Panel (HTTPS)',
            8880: 'Plesk Control Panel (HTTP)',
            8447: 'Plesk Installer/Updates',
        }
        
        # Common Plesk paths
        self.plesk_paths = [
            '/',
            '/login_up.php',
            '/admin/',
            '/smb/',
            '/webmail/',
            '/roundcube/',
            '/horde/',
            '/phpmyadmin/',
            '/plesk-stat/',
            '/.plesk/',
        ]
        
        # Plesk-specific files that could expose information
        self.sensitive_paths = [
            '/.plesk.yml',
            '/.plesk/client_prefs.php',
            '/plesk-backup/',
            '/plesk-backup.tar.gz',
            '/admin/backup/',
            '/.well-known/plesk/',
        ]
        
        # Version detection patterns
        self.version_patterns = [
            r'Plesk\s+([\d.]+)',
            r'Plesk\s+Obsidian\s+([\d.]+)',
            r'Plesk\s+Onyx\s+([\d.]+)',
            r'<title>Plesk\s+([\d.]+)</title>',
            r'plesk_version\s*[:=]\s*["\']?([\d.]+)',
            r'\"version\":\s*\"([\d.]+)\"',
            r'<meta\s+name=\"generator\"\s+content=\"Plesk\s+([\d.]+)\"',
        ]
        
        # Technology stack patterns
        self.tech_patterns = [
            r'<meta\s+name=\"generator\"\s+content=\"Plesk',
            r'plesk\.js',
            r'plesk\.css',
            r'\/plesk\/',
            r'plesk-widget',
            r'x-plesk',
        ]
        
        # API endpoints
        self.api_endpoints = [
            '/api/v2/',
            '/api/v2/swagger.json',
            '/api/v2/openapi.json',
            '/api/',
            '/rest/v1/',
        ]
    
    def run(self) -> Dict:
        """
        Execute Plesk security tests.
        
        Returns:
            Dict with findings and comprehensive analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'plesk_detected': False,
            'version': None,
            'version_exposed': False,
            'open_ports': [],
            'exposed_paths': [],
            'api_exposed': False,
            'backup_exposed': False,
            'default_page_exposed': False,
            'findings': []
        }
        
        # Stage 1: Port scanning
        result['open_ports'] = self._scan_ports()
        if result['open_ports']:
            result['plesk_detected'] = True
        
        # Stage 2: Check main ports for Plesk interface
        plesk_info = self._detect_plesk_interface()
        if plesk_info:
            result['plesk_detected'] = True
            result['version'] = plesk_info.get('version')
            result['version_exposed'] = plesk_info.get('version_exposed', False)
            result['default_page_exposed'] = plesk_info.get('default_page', False)
        
        # Stage 3: Check standard web ports
        web_detection = self._check_web_paths()
        if web_detection.get('detected'):
            result['plesk_detected'] = True
            if not result['version']:
                result['version'] = web_detection.get('version')
            result['exposed_paths'] = web_detection.get('exposed_paths', [])
        
        # Stage 4: Check API exposure
        result['api_exposed'] = self._check_api_exposure()
        
        # Stage 5: Check for backup exposure
        result['backup_exposed'] = self._check_backup_exposure()
        
        # Stage 6: Check for sensitive file exposure
        sensitive_findings = self._check_sensitive_files()
        
        # ===================================================================
        # Generate security findings
        # ===================================================================
        
        # Finding: Plesk detected
        if result['plesk_detected']:
            # Finding: Open ports
            if result['open_ports']:
                port_details = []
                for port_info in result['open_ports']:
                    service = self.plesk_ports.get(port_info['port'], 'Unknown Service')
                    port_details.append(f"{port_info['port']} ({service})")
                
                self.findings.append({
                    'title': f"Plesk control panel ports exposed: {', '.join(port_details)}",
                    'severity': 'high',
                    'description': (
                        f"Plesk control panel services are directly accessible on "
                        f"port(s): {', '.join(port_details)}. This exposes administrative "
                        "interfaces to potential brute-force attacks and unauthorized access attempts."
                    ),
                    'recommendation': (
                        "1. Use firewall to restrict access to Plesk ports by trusted IP addresses only\n"
                        "2. Implement fail2ban with Plesk integration for brute-force protection\n"
                        "3. Consider using a VPN for administrative access\n"
                        "4. Enable two-factor authentication for all Plesk accounts\n"
                        "5. Change default Plesk ports to non-standard values\n"
                        "6. Use Plesk Firewall extension to manage access rules"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 7.5,
                    'evidence': f"Open Plesk ports: {port_details}",
                    'references': [
                        'https://docs.plesk.com/en-US/obsidian/administrator-guide/server-administration/protecting-plesk/plesk-firewall.65280/',
                    ]
                })
            
            # Finding: Version exposed
            if result['version_exposed'] and result['version']:
                self.findings.append({
                    'title': f"Plesk version disclosed: {result['version']}",
                    'severity': 'medium',
                    'description': (
                        f"Plesk version {result['version']} is publicly visible. "
                        "Version disclosure helps attackers identify known vulnerabilities "
                        "and plan targeted attacks against specific versions."
                    ),
                    'recommendation': (
                        "1. Update Plesk to the latest stable version\n"
                        "2. Check the Plesk Change Log for security fixes\n"
                        "3. Subscribe to Plesk security notifications\n"
                        "4. Consider hiding version information in Plesk settings\n"
                        "5. Implement Web Application Firewall rules to strip version headers"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 5.0,
                    'evidence': f"Detected version: {result['version']}",
                    'references': [
                        'https://docs.plesk.com/release-notes/obsidian/change-log/',
                    ]
                })
            
            # Finding: Default page exposed
            if result['default_page_exposed']:
                self.findings.append({
                    'title': 'Plesk default page is publicly accessible',
                    'severity': 'medium',
                    'description': (
                        "The Plesk default page is accessible without authentication. "
                        "This page may contain server information and confirms the presence "
                        "of Plesk control panel to potential attackers."
                    ),
                    'recommendation': (
                        "1. Configure Plesk to require authentication for all pages\n"
                        "2. Set up a custom default page or redirect\n"
                        "3. Use .htaccess to restrict access to Plesk directories\n"
                        "4. Consider using the Plesk Custom Default Page extension"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 4.0,
                    'evidence': 'Plesk default page accessible without authentication',
                })
            
            # Finding: API exposed
            if result['api_exposed']:
                self.findings.append({
                    'title': 'Plesk REST API is publicly accessible',
                    'severity': 'high',
                    'description': (
                        "The Plesk REST API is exposed and accessible. The API provides "
                        "programmatic access to server management functions including "
                        "domain management, database administration, and file operations."
                    ),
                    'recommendation': (
                        "1. Restrict API access by IP address in Plesk firewall\n"
                        "2. Require strong authentication for all API requests\n"
                        "3. Use API keys instead of passwords where possible\n"
                        "4. Enable API request logging and monitoring\n"
                        "5. Disable API if not actively used\n"
                        "6. Implement rate limiting on API endpoints"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-306',
                    'cvss_score': 8.0,
                    'evidence': 'REST API endpoints accessible',
                    'references': [
                        'https://docs.plesk.com/en-US/obsidian/api-rpc/about-the-plesk-api/rest-api.28779/',
                    ]
                })
            
            # Finding: Backup exposed
            if result['backup_exposed']:
                self.findings.append({
                    'title': 'Plesk backup files are publicly accessible',
                    'severity': 'critical',
                    'description': (
                        "Plesk backup files or backup directories are publicly accessible. "
                        "Backups may contain complete server configurations, databases, "
                        "email accounts, and sensitive customer data."
                    ),
                    'recommendation': (
                        "1. Move all backup files outside the web-accessible directory\n"
                        "2. Store backups in a secure, encrypted location\n"
                        "3. Use Plesk Backup Manager to configure secure backup storage\n"
                        "4. Implement access controls on backup directories\n"
                        "5. Regularly audit backup file permissions\n"
                        "6. Consider using remote/cloud backup storage"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-538',
                    'cvss_score': 9.5,
                    'evidence': 'Backup files/directories publicly accessible',
                })
            
            # Finding: Sensitive files
            for sensitive in sensitive_findings:
                self.findings.append({
                    'title': f"Sensitive Plesk file exposed: {sensitive['path']}",
                    'severity': 'high',
                    'description': (
                        f"The file {sensitive['path']} is publicly accessible. "
                        "This file may contain configuration details, credentials, "
                        "or other sensitive information about the Plesk installation."
                    ),
                    'recommendation': (
                        "1. Restrict access to .plesk directory using web server configuration\n"
                        "2. Add the following to .htaccess or web server config:\n"
                        "   <DirectoryMatch \".plesk\">\n"
                        "       Require all denied\n"
                        "   </DirectoryMatch>\n"
                        "3. Set proper file permissions (640 or 600)\n"
                        "4. Regularly scan for exposed configuration files"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 7.5,
                    'evidence': f"Status code: {sensitive['status']}",
                })
        
        else:
            # Plesk not detected
            self.findings.append({
                'title': 'No Plesk installation detected',
                'severity': 'info',
                'description': 'No evidence of Plesk control panel was found on the target system.',
                'recommendation': 'If Plesk is installed, verify that it is properly secured and not exposed.',
                'module': self.module_name,
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Detected: {result['plesk_detected']}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _scan_ports(self) -> List[Dict]:
        """
        Scan for open Plesk ports.
        
        Returns:
            List of dicts with port information
        """
        open_ports = []
        
        for port, service in self.plesk_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.hostname, port))
                sock.close()
                
                if result == 0:
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
            except socket.gaierror:
                logger.debug(f"DNS resolution failed for {self.hostname}")
                break
            except Exception as e:
                logger.debug(f"Port scan error for port {port}: {e}")
        
        return open_ports
    
    def _detect_plesk_interface(self) -> Optional[Dict]:
        """
        Try to access Plesk interface on default ports.
        
        Returns:
            Dict with Plesk information or None
        """
        # Try HTTPS on port 8443 first
        plesk_url = f"https://{self.hostname}:8443"
        
        try:
            import requests
            # Disable SSL warnings for self-signed certificates
            requests.packages.urllib3.disable_warnings()
            
            resp = requests.get(
                plesk_url,
                verify=False,
                timeout=10,
                allow_redirects=True
            )
            
            info = {
                'default_page': False,
                'version': None,
                'version_exposed': False,
            }
            
            # Check if it's a Plesk page
            is_plesk = any(
                indicator in resp.text.lower()
                for indicator in ['plesk', 'pp-', 'plesk-']
            )
            
            if not is_plesk and resp.status_code != 200:
                return None
            
            info['default_page'] = resp.status_code == 200
            
            # Try to extract version
            for pattern in self.version_patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    info['version'] = match.group(1)
                    info['version_exposed'] = True
                    break
            
            # Check headers for Plesk indicators
            server_header = resp.headers.get('Server', '')
            if 'plesk' in server_header.lower():
                info['version_exposed'] = True
            
            return info
            
        except requests.ConnectionError:
            # Try HTTP on port 8880
            try:
                plesk_url = f"http://{self.hostname}:8880"
                resp = requests.get(plesk_url, timeout=10, allow_redirects=True)
                
                if 'plesk' in resp.text.lower():
                    return {
                        'default_page': resp.status_code == 200,
                        'version': None,
                        'version_exposed': False,
                    }
            except:
                pass
        except Exception as e:
            logger.debug(f"Plesk interface detection error: {e}")
        
        return None
    
    def _check_web_paths(self) -> Dict:
        """
        Check standard web paths for Plesk indicators.
        
        Returns:
            Dict with detection results
        """
        result = {
            'detected': False,
            'version': None,
            'exposed_paths': [],
        }
        
        # First check the main page for Plesk indicators
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            # Check for Plesk technology signatures
            for pattern in self.tech_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    result['detected'] = True
                    break
            
            # Check for version
            if result['detected']:
                for pattern in self.version_patterns:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        result['version'] = match.group(1)
                        break
        
        # Check Plesk-specific paths
        for path in self.plesk_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 301, 302, 403]:
                result['exposed_paths'].append({
                    'path': path,
                    'status': resp.status_code,
                })
                
                if 'plesk' in resp.text.lower():
                    result['detected'] = True
                    
                    if not result['version']:
                        for pattern in self.version_patterns:
                            match = re.search(pattern, resp.text, re.IGNORECASE)
                            if match:
                                result['version'] = match.group(1)
                                break
        
        return result
    
    def _check_api_exposure(self) -> bool:
        """
        Check if Plesk REST API is exposed.
        
        Returns:
            True if API is accessible
        """
        for endpoint in self.api_endpoints:
            resp = self.browser.get(endpoint)
            if resp and resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '')
                
                # Check for JSON API response
                if 'application/json' in content_type:
                    try:
                        import json
                        data = json.loads(resp.text)
                        # Plesk API typically returns swagger documentation
                        if 'swagger' in resp.text.lower() or 'openapi' in resp.text.lower():
                            return True
                        if isinstance(data, dict) and 'paths' in data:
                            return True
                    except:
                        pass
                
                # Check for XML-RPC API
                if 'xml' in content_type.lower() and 'plesk' in resp.text.lower():
                    return True
        
        return False
    
    def _check_backup_exposure(self) -> bool:
        """
        Check for exposed Plesk backup files.
        
        Returns:
            True if backups are accessible
        """
        for path in self.sensitive_paths:
            if 'backup' in path:
                resp = self.browser.head(path)
                if resp and resp.status_code == 200:
                    return True
                
                # Also try GET for directory listing
                resp = self.browser.get(path)
                if resp and resp.status_code == 200:
                    if 'Index of' in resp.text or 'plesk' in resp.text.lower():
                        return True
        
        return False
    
    def _check_sensitive_files(self) -> List[Dict]:
        """
        Check for exposed sensitive Plesk files.
        
        Returns:
            List of exposed file information
        """
        exposed = []
        
        for path in self.sensitive_paths:
            if 'backup' not in path:  # Backup paths handled separately
                resp = self.browser.head(path)
                if resp and resp.status_code == 200:
                    exposed.append({
                        'path': path,
                        'status': resp.status_code,
                    })
        
        return exposed