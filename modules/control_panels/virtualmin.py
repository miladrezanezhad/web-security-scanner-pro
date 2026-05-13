#!/usr/bin/env python3
"""
Virtualmin Control Panel Security Scanner Module.
Tests for common Virtualmin security misconfigurations and exposures.

References:
    - Virtualmin Security: https://www.virtualmin.com/documentation/security/
    - Webmin Security: https://webmin.com/docs/#security
    - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from loguru import logger


class Scanner:
    """Virtualmin/Webmin security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize Virtualmin scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Virtualmin/Webmin Security Analysis"
        
        # Parse hostname from URL
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        
        # Virtualmin/Webmin default port
        self.webmin_port = 10000
        
        # Additional ports Virtualmin might use
        self.virtualmin_ports = {
            10000: 'Webmin/Virtualmin Control Panel',
            20000: 'Usermin Webmail Interface',
        }
        
        # Common Virtualmin paths
        self.virtualmin_paths = [
            '/',
            '/virtualmin/',
            '/webmin/',
            '/usermin/',
            '/virtual-server/',
            '/phpmyadmin/',
            '/roundcube/',
            '/mail/',
        ]
        
        # Virtualmin-specific files and directories
        self.sensitive_paths = [
            '/.virtualmin/',
            '/virtualmin-backup/',
            '/etc/webmin/',
            '/webmin/backup/',
            '/unauthenticated/',
            '/password_change.cgi',
            '/shell/index.cgi',
            '/file/show.cgi',
        ]
        
        # Version detection patterns
        self.version_patterns = [
            r'Webmin\s+([\d.]+)',
            r'Virtualmin\s+([\d.]+)',
            r'Webmin\s+version\s+([\d.]+)',
            r'<title>Webmin\s+([\d.]+)</title>',
            r'<title>Virtualmin\s+([\d.]+)</title>',
            r'webmin_version\s*=\s*["\']?([\d.]+)',
            r'virtualmin_version\s*=\s*["\']?([\d.]+)',
            r'powered by Webmin\s+([\d.]+)',
            r'Server:\s*MiniServ/([\d.]+)',
        ]
        
        # Technology stack patterns
        self.tech_patterns = [
            r'Webmin',
            r'Virtualmin',
            r'MiniServ',
            r'webmin\.css',
            r'virtualmin\.css',
            r'/webmin/',
            r'/virtualmin/',
            r'/virtual-server/',
        ]
        
        # Known vulnerable paths (unauthenticated access)
        self.unauthenticated_paths = [
            '/unauthenticated/',
            '/password_change.cgi',
            '/shell/index.cgi',
            '/file/show.cgi',
            '/file/min.cgi',
            '/proc/index.cgi',
            '/sysinfo.cgi',
            '/status/',
        ]
    
    def run(self) -> Dict:
        """
        Execute Virtualmin/Webmin security tests.
        
        Returns:
            Dict with findings and comprehensive analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'virtualmin_detected': False,
            'webmin_detected': False,
            'version': None,
            'version_exposed': False,
            'open_ports': [],
            'exposed_paths': [],
            'unauthenticated_access': [],
            'default_credentials_risk': False,
            'findings': []
        }
        
        # Stage 1: Port scanning
        result['open_ports'] = self._scan_ports()
        if result['open_ports']:
            result['webmin_detected'] = True
            result['virtualmin_detected'] = True
        
        # Stage 2: Check Virtualmin/Webmin interface
        webmin_info = self._detect_webmin_interface()
        if webmin_info:
            result['webmin_detected'] = True
            result['virtualmin_detected'] = webmin_info.get('is_virtualmin', False)
            result['version'] = webmin_info.get('version')
            result['version_exposed'] = webmin_info.get('version_exposed', False)
        
        # Stage 3: Check standard web paths
        web_detection = self._check_web_paths()
        if web_detection.get('detected'):
            if not result['webmin_detected']:
                result['webmin_detected'] = True
            if web_detection.get('is_virtualmin'):
                result['virtualmin_detected'] = True
            if not result['version']:
                result['version'] = web_detection.get('version')
            result['exposed_paths'] = web_detection.get('exposed_paths', [])
        
        # Stage 4: Check for unauthenticated access
        result['unauthenticated_access'] = self._check_unauthenticated_access()
        
        # Stage 5: Check for default credentials risk
        result['default_credentials_risk'] = self._check_default_credentials_risk()
        
        # Stage 6: Check sensitive file exposure
        sensitive_findings = self._check_sensitive_files()
        
        # ===================================================================
        # Generate security findings
        # ===================================================================
        
        if result['webmin_detected']:
            # Finding: Open ports
            if result['open_ports']:
                port_details = []
                for port_info in result['open_ports']:
                    service = self.virtualmin_ports.get(
                        port_info['port'], 
                        'Unknown Service'
                    )
                    port_details.append(f"{port_info['port']} ({service})")
                
                self.findings.append({
                    'title': f"Webmin/Virtualmin control panel ports exposed: {', '.join(port_details)}",
                    'severity': 'high',
                    'description': (
                        f"Webmin/Virtualmin control panel services are directly accessible "
                        f"on port(s): {', '.join(port_details)}. Webmin provides root-level "
                        "server administration capabilities through a web interface."
                    ),
                    'recommendation': (
                        "1. Use firewall to restrict access to port 10000 by trusted IPs only\n"
                        "2. Consider using a VPN for administrative access\n"
                        "3. Enable two-factor authentication in Webmin\n"
                        "4. Configure fail2ban for Webmin login protection\n"
                        "5. Use Webmin's IP Access Control feature\n"
                        "6. Change the default Webmin port to a non-standard value\n"
                        "7. Consider using SSH tunneling instead of direct access"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 8.0,
                    'evidence': f"Open Webmin ports: {port_details}",
                    'references': [
                        'https://webmin.com/docs/#security',
                        'https://www.virtualmin.com/documentation/security/',
                    ]
                })
            
            # Finding: Version exposed
            if result['version_exposed'] and result['version']:
                # Check if version has known vulnerabilities
                self.findings.append({
                    'title': f"Webmin/Virtualmin version disclosed: {result['version']}",
                    'severity': 'medium',
                    'description': (
                        f"Webmin/Virtualmin version {result['version']} is publicly visible. "
                        "Webmin has had several critical vulnerabilities in the past "
                        "(CVE-2019-15107, CVE-2020-8820, etc.) that allow remote code execution. "
                        "Version disclosure makes it easy for attackers to target specific vulnerable versions."
                    ),
                    'recommendation': (
                        "1. Update Webmin/Virtualmin to the latest version immediately\n"
                        "2. Check for security advisories at webmin.com/security.html\n"
                        "3. Subscribe to Webmin security announcements\n"
                        "4. Consider hiding version information via Webmin configuration\n"
                        "5. Regularly run 'yum update webmin' or 'apt upgrade webmin'"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 6.0,
                    'evidence': f"Detected version: {result['version']}",
                    'references': [
                        'https://webmin.com/security.html',
                        'https://www.cvedetails.com/vulnerability-list/vendor_id-429/Webmin.html',
                    ]
                })
            
            # Finding: Unauthenticated access
            if result['unauthenticated_access']:
                accessible_paths = [u['path'] for u in result['unauthenticated_access']]
                self.findings.append({
                    'title': (
                        f"Unauthenticated access to Webmin resources: "
                        f"{', '.join(accessible_paths[:5])}"
                    ),
                    'severity': 'critical',
                    'description': (
                        f"Several Webmin paths are accessible without authentication: "
                        f"{', '.join(accessible_paths)}. This could allow attackers to "
                        "execute commands, read files, or change passwords without logging in."
                    ),
                    'recommendation': (
                        "1. Update Webmin immediately to the latest version\n"
                        "2. Check /etc/webmin/miniserv.conf for 'unauthenticated' settings\n"
                        "3. Remove or restrict access to unauthenticated paths\n"
                        "4. Set 'unauthenticated_access=none' in miniserv.conf\n"
                        "5. Restart Webmin after configuration changes\n"
                        "6. Check Webmin User Interface settings"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-306',
                    'cvss_score': 9.8,
                    'evidence': f"Accessible unauthenticated paths: {accessible_paths}",
                    'references': [
                        'https://www.cvedetails.com/cve/CVE-2019-15107/',
                        'https://github.com/webmin/webmin/security/advisories',
                    ]
                })
            
            # Finding: Default credentials risk
            if result['default_credentials_risk']:
                self.findings.append({
                    'title': 'Potential default credentials risk detected',
                    'severity': 'high',
                    'description': (
                        "The Webmin/Virtualmin login page is accessible and may be "
                        "using default credentials. Default credentials are a common "
                        "attack vector for gaining unauthorized administrative access."
                    ),
                    'recommendation': (
                        "1. Change the default 'root' or 'admin' password immediately\n"
                        "2. Enforce strong password policies\n"
                        "3. Enable two-factor authentication\n"
                        "4. Limit login attempts (fail2ban integration)\n"
                        "5. Use SSH key authentication where possible\n"
                        "6. Regularly audit user accounts and permissions"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-1392',
                    'cvss_score': 8.5,
                    'evidence': 'Webmin login interface detected with potential default credentials',
                })
            
            # Finding: Sensitive files
            for sensitive in sensitive_findings:
                self.findings.append({
                    'title': f"Sensitive Webmin/Virtualmin path exposed: {sensitive['path']}",
                    'severity': 'high',
                    'description': (
                        f"The path {sensitive['path']} is publicly accessible. "
                        "This may expose configuration files, backup data, or "
                        "administrative functions."
                    ),
                    'recommendation': (
                        "1. Restrict access to administrative paths\n"
                        "2. Configure web server to deny access to .virtualmin directory\n"
                        "3. Move configuration files outside web root\n"
                        "4. Use proper file permissions (600 for config files)\n"
                        "5. Regularly audit file permissions"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 7.5,
                    'evidence': f"Status code: {sensitive['status']}",
                })
            
            # Finding: Virtualmin-specific
            if result['virtualmin_detected']:
                self.findings.append({
                    'title': 'Virtualmin hosting control panel detected',
                    'severity': 'info',
                    'description': (
                        "Virtualmin hosting control panel has been detected. "
                        "Virtualmin provides complete virtual hosting management "
                        "including Apache, DNS, MySQL, mail, and FTP administration."
                    ),
                    'recommendation': (
                        "1. Ensure Virtualmin is updated regularly\n"
                        "2. Review Virtualmin security settings\n"
                        "3. Use Virtualmin's built-in security features\n"
                        "4. Monitor /var/log/virtualmin/ for suspicious activity\n"
                        "5. Consider professional security audit for hosting environments"
                    ),
                    'module': self.module_name,
                    'cwe_id': 'CWE-200',
                    'cvss_score': 0,
                    'references': [
                        'https://www.virtualmin.com/documentation/security/',
                    ]
                })
        
        else:
            self.findings.append({
                'title': 'No Webmin/Virtualmin installation detected',
                'severity': 'info',
                'description': (
                    'No evidence of Webmin or Virtualmin control panel was found '
                    'on the target system.'
                ),
                'recommendation': (
                    'If Webmin/Virtualmin is installed, verify that it is properly '
                    'secured and not exposed to the internet.'
                ),
                'module': self.module_name,
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Detected: {result['webmin_detected']}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _scan_ports(self) -> List[Dict]:
        """
        Scan for open Virtualmin/Webmin ports.
        
        Returns:
            List of dicts with port information
        """
        open_ports = []
        
        for port, service in self.virtualmin_ports.items():
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
    
    def _detect_webmin_interface(self) -> Optional[Dict]:
        """
        Try to access Webmin/Virtualmin interface on default port.
        
        Returns:
            Dict with Webmin information or None
        """
        webmin_url = f"https://{self.hostname}:{self.webmin_port}"
        
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
            
            resp = requests.get(
                webmin_url,
                verify=False,
                timeout=10,
                allow_redirects=True
            )
            
            info = {
                'is_virtualmin': False,
                'version': None,
                'version_exposed': False,
            }
            
            # Check if it's Webmin
            is_webmin = 'webmin' in resp.text.lower() or 'MiniServ' in resp.headers.get('Server', '')
            
            if not is_webmin:
                return None
            
            # Check if it's Virtualmin specifically
            if 'virtualmin' in resp.text.lower() or 'virtual-server' in resp.text.lower():
                info['is_virtualmin'] = True
            
            # Extract version
            for pattern in self.version_patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    info['version'] = match.group(1)
                    info['version_exposed'] = True
                    break
            
            # Check Server header
            server_header = resp.headers.get('Server', '')
            if 'MiniServ' in server_header:
                match = re.search(r'MiniServ/([\d.]+)', server_header)
                if match and not info['version']:
                    info['version'] = match.group(1)
                    info['version_exposed'] = True
            
            return info
            
        except requests.ConnectionError:
            logger.debug(f"Could not connect to Webmin on port {self.webmin_port}")
        except Exception as e:
            logger.debug(f"Webmin interface detection error: {e}")
        
        return None
    
    def _check_web_paths(self) -> Dict:
        """
        Check standard web paths for Virtualmin/Webmin indicators.
        
        Returns:
            Dict with detection results
        """
        result = {
            'detected': False,
            'is_virtualmin': False,
            'version': None,
            'exposed_paths': [],
        }
        
        # Check main page
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            for pattern in self.tech_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    result['detected'] = True
                    if 'virtualmin' in resp.text.lower():
                        result['is_virtualmin'] = True
                    break
            
            if result['detected']:
                for pattern in self.version_patterns:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        result['version'] = match.group(1)
                        break
        
        # Check Virtualmin-specific paths
        for path in self.virtualmin_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code in [200, 301, 302, 403]:
                result['exposed_paths'].append({
                    'path': path,
                    'status': resp.status_code,
                })
                
                if 'webmin' in resp.text.lower():
                    result['detected'] = True
                if 'virtualmin' in resp.text.lower():
                    result['detected'] = True
                    result['is_virtualmin'] = True
        
        return result
    
    def _check_unauthenticated_access(self) -> List[Dict]:
        """
        Check for unauthenticated access to Webmin resources.
        
        This is critical as several Webmin CVEs involve unauthenticated RCE.
        
        Returns:
            List of accessible unauthenticated paths
        """
        accessible = []
        
        for path in self.unauthenticated_paths:
            # Try on main web port
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                # Verify it's not a login redirect
                if 'login' not in resp.text.lower() or len(resp.text) < 100:
                    continue
                
                accessible.append({
                    'path': path,
                    'status': resp.status_code,
                    'content_length': len(resp.text),
                })
            
            # Try on Webmin port
            try:
                import requests
                requests.packages.urllib3.disable_warnings()
                
                webmin_url = f"https://{self.hostname}:{self.webmin_port}{path}"
                resp = requests.get(webmin_url, verify=False, timeout=5)
                
                if resp.status_code == 200:
                    if 'login' not in resp.text.lower():
                        accessible.append({
                            'path': f":{self.webmin_port}{path}",
                            'status': resp.status_code,
                            'content_length': len(resp.text),
                        })
            except:
                pass
        
        return accessible
    
    def _check_default_credentials_risk(self) -> bool:
        """
        Check if there's a risk of default credentials.
        
        Returns:
            True if default credentials risk exists
        """
        # If login page is accessible, there's always some risk
        login_paths = ['/', '/webmin/', '/virtualmin/']
        
        for path in login_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                if any(
                    keyword in resp.text.lower()
                    for keyword in ['login', 'sign in', 'password', 'username']
                ):
                    # Login page found - default credentials risk exists
                    return True
        
        return False
    
    def _check_sensitive_files(self) -> List[Dict]:
        """
        Check for exposed sensitive Virtualmin files.
        
        Returns:
            List of exposed file information
        """
        exposed = []
        
        for path in self.sensitive_paths:
            # Skip paths already checked for unauthenticated access
            if path in self.unauthenticated_paths:
                continue
            
            resp = self.browser.head(path)
            if resp and resp.status_code in [200, 403]:
                exposed.append({
                    'path': path,
                    'status': resp.status_code,
                })
        
        return exposed