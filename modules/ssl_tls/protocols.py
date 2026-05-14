#!/usr/bin/env python3
"""
SSL/TLS Protocol Version Analysis Module.
Tests for supported and vulnerable SSL/TLS protocol versions.
Compatible with Python 3.7+ including 3.11+.

References:
    - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
    - NIST: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
"""

import ssl
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from loguru import logger


class Scanner:
    """SSL/TLS Protocol version scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize protocol scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "SSL/TLS Protocol Analysis"
        
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        self.port = parsed.port or 443
        
        # Build protocol list dynamically based on Python version
        self.protocols = self._build_protocol_list()
    
    def _build_protocol_list(self) -> Dict:
        """
        Build protocol list based on available SSL constants.
        Python 3.10+ removed SSLv2, SSLv3 constants.
        """
        protocols = {}
        
        # Define protocol metadata
        protocol_defs = [
            ('SSLv2', 'critical', False, 'SSL 2.0 is completely insecure (RFC 6176)'),
            ('SSLv3', 'critical', False, 'SSL 3.0 is vulnerable to POODLE attack (RFC 7568)'),
            ('TLSv1_0', 'high', False, 'TLS 1.0 is deprecated due to BEAST attack'),
            ('TLSv1_1', 'high', False, 'TLS 1.1 is deprecated by PCI DSS and browsers'),
            ('TLSv1_2', 'info', True, 'TLS 1.2 is currently secure when properly configured'),
            ('TLSv1_3', 'info', True, 'TLS 1.3 is the most secure and performant version'),
        ]
        
        for name, severity, secure, description in protocol_defs:
            proto_info = {
                'name': name,
                'severity': severity,
                'secure': secure,
                'description': description,
                'available': False,
                'constant': None,
            }
            
            # Try to get the SSL constant
            constant = self._get_protocol_constant(name)
            if constant is not None:
                proto_info['available'] = True
                proto_info['constant'] = constant
            else:
                # Even if constant not available, keep for reporting
                proto_info['available'] = False
            
            protocols[name] = proto_info
        
        return protocols
    
    def _get_protocol_constant(self, name: str):
        """
        Get SSL protocol constant by name.
        Handles Python version differences.
        """
        # Map protocol names to possible constant names
        name_map = {
            'SSLv2': ['PROTOCOL_SSLv2'],
            'SSLv3': ['PROTOCOL_SSLv3'],
            'TLSv1_0': ['PROTOCOL_TLSv1', 'PROTOCOL_TLS'],
            'TLSv1_1': ['PROTOCOL_TLSv1_1'],
            'TLSv1_2': ['PROTOCOL_TLSv1_2', 'PROTOCOL_TLS'],
            'TLSv1_3': ['PROTOCOL_TLSv1_3', 'PROTOCOL_TLS_CLIENT'],
        }
        
        constants = name_map.get(name, [])
        
        for const_name in constants:
            if hasattr(ssl, const_name):
                const_value = getattr(ssl, const_name)
                # Validate it's usable
                try:
                    # Some constants exist but raise errors when used
                    if name in ['SSLv2', 'SSLv3']:
                        # Try to create context to verify it works
                        ssl.SSLContext(const_value)
                    return const_value
                except (ssl.SSLError, ValueError, AttributeError, OSError):
                    continue
        
        return None
    
    def run(self) -> Dict:
        """
        Execute SSL/TLS protocol analysis.
        
        Returns:
            Dict with findings and protocol analysis
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}:{self.port}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'port': self.port,
            'supported_protocols': [],
            'insecure_protocols': [],
            'secure_protocols': [],
            'highest_protocol': None,
            'python_ssl_version': ssl.OPENSSL_VERSION if hasattr(ssl, 'OPENSSL_VERSION') else 'Unknown',
            'findings': []
        }
        
        # Test each protocol
        for proto_name, proto_info in self.protocols.items():
            is_supported = False
            
            if proto_info['available'] and proto_info['constant'] is not None:
                is_supported = self._test_protocol(proto_info['constant'])
            else:
                # Protocol constant not available in this Python version
                # SSLv2/SSLv3 removed in Python 3.10+
                logger.debug(f"Protocol {proto_name} not testable in this Python version")
            
            protocol_result = {
                'name': proto_info['name'],
                'supported': is_supported,
                'secure': proto_info['secure'],
                'testable': proto_info['available'],
            }
            
            result['supported_protocols'].append(protocol_result)
            
            if is_supported:
                if proto_info['secure']:
                    result['secure_protocols'].append(proto_info['name'])
                else:
                    result['insecure_protocols'].append(proto_info['name'])
                    
                    self.findings.append({
                        'title': 'Insecure protocol supported: ' + proto_info['name'],
                        'severity': proto_info['severity'],
                        'description': proto_info['description'],
                        'recommendation': (
                            "Disable " + proto_info['name'] + " and enable only TLS 1.2 and TLS 1.3. "
                            "Update server configuration to remove support for outdated protocols."
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-326' if proto_info['severity'] in ['critical', 'high'] else None,
                        'cvss_score': 7.5 if proto_info['severity'] == 'critical' else 5.0,
                        'evidence': proto_info['name'] + " is supported by the server",
                    })
        
        # Find highest supported protocol
        for proto_name in ['TLSv1_3', 'TLSv1_2', 'TLSv1_1', 'TLSv1_0']:
            for p in result['supported_protocols']:
                if p['name'] == self.protocols[proto_name]['name'] and p['supported']:
                    result['highest_protocol'] = self.protocols[proto_name]['name']
                    break
            if result['highest_protocol']:
                break
        
        # Check TLS 1.3
        tls13_supported = any(
            p['name'] == 'TLSv1_3' and p['supported']
            for p in result['supported_protocols']
        )
        
        if not tls13_supported and result['secure_protocols']:
            self.findings.append({
                'title': 'TLS 1.3 not supported',
                'severity': 'medium',
                'description': 'The server does not support TLS 1.3, the most secure and performant version',
                'recommendation': 'Enable TLS 1.3 support in the web server configuration',
                'module': self.module_name,
                'cvss_score': 4.0,
            })
        
        # All clear check
        if not result['insecure_protocols'] and result['secure_protocols']:
            self.findings.append({
                'title': 'Protocol configuration is secure',
                'severity': 'info',
                'description': "Only secure protocols are enabled: " + ", ".join(result['secure_protocols']),
                'recommendation': 'Continue monitoring for new protocol vulnerabilities',
                'module': self.module_name,
            })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Secure: {result['secure_protocols']}, "
            f"Insecure: {result['insecure_protocols']}"
        )
        return result
    
    def _test_protocol(self, protocol_const) -> bool:
        """
        Test if a specific SSL/TLS protocol version is supported.
        
        Args:
            protocol_const: SSL protocol constant
        
        Returns:
            True if protocol is supported
        """
        try:
            context = ssl.SSLContext(protocol_const)
            
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set minimum ciphers for testing
            try:
                context.set_ciphers('ALL:@SECLEVEL=0')
            except (ssl.SSLError, AttributeError):
                pass  # Some protocols don't support set_ciphers
            
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    return True
                    
        except (ssl.SSLError, socket.error, ConnectionRefusedError, OSError, ValueError, AttributeError):
            return False
        except Exception as e:
            logger.debug(f"Protocol test error: {e}")
            return False