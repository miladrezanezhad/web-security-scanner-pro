#!/usr/bin/env python3
"""
SSL/TLS Protocol Version Analysis Module.
Tests for supported and vulnerable SSL/TLS protocol versions.

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
    
    # Protocol versions and their security status
    PROTOCOLS = {
        ssl.PROTOCOL_SSLv2: {
            'name': 'SSLv2',
            'secure': False,
            'severity': 'critical',
            'description': 'SSL 2.0 is completely insecure and has been deprecated since 2011 (RFC 6176)',
        },
        ssl.PROTOCOL_SSLv3: {
            'name': 'SSLv3',
            'secure': False,
            'severity': 'critical',
            'description': 'SSL 3.0 is vulnerable to POODLE attack and has been deprecated since 2015 (RFC 7568)',
        },
        ssl.PROTOCOL_TLSv1: {
            'name': 'TLSv1.0',
            'secure': False,
            'severity': 'high',
            'description': 'TLS 1.0 is deprecated by PCI DSS and major browsers due to BEAST attack',
        },
        ssl.PROTOCOL_TLSv1_1: {
            'name': 'TLSv1.1',
            'secure': False,
            'severity': 'high',
            'description': 'TLS 1.1 is deprecated by major browsers and PCI DSS',
        },
        ssl.PROTOCOL_TLSv1_2: {
            'name': 'TLSv1.2',
            'secure': True,
            'severity': 'info',
            'description': 'TLS 1.2 is currently secure when properly configured',
        },
    }
    
    # TLS 1.3 constant (Python 3.7+)
    try:
        PROTOCOLS[ssl.PROTOCOL_TLS] = {
            'name': 'TLSv1.2 (negotiated)',
            'secure': True,
            'severity': 'info',
            'description': 'Using negotiated TLS version',
        }
    except AttributeError:
        pass
    
    # TLS 1.3 support (Python 3.7+)
    HAS_TLS13 = hasattr(ssl, 'PROTOCOL_TLSv1_3')
    if HAS_TLS13:
        PROTOCOLS[ssl.PROTOCOL_TLSv1_3] = {
            'name': 'TLSv1.3',
            'secure': True,
            'severity': 'info',
            'description': 'TLS 1.3 is the most secure version available',
        }
    
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
            'findings': []
        }
        
        # Test each protocol version
        for protocol_const, protocol_info in self.PROTOCOLS.items():
            is_supported = self._test_protocol(protocol_const)
            
            protocol_result = {
                'name': protocol_info['name'],
                'supported': is_supported,
                'secure': protocol_info['secure'],
            }
            
            result['supported_protocols'].append(protocol_result)
            
            if is_supported:
                if protocol_info['secure']:
                    result['secure_protocols'].append(protocol_info['name'])
                else:
                    result['insecure_protocols'].append(protocol_info['name'])
                    
                    # Add finding for insecure protocol
                    self.findings.append({
                        'title': f'Insecure protocol supported: {protocol_info["name"]}',
                        'severity': protocol_info['severity'],
                        'description': protocol_info['description'],
                        'recommendation': (
                            f"Disable {protocol_info['name']} and enable only TLS 1.2 and TLS 1.3. "
                            "Update server configuration to remove support for outdated protocols."
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-326' if protocol_info['severity'] in ['critical', 'high'] else None,
                        'cvss_score': 7.5 if protocol_info['severity'] == 'critical' else 5.0,
                        'evidence': f"{protocol_info['name']} is supported by the server",
                    })
        
        # Find highest supported protocol
        for protocol_const, protocol_info in reversed(list(self.PROTOCOLS.items())):
            if any(p['name'] == protocol_info['name'] and p['supported'] 
                   for p in result['supported_protocols']):
                result['highest_protocol'] = protocol_info['name']
                break
        
        # Check if TLS 1.3 is available
        if 'TLSv1.3' not in result['secure_protocols']:
            self.findings.append({
                'title': 'TLS 1.3 not supported',
                'severity': 'medium',
                'description': 'The server does not support TLS 1.3, which is the most secure and performant version',
                'recommendation': 'Enable TLS 1.3 support in the web server configuration',
                'module': self.module_name,
                'cvss_score': 4.0,
            })
        
        # Check if only secure protocols are enabled
        if not result['insecure_protocols'] and result['secure_protocols']:
            self.findings.append({
                'title': 'Protocol configuration is secure',
                'severity': 'info',
                'description': f"Only secure protocols are enabled: {', '.join(result['secure_protocols'])}",
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
    
    def _test_protocol(self, protocol_const: int) -> bool:
        """
        Test if a specific SSL/TLS protocol version is supported.
        
        Args:
            protocol_const: SSL protocol constant
        
        Returns:
            True if protocol is supported
        """
        try:
            # Skip SSLv2 on newer Python versions
            if protocol_const == ssl.PROTOCOL_SSLv2:
                try:
                    context = ssl.SSLContext(protocol_const)
                except (ssl.SSLError, ValueError, AttributeError):
                    return False
            else:
                context = ssl.SSLContext(protocol_const)
            
            # Set minimum security for connection
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set ciphers (allow all for testing)
            context.set_ciphers('ALL:@SECLEVEL=0')
            
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Connection successful - protocol is supported
                    return True
                    
        except (ssl.SSLError, socket.error, ConnectionRefusedError, OSError) as e:
            # Protocol not supported or connection failed
            return False
        except Exception as e:
            logger.debug(f"Protocol test error ({protocol_const}): {e}")
            return False