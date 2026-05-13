#!/usr/bin/env python3
"""
SSL/TLS Cipher Suite Analysis Module.
Tests for weak and insecure cipher suites.

References:
    - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
    - Mozilla: https://wiki.mozilla.org/Security/Server_Side_TLS
"""

import ssl
import socket
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from loguru import logger


class Scanner:
    """SSL/TLS Cipher Suite scanner."""
    
    # Weak cipher indicators
    WEAK_CIPHER_INDICATORS = [
        'NULL', 'anon', 'EXPORT', 'DES', 'RC4', 'RC2', 
        'MD5', '3DES', 'SEED', 'IDEA', 'CAMELLIA',
        'TLS_RSA_', 'TLS_DH_', 'TLS_ECDH_',
    ]
    
    # Insecure key exchange
    INSECURE_KEY_EXCHANGE = [
        'TLS_RSA_', 'TLS_DH_anon', 'TLS_ECDH_anon',
    ]
    
    # Weak hash algorithms
    WEAK_HASHES = ['MD5', 'SHA1', 'SHA-1']
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize cipher scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "SSL/TLS Cipher Suite Analysis"
        
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        self.port = parsed.port or 443
    
    def run(self) -> Dict:
        """
        Execute cipher suite analysis.
        
        Returns:
            Dict with findings and cipher analysis
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}:{self.port}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'port': self.port,
            'supported_ciphers': [],
            'weak_ciphers': [],
            'insecure_ciphers': [],
            'total_ciphers': 0,
            'weak_count': 0,
            'findings': []
        }
        
        # Get supported ciphers
        ciphers = self._get_supported_ciphers()
        result['supported_ciphers'] = ciphers
        result['total_ciphers'] = len(ciphers)
        
        # Analyze each cipher
        for cipher in ciphers:
            analysis = self._analyze_cipher(cipher)
            
            if analysis['weak']:
                result['weak_ciphers'].append({
                    'cipher': cipher,
                    'issues': analysis['issues']
                })
                result['weak_count'] += 1
                
                if analysis['insecure']:
                    result['insecure_ciphers'].append(cipher)
        
        # Generate findings
        if result['weak_count'] > 0:
            self.findings.append({
                'title': f'{result["weak_count"]} weak cipher(s) supported',
                'severity': 'high' if result['weak_count'] > 5 else 'medium',
                'description': (
                    f"The server supports {result['weak_count']} weak cipher suite(s) "
                    f"out of {result['total_ciphers']} total ciphers. "
                    f"Insecure ciphers: {', '.join(result['insecure_ciphers'][:5])}"
                ),
                'recommendation': (
                    "1. Disable all NULL, EXPORT, and anonymous cipher suites\n"
                    "2. Disable RC4, 3DES, and DES ciphers\n"
                    "3. Prefer ECDHE key exchange over RSA\n"
                    "4. Use only AEAD ciphers (GCM or ChaCha20-Poly1305)\n"
                    "5. Configure cipher order to prefer strongest ciphers first"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-327',
                'cvss_score': 6.5,
                'evidence': f"Weak ciphers: {', '.join(result['insecure_ciphers'][:5])}",
            })
        else:
            self.findings.append({
                'title': 'Cipher configuration appears secure',
                'severity': 'info',
                'description': f"No weak cipher suites detected among {result['total_ciphers']} supported ciphers",
                'recommendation': 'Continue monitoring for new cipher vulnerabilities',
                'module': self.module_name,
            })
        
        # Check for Forward Secrecy support
        has_fs = self._check_forward_secrecy(ciphers)
        if not has_fs:
            self.findings.append({
                'title': 'No Forward Secrecy ciphers supported',
                'severity': 'medium',
                'description': 'The server does not support ECDHE or DHE key exchange for Forward Secrecy',
                'recommendation': 'Enable ECDHE-based cipher suites to support Perfect Forward Secrecy',
                'module': self.module_name,
                'cvss_score': 4.0,
            })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. {result['weak_count']}/{result['total_ciphers']} weak ciphers")
        return result
    
    def _get_supported_ciphers(self) -> List[str]:
        """
        Get list of supported cipher suites from the server.
        
        Returns:
            List of cipher suite names
        """
        supported_ciphers = []
        
        # Get all available cipher suites
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers('ALL:@SECLEVEL=0')
            
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Get negotiated cipher
                    negotiated = ssock.cipher()
                    if negotiated:
                        supported_ciphers.append(negotiated[0])
                    
                    # Get shared ciphers list
                    shared_ciphers = ssock.shared_ciphers()
                    if shared_ciphers:
                        for cipher, protocol_version, key_exchange_bits in shared_ciphers:
                            if cipher not in supported_ciphers:
                                supported_ciphers.append(cipher)
                    
        except Exception as e:
            logger.error(f"Error getting ciphers: {e}")
        
        # Fallback: Test common cipher suites individually
        if not supported_ciphers:
            supported_ciphers = self._test_individual_ciphers()
        
        return supported_ciphers
    
    def _test_individual_ciphers(self) -> List[str]:
        """Test individual cipher suites."""
        # Modern cipher suites to test
        test_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
            'AES256-SHA256',
            'AES128-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'AES256-SHA',
            'AES128-SHA',
            'DES-CBC3-SHA',
            'RC4-SHA',
            'RC4-MD5',
            'NULL-SHA',
            'NULL-MD5',
            'EXP-RC4-MD5',
            'EXP-DES-CBC-SHA',
        ]
        
        supported = []
        
        for cipher in test_ciphers:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers(cipher)
                
                with socket.create_connection((self.hostname, self.port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        supported.append(cipher)
            except:
                pass
        
        return supported
    
    def _analyze_cipher(self, cipher: str) -> Dict:
        """
        Analyze a cipher suite for weaknesses.
        
        Args:
            cipher: Cipher suite name
        
        Returns:
            Dict with analysis results
        """
        analysis = {
            'cipher': cipher,
            'weak': False,
            'insecure': False,
            'issues': [],
        }
        
        cipher_upper = cipher.upper()
        
        # Check for NULL ciphers
        if 'NULL' in cipher_upper:
            analysis['weak'] = True
            analysis['insecure'] = True
            analysis['issues'].append('NULL encryption (no encryption)')
        
        # Check for anonymous key exchange
        if 'anon' in cipher_upper.lower() or '_DH_' in cipher_upper:
            analysis['weak'] = True
            analysis['insecure'] = True
            analysis['issues'].append('Anonymous key exchange (no authentication)')
        
        # Check for EXPORT ciphers
        if 'EXPORT' in cipher_upper:
            analysis['weak'] = True
            analysis['insecure'] = True
            analysis['issues'].append('EXPORT-grade encryption (intentionally weakened)')
        
        # Check for RC4
        if 'RC4' in cipher_upper:
            analysis['weak'] = True
            analysis['insecure'] = True
            analysis['issues'].append('RC4 stream cipher (cryptographically broken)')
        
        # Check for DES/3DES
        if 'DES' in cipher_upper and '3DES' not in cipher_upper:
            analysis['weak'] = True
            analysis['insecure'] = True
            analysis['issues'].append('Single DES (56-bit, brute-forceable)')
        
        if '3DES' in cipher_upper:
            analysis['weak'] = True
            analysis['issues'].append('Triple DES (slow and weak, Sweet32 attack)')
        
        # Check for weak key exchange
        for weak_kx in self.INSECURE_KEY_EXCHANGE:
            if weak_kx in cipher_upper:
                if not analysis['weak']:
                    analysis['weak'] = True
                analysis['issues'].append(f'Weak key exchange: {weak_kx}')
        
        # Check for weak hash
        for weak_hash in self.WEAK_HASHES:
            if weak_hash in cipher_upper:
                if not analysis['weak']:
                    analysis['weak'] = True
                analysis['issues'].append(f'Weak hash algorithm: {weak_hash}')
        
        return analysis
    
    def _check_forward_secrecy(self, ciphers: List[str]) -> bool:
        """
        Check if any cipher supports Forward Secrecy.
        
        Args:
            ciphers: List of cipher suite names
        
        Returns:
            True if Forward Secrecy is supported
        """
        fs_indicators = ['ECDHE', 'DHE']
        
        for cipher in ciphers:
            cipher_upper = cipher.upper()
            for fs in fs_indicators:
                if fs in cipher_upper:
                    # Ensure it's not anonymous
                    if 'anon' not in cipher_upper.lower():
                        return True
        
        return False