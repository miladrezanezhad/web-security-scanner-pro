#!/usr/bin/env python3
"""
SSL/TLS Certificate Analysis Module.
Analyzes SSL certificates for security issues.

References:
    - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
    - SSL Labs: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
"""

import ssl
import socket
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse
from loguru import logger

try:
    import cryptography
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logger.warning("cryptography module not available. Install with: pip install cryptography")


class Scanner:
    """SSL/TLS Certificate security scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize certificate scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "SSL/TLS Certificate Analysis"
        
        # Parse hostname from URL
        parsed = urlparse(target_url)
        self.hostname = parsed.hostname
        self.port = parsed.port or 443
        
        # Certificate grade thresholds
        self.grade_thresholds = {
            'A+': 95,
            'A': 90,
            'B': 80,
            'C': 70,
            'D': 60,
            'F': 0,
        }
    
    def run(self) -> Dict:
        """
        Execute SSL/TLS certificate analysis.
        
        Returns:
            Dict with findings and certificate analysis
        """
        logger.info(f"Starting {self.module_name} for {self.hostname}:{self.port}")
        
        result = {
            'module': self.module_name,
            'hostname': self.hostname,
            'port': self.port,
            'certificate': None,
            'issues': [],
            'grade': None,
            'score': 100,
            'findings': []
        }
        
        # Get certificate
        cert_info = self._get_certificate()
        
        if not cert_info:
            self.findings.append({
                'title': 'Unable to retrieve SSL/TLS certificate',
                'severity': 'high',
                'description': f"Could not establish SSL/TLS connection to {self.hostname}:{self.port}",
                'recommendation': "Ensure the server is properly configured for HTTPS",
                'module': self.module_name,
            })
            result['findings'] = self.findings
            return result
        
        result['certificate'] = cert_info
        
        # Analyze certificate
        issues = self._analyze_certificate(cert_info)
        result['issues'] = issues
        
        # Calculate score
        score_deductions = sum(issue.get('score_impact', 0) for issue in issues)
        result['score'] = max(0, 100 - score_deductions)
        
        # Calculate grade
        result['grade'] = self._calculate_grade(result['score'])
        
        # Generate findings
        for issue in issues:
            self.findings.append({
                'title': issue['title'],
                'severity': issue['severity'],
                'description': issue['description'],
                'recommendation': issue['recommendation'],
                'module': self.module_name,
                'evidence': issue.get('evidence'),
            })
        
        # Overall assessment
        if result['score'] >= 90:
            severity = 'info'
            title = f"SSL/TLS Certificate Grade: {result['grade']} (Good)"
        elif result['score'] >= 70:
            severity = 'medium'
            title = f"SSL/TLS Certificate Grade: {result['grade']} (Needs Improvement)"
        else:
            severity = 'high'
            title = f"SSL/TLS Certificate Grade: {result['grade']} (Poor)"
        
        self.findings.append({
            'title': title,
            'severity': severity,
            'description': f"Overall SSL/TLS certificate score: {result['score']}/100. Grade: {result['grade']}",
            'recommendation': "Address the identified certificate issues to improve security",
            'module': self.module_name,
            'cvss_score': 7.5 if severity == 'high' else 5.0 if severity == 'medium' else 0,
        })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Grade: {result['grade']}, Score: {result['score']}")
        return result
    
    def _get_certificate(self) -> Optional[Dict]:
        """
        Retrieve SSL/TLS certificate from the target.
        
        Returns:
            Dict with certificate details or None
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    if not cert_bin:
                        return None
                    
                    # Build certificate info
                    cert_info = {
                        'subject': dict(x[0] for x in cert_dict.get('subject', [])),
                        'issuer': dict(x[0] for x in cert_dict.get('issuer', [])),
                        'version': cert_dict.get('version', 0),
                        'serial_number': cert_dict.get('serialNumber', ''),
                        'not_before': cert_dict.get('notBefore', ''),
                        'not_after': cert_dict.get('notAfter', ''),
                        'subject_alt_names': [],
                        'signature_algorithm': None,
                        'key_size': None,
                        'hash_algorithm': None,
                        'is_self_signed': False,
                        'is_expired': False,
                        'is_wildcard': False,
                        'days_until_expiry': 0,
                    }
                    
                    # Parse dates
                    if cert_info['not_before']:
                        cert_info['not_before'] = self._parse_ssl_date(cert_info['not_before'])
                    if cert_info['not_after']:
                        cert_info['not_after'] = self._parse_ssl_date(cert_info['not_after'])
                    
                    # Calculate days until expiry
                    if isinstance(cert_info['not_after'], datetime):
                        cert_info['days_until_expiry'] = (
                            cert_info['not_after'] - datetime.now()
                        ).days
                        
                        if cert_info['days_until_expiry'] < 0:
                            cert_info['is_expired'] = True
                    
                    # Extract Subject Alternative Names
                    if 'subjectAltName' in cert_dict:
                        san_list = cert_dict['subjectAltName']
                        cert_info['subject_alt_names'] = [
                            name for _, name in san_list
                        ]
                    
                    # Check wildcard
                    cert_info['is_wildcard'] = any(
                        name.startswith('*.') for name in cert_info['subject_alt_names']
                    )
                    
                    # Check self-signed
                    if cert_info['subject'] == cert_info['issuer']:
                        cert_info['is_self_signed'] = True
                    
                    # Analyze with cryptography library if available
                    if CRYPTOGRAPHY_AVAILABLE and cert_bin:
                        try:
                            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                            
                            # Get signature algorithm
                            cert_info['signature_algorithm'] = cert.signature_algorithm_oid._name
                            
                            # Get public key size
                            public_key = cert.public_key()
                            if hasattr(public_key, 'key_size'):
                                cert_info['key_size'] = public_key.key_size
                            
                            # Get hash algorithm
                            if hasattr(cert.signature_hash_algorithm, 'name'):
                                cert_info['hash_algorithm'] = cert.signature_hash_algorithm.name
                            
                            # Get fingerprint
                            fingerprint = cert.fingerprint(hashes.SHA256())
                            cert_info['sha256_fingerprint'] = fingerprint.hex()
                            
                            # Get full SAN list from cryptography
                            try:
                                san_ext = cert.extensions.get_extension_for_class(
                                    x509.SubjectAlternativeName
                                )
                                cert_info['subject_alt_names'] = san_ext.value.get_values_for_type(x509.DNSName)
                            except x509.ExtensionNotFound:
                                pass
                            
                        except Exception as e:
                            logger.debug(f"Cryptography analysis error: {e}")
                    
                    return cert_info
                    
        except ssl.SSLError as e:
            logger.error(f"SSL error: {e}")
            return None
        except socket.error as e:
            logger.error(f"Socket error: {e}")
            return None
        except Exception as e:
            logger.error(f"Certificate retrieval error: {e}")
            return None
    
    def _parse_ssl_date(self, date_str: str) -> Optional[datetime]:
        """Parse SSL date format to datetime."""
        if not date_str:
            return None
        
        # SSL dates are in format: 'Dec 31 23:59:59 2024 GMT'
        try:
            from datetime import datetime
            return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
        except ValueError:
            try:
                return datetime.strptime(date_str, '%b %d %H:%M:%S %Y')
            except ValueError:
                return None
    
    def _analyze_certificate(self, cert_info: Dict) -> List[Dict]:
        """
        Analyze certificate for security issues.
        
        Args:
            cert_info: Certificate information dictionary
        
        Returns:
            List of issues found
        """
        issues = []
        score_deduction = 0
        
        # Check 1: Certificate expiry
        if cert_info.get('is_expired'):
            issues.append({
                'title': 'SSL Certificate has expired',
                'severity': 'critical',
                'description': f"Certificate expired on {cert_info['not_after']}",
                'recommendation': "Renew the SSL certificate immediately",
                'score_impact': 40,
                'evidence': f"Expiry date: {cert_info['not_after']}",
            })
        elif cert_info.get('days_until_expiry', 0) < 30:
            days = cert_info['days_until_expiry']
            issues.append({
                'title': f'SSL Certificate expires in {days} days',
                'severity': 'high' if days < 7 else 'medium',
                'description': f"Certificate will expire on {cert_info['not_after']} ({days} days remaining)",
                'recommendation': "Renew the certificate before it expires to prevent service disruption",
                'score_impact': 15 if days < 7 else 5,
                'evidence': f"Expiry date: {cert_info['not_after']}, Days remaining: {days}",
            })
        
        # Check 2: Self-signed certificate
        if cert_info.get('is_self_signed'):
            issues.append({
                'title': 'Self-signed certificate detected',
                'severity': 'high',
                'description': "The certificate is self-signed and not trusted by browsers",
                'recommendation': "Obtain a certificate from a trusted Certificate Authority (e.g., Let's Encrypt)",
                'score_impact': 20,
                'evidence': 'Subject and Issuer are identical',
            })
        
        # Check 3: Weak signature algorithm
        sig_alg = cert_info.get('signature_algorithm', '').lower()
        weak_sig_algos = ['md5', 'sha1', 'md2', 'md4']
        
        for weak_algo in weak_sig_algos:
            if weak_algo in sig_alg:
                issues.append({
                    'title': f'Weak signature algorithm: {sig_alg}',
                    'severity': 'high' if weak_algo in ['md5', 'md2', 'md4'] else 'medium',
                    'description': f"Certificate uses {sig_alg} which is considered cryptographically broken",
                    'recommendation': f"Obtain a new certificate using SHA-256 or stronger signature algorithm",
                    'score_impact': 10,
                    'evidence': f"Signature algorithm: {sig_alg}",
                })
                break
        
        # Check 4: Weak key size
        key_size = cert_info.get('key_size', 0)
        if key_size and key_size < 2048:
            issues.append({
                'title': f'Weak key size: {key_size} bits',
                'severity': 'high' if key_size < 1024 else 'medium',
                'description': f"RSA key size of {key_size} bits is insufficient for modern security",
                'recommendation': "Generate a new certificate with at least 2048-bit key (4096-bit recommended)",
                'score_impact': 15 if key_size < 1024 else 8,
                'evidence': f"Key size: {key_size} bits",
            })
        
        # Check 5: Wildcard certificate risks
        if cert_info.get('is_wildcard'):
            issues.append({
                'title': 'Wildcard certificate in use',
                'severity': 'low',
                'description': "Wildcard certificates (*.example.com) can increase risk if the private key is compromised",
                'recommendation': "Consider using specific certificates or monitor wildcard certificate usage closely",
                'score_impact': 2,
                'evidence': 'Certificate contains wildcard domain',
            })
        
        # Check 6: Missing Subject Alternative Names
        if not cert_info.get('subject_alt_names'):
            issues.append({
                'title': 'No Subject Alternative Names (SAN)',
                'severity': 'low',
                'description': "Certificate does not include Subject Alternative Names",
                'recommendation': "Include relevant domain names in the SAN extension",
                'score_impact': 3,
                'evidence': 'SAN list is empty',
            })
        
        # Check 7: Hostname mismatch
        if cert_info.get('subject_alt_names') and self.hostname:
            if self.hostname not in cert_info['subject_alt_names']:
                # Check wildcard match
                matched = False
                for san in cert_info['subject_alt_names']:
                    if san.startswith('*.'):
                        base_domain = san[2:]
                        if self.hostname.endswith(base_domain):
                            matched = True
                            break
                
                if not matched:
                    issues.append({
                        'title': 'Hostname mismatch',
                        'severity': 'high',
                        'description': f"Certificate does not include {self.hostname} in Subject Alternative Names",
                        'recommendation': "Obtain a certificate that includes this hostname",
                        'score_impact': 15,
                        'evidence': f"SANs: {cert_info['subject_alt_names']}",
                    })
        
        return issues
    
    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade from score."""
        for grade, threshold in sorted(
            self.grade_thresholds.items(), 
            key=lambda x: x[1], 
            reverse=True
        ):
            if score >= threshold:
                return grade
        
        return 'F'