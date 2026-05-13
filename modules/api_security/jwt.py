#!/usr/bin/env python3
"""
JWT (JSON Web Token) Security Analyzer Module.
Tests for common JWT security vulnerabilities and misconfigurations.

References:
    - OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
    - JWT.io: https://jwt.io/
    - RFC 7519: JSON Web Token (JWT)
"""

import re
import json
import base64
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from loguru import logger


class Scanner:
    """JWT security vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize JWT scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "JWT Security Analysis"
        
        # Common JWT header names in requests
        self.jwt_headers = [
            'Authorization',
            'Bearer',
            'JWT',
            'X-JWT',
            'X-Auth-Token',
            'X-Access-Token',
            'Token',
            'Auth',
        ]
        
        # Common JWT locations in responses
        self.jwt_response_locations = [
            'token',
            'access_token',
            'accessToken',
            'jwt',
            'id_token',
            'idToken',
            'refresh_token',
            'refreshToken',
            'auth_token',
            'authToken',
        ]
        
        # JWT algorithm types
        self.jwt_algorithms = {
            'HS256': 'HMAC with SHA-256',
            'HS384': 'HMAC with SHA-384',
            'HS512': 'HMAC with SHA-512',
            'RS256': 'RSA with SHA-256',
            'RS384': 'RSA with SHA-384',
            'RS512': 'RSA with SHA-512',
            'ES256': 'ECDSA with SHA-256',
            'ES384': 'ECDSA with SHA-384',
            'ES512': 'ECDSA with SHA-512',
            'PS256': 'RSASSA-PSS with SHA-256',
            'PS384': 'RSASSA-PSS with SHA-384',
            'PS512': 'RSASSA-PSS with SHA-512',
            'none': 'No signature (INSECURE)',
        }
        
        # Common secret keys for testing
        self.test_secrets = [
            'secret',
            'password',
            'key',
            'secretkey',
            'privatekey',
            'changeme',
            'admin',
            'test',
            'jwt_secret',
            'my_secret_key',
            'super_secret',
        ]
    
    def run(self) -> Dict:
        """
        Execute JWT security tests.
        
        Returns:
            Dict with findings and comprehensive analysis results
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'jwt_detected': False,
            'jwt_tokens_found': [],
            'algorithm': None,
            'token_structure': {},
            'weak_secret_detected': False,
            'none_algorithm_accepted': False,
            'missing_expiration': False,
            'sensitive_data_in_token': [],
            'findings': []
        }
        
        # Stage 1: Discover JWT tokens in responses
        tokens = self._discover_jwt_tokens()
        
        if not tokens:
            result['findings'].append({
                'title': 'No JWT tokens detected',
                'severity': 'info',
                'description': 'No JWT tokens were found in API responses or authentication endpoints.',
                'recommendation': 'If JWT is in use, verify token handling configuration.',
                'module': self.module_name,
            })
            return result
        
        result['jwt_detected'] = True
        result['jwt_tokens_found'] = tokens
        
        # Analyze each token
        for token_info in tokens:
            token_analysis = self._analyze_token(token_info['token'])
            
            if token_analysis['valid_jwt']:
                result['algorithm'] = token_analysis.get('algorithm')
                result['token_structure'] = token_analysis
                
                # Check for 'none' algorithm
                if token_analysis.get('algorithm') == 'none':
                    result['none_algorithm_accepted'] = True
                    result['findings'].append({
                        'title': 'JWT using "none" algorithm detected',
                        'severity': 'critical',
                        'description': (
                            f"A JWT token using the 'none' algorithm was found at "
                            f"{token_info['location']}. The 'none' algorithm means no "
                            "signature verification is performed, allowing attackers to "
                            "forge tokens with arbitrary claims."
                        ),
                        'recommendation': (
                            "1. Immediately update JWT library to reject 'none' algorithm\n"
                            "2. Explicitly specify allowed algorithms in JWT verification\n"
                            "3. Update: jwt.verify(token, secret, { algorithms: ['HS256'] })\n"
                            "4. Audit all JWT validation code\n"
                            "5. Rotate all existing tokens"
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-345',
                        'cvss_score': 10.0,
                        'evidence': f"Token with 'none' algorithm at: {token_info['location']}",
                        'references': [
                            'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
                        ]
                    })
                
                # Check for weak HMAC secret
                if token_analysis.get('algorithm', '').startswith('HS'):
                    weak_result = self._test_weak_secret(token_info['token'])
                    if weak_result['cracked']:
                        result['weak_secret_detected'] = True
                        result['findings'].append({
                            'title': f"JWT signed with weak secret key: '{weak_result['secret']}'",
                            'severity': 'critical',
                            'description': (
                                f"The JWT token uses a weak HMAC secret key: '{weak_result['secret']}'. "
                                "This allows attackers to forge valid tokens with arbitrary claims "
                                "including admin privileges."
                            ),
                            'recommendation': (
                                "1. Use a strong, randomly generated secret (at least 256 bits)\n"
                                "2. Generate secrets using: openssl rand -base64 32\n"
                                "3. Store secrets in environment variables, not in code\n"
                                "4. Rotate all existing tokens immediately\n"
                                "5. Use asymmetric algorithms (RS256/ES256) instead of HMAC"
                            ),
                            'module': self.module_name,
                            'cwe_id': 'CWE-327',
                            'cvss_score': 9.8,
                            'evidence': f"Weak secret found: '{weak_result['secret']}'",
                        })
                
                # Check for missing expiration
                payload = token_analysis.get('payload', {})
                if 'exp' not in payload:
                    result['missing_expiration'] = True
                    result['findings'].append({
                        'title': 'JWT token missing expiration claim (exp)',
                        'severity': 'medium',
                        'description': (
                            "The JWT token does not include an expiration ('exp') claim. "
                            "Without expiration, tokens remain valid indefinitely, increasing "
                            "the risk if a token is compromised."
                        ),
                        'recommendation': (
                            "1. Always include 'exp' claim with a short expiration time\n"
                            "2. Recommended expiration: 15 minutes for access tokens\n"
                            "3. Use refresh tokens for longer sessions\n"
                            "4. Implement token revocation/blacklisting"
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-613',
                        'cvss_score': 4.0,
                        'evidence': 'No "exp" claim in token payload',
                    })
                
                # Check for sensitive data in token payload
                sensitive_claims = self._check_sensitive_claims(payload)
                if sensitive_claims:
                    result['sensitive_data_in_token'] = sensitive_claims
                    result['findings'].append({
                        'title': f"Sensitive data exposed in JWT payload: {', '.join(sensitive_claims)}",
                        'severity': 'high',
                        'description': (
                            f"The JWT payload contains sensitive information: "
                            f"{', '.join(sensitive_claims)}. JWT payloads are base64-encoded, "
                            "not encrypted. Anyone with the token can decode and read the payload."
                        ),
                        'recommendation': (
                            "1. Never store sensitive data in JWT payload\n"
                            "2. Store only minimal claims (sub, exp, iat)\n"
                            "3. Use server-side lookup for sensitive user data\n"
                            "4. If sensitive data must be in token, use JWE (encrypted tokens)\n"
                            "5. Implement token binding to prevent token reuse"
                        ),
                        'module': self.module_name,
                        'cwe_id': 'CWE-312',
                        'cvss_score': 7.5,
                        'evidence': f"Sensitive claims: {sensitive_claims}",
                    })
        
        result['findings'] = self.findings
        
        logger.info(
            f"{self.module_name} complete. "
            f"Tokens found: {len(tokens)}, "
            f"Findings: {len(self.findings)}"
        )
        return result
    
    def _discover_jwt_tokens(self) -> List[Dict]:
        """
        Discover JWT tokens in API responses and cookies.
        
        Returns:
            List of discovered token information
        """
        tokens = []
        
        # Check common API endpoints for JWT in responses
        api_paths = [
            '/api/login',
            '/api/auth/login',
            '/api/auth/token',
            '/auth/login',
            '/login',
            '/api/v1/auth',
            '/oauth/token',
            '/token',
        ]
        
        for path in api_paths:
            resp = self.browser.get(path)
            if not resp or resp.status_code not in [200, 201]:
                continue
            
            # Check response body for JWT patterns
            jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
            matches = re.findall(jwt_pattern, resp.text)
            
            for match in matches:
                tokens.append({
                    'token': match,
                    'location': f"Response body at {path}",
                    'type': 'response_body',
                })
            
            # Check for JWT in JSON response
            try:
                data = json.loads(resp.text)
                for key in self.jwt_response_locations:
                    if key in data:
                        token_value = str(data[key])
                        if re.match(jwt_pattern, token_value):
                            tokens.append({
                                'token': token_value,
                                'location': f"JSON key '{key}' at {path}",
                                'type': 'json_response',
                            })
            except:
                pass
            
            # Check Set-Cookie headers
            set_cookie = resp.headers.get('Set-Cookie', '')
            cookie_matches = re.findall(jwt_pattern, set_cookie)
            for match in cookie_matches:
                tokens.append({
                    'token': match,
                    'location': f"Cookie at {path}",
                    'type': 'cookie',
                })
        
        # Check Authorization header in responses (unusual but possible)
        resp = self.browser.get('/')
        if resp:
            auth_header = resp.headers.get('Authorization', '')
            jwt_matches = re.findall(jwt_pattern, auth_header)
            for match in jwt_matches:
                tokens.append({
                    'token': match,
                    'location': 'Authorization response header',
                    'type': 'response_header',
                })
        
        return tokens[:10]  # Limit to 10 tokens
    
    def _analyze_token(self, token: str) -> Dict:
        """
        Analyze a JWT token structure.
        
        Args:
            token: JWT token string
        
        Returns:
            Dict with token analysis
        """
        analysis = {
            'valid_jwt': False,
            'header': {},
            'payload': {},
            'algorithm': None,
            'signature': '',
            'parts_count': 0,
        }
        
        # Split token into parts
        parts = token.split('.')
        analysis['parts_count'] = len(parts)
        
        if len(parts) < 2:
            return analysis
        
        # Decode header
        try:
            header_bytes = parts[0]
            # Add padding if needed
            padding = 4 - len(header_bytes) % 4
            if padding != 4:
                header_bytes += '=' * padding
            
            header_json = base64.urlsafe_b64decode(header_bytes).decode('utf-8')
            analysis['header'] = json.loads(header_json)
            analysis['algorithm'] = analysis['header'].get('alg', 'unknown')
            analysis['valid_jwt'] = True
        except Exception as e:
            logger.debug(f"JWT header decode error: {e}")
            return analysis
        
        # Decode payload
        try:
            payload_bytes = parts[1]
            padding = 4 - len(payload_bytes) % 4
            if padding != 4:
                payload_bytes += '=' * padding
            
            payload_json = base64.urlsafe_b64decode(payload_bytes).decode('utf-8')
            analysis['payload'] = json.loads(payload_json)
        except Exception as e:
            logger.debug(f"JWT payload decode error: {e}")
        
        # Store signature
        if len(parts) == 3:
            analysis['signature'] = parts[2]
        
        return analysis
    
    def _test_weak_secret(self, token: str) -> Dict:
        """
        Test if JWT is signed with a weak/guessable secret.
        
        Args:
            token: JWT token string
        
        Returns:
            Dict with weak secret test results
        """
        result = {
            'cracked': False,
            'secret': None,
        }
        
        parts = token.split('.')
        if len(parts) != 3:
            return result
        
        header_b64 = parts[0]
        payload_b64 = parts[1]
        signature = parts[2]
        
        # Get algorithm from header
        try:
            header_bytes = header_b64
            padding = 4 - len(header_bytes) % 4
            if padding != 4:
                header_bytes += '=' * padding
            header = json.loads(base64.urlsafe_b64decode(header_bytes))
            algorithm = header.get('alg', 'HS256')
        except:
            return result
        
        if not algorithm.startswith('HS'):
            return result
        
        # Map algorithm to hashlib function
        hash_map = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }
        
        hash_func = hash_map.get(algorithm, hashlib.sha256)
        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        
        # Try common secrets
        for secret in self.test_secrets:
            computed_signature = hmac.new(
                secret.encode('utf-8'),
                message,
                hash_func
            ).digest()
            
            computed_b64 = base64.urlsafe_b64encode(computed_signature).rstrip(b'=').decode('utf-8')
            
            if computed_b64 == signature:
                result['cracked'] = True
                result['secret'] = secret
                break
        
        return result
    
    def _check_sensitive_claims(self, payload: Dict) -> List[str]:
        """
        Check for sensitive data in JWT payload.
        
        Args:
            payload: Decoded JWT payload
        
        Returns:
            List of sensitive claim names found
        """
        sensitive_keywords = [
            'password', 'passwd', 'pwd', 'pass',
            'secret', 'apikey', 'api_key',
            'creditcard', 'credit_card', 'cc',
            'ssn', 'socialsecurity',
            'pin', 'cvv',
            'token', 'privatekey',
            'role', 'permissions', 'isAdmin',
        ]
        
        sensitive_found = []
        
        for key, value in payload.items():
            key_lower = key.lower()
            for keyword in sensitive_keywords:
                if keyword in key_lower:
                    sensitive_found.append(key)
                    break
        
        return sensitive_found