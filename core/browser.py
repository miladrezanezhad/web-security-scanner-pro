#!/usr/bin/env python3
"""
Stealth HTTP Browser Module.
Provides HTTP client functionality with anti-detection capabilities.

Features:
    - Automatic User-Agent rotation
    - Intelligent request throttling
    - Proxy support with rotation
    - Automatic retry with exponential backoff
    - WAF bypass techniques
    - Session management with cookie persistence
    - TLS fingerprint randomization
"""

import time
import random
import logging
from typing import Dict, Optional, Any
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.evasion import EvasionEngine, EvasionConfig, ScanMode

logger = logging.getLogger(__name__)


class StealthBrowser:
    """
    Advanced HTTP client with evasion capabilities.
    
    Provides a browser-like HTTP interface that mimics real user behavior
    to avoid detection by WAFs, rate limiters, and security systems.
    """
    
    def __init__(self, target_url: str, evasion_config: EvasionConfig = None):
        """
        Initialize the stealth browser.
        
        Args:
            target_url: Target URL for all requests
            evasion_config: Evasion engine configuration
        """
        self.target_url = target_url.rstrip('/')
        self.evasion_config = evasion_config or EvasionConfig()
        self.evasion = EvasionEngine(self.evasion_config)
        self.session = self._create_session()
        
        # Statistics tracking
        self.stats = {
            "requests_sent": 0,
            "requests_successful": 0,
            "requests_failed": 0,
            "requests_blocked": 0,
            "requests_retried": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "start_time": time.time(),
        }
        
        # Request history for pattern analysis
        self.request_history = []
        
        logger.info(f"StealthBrowser initialized for {target_url}")
    
    def _create_session(self) -> requests.Session:
        """
        Create a requests Session with optimal settings.
        
        Returns:
            Configured requests.Session object
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=0,  # We handle retries ourselves for more control
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            backoff_factor=0.5
        )
        
        # Configure connection adapter
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=30,
            pool_block=True
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Default settings
        session.verify = False
        session.allow_redirects = True
        session.max_redirects = 5
        
        # Suppress SSL warnings for scanning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        return session
    
    def get(
        self,
        path: str = '/',
        params: Dict = None,
        custom_headers: Dict = None,
        use_evasion: bool = True,
        timeout: int = 30
    ) -> Optional[requests.Response]:
        """
        Send GET request with evasion techniques.
        
        Args:
            path: URL path (appended to target_url)
            params: Query parameters dictionary
            custom_headers: Additional headers to include
            use_evasion: Whether to apply evasion techniques
            timeout: Request timeout in seconds
        
        Returns:
            Response object or None on failure
        """
        url = self._build_url(path)
        
        # Apply rate limiting delay
        if use_evasion:
            self.evasion.apply_delay()
        
        # Build headers
        headers = {}
        if use_evasion:
            headers = self.evasion.get_stealth_headers(path)
        if custom_headers:
            headers.update(custom_headers)
        
        # Get proxy if configured
        proxies = None
        if use_evasion and self.evasion.proxies:
            proxies = self.evasion.get_next_proxy()
        
        # Send request with retry logic
        for attempt in range(self.evasion_config.max_retries + 1):
            try:
                start_time = time.time()
                response = self.session.get(
                    url,
                    headers=headers,
                    params=params,
                    proxies=proxies,
                    timeout=timeout,
                    allow_redirects=True
                )
                elapsed = time.time() - start_time
                
                self.stats["requests_sent"] += 1
                self.stats["bytes_received"] += len(response.content)
                
                # Track request
                self.request_history.append({
                    'method': 'GET',
                    'path': path,
                    'status': response.status_code,
                    'time': elapsed,
                    'size': len(response.content),
                })
                
                # Trim history if too large
                if len(self.request_history) > 100:
                    self.request_history = self.request_history[-50:]
                
                # Check if blocked
                if use_evasion and self.evasion.is_blocked(response):
                    self.stats["requests_blocked"] += 1
                    logger.warning(f"Request blocked (attempt {attempt + 1}): {path}")
                    
                    # Detect WAF and captcha
                    self.evasion.detect_waf(response)
                    self.evasion.detect_captcha(response)
                    
                    if attempt < self.evasion_config.max_retries:
                        delay = self.evasion.calculate_backoff(attempt + 1)
                        logger.info(f"Retrying in {delay:.1f}s...")
                        time.sleep(delay)
                        self.stats["requests_retried"] += 1
                        
                        # Rotate identity on retry
                        if use_evasion:
                            headers = self.evasion.get_stealth_headers(path)
                        if proxies and len(self.evasion.proxies) > 1:
                            proxies = self.evasion.get_next_proxy()
                        
                        continue
                    else:
                        logger.error(f"Max retries exceeded for {path}")
                        return response
                
                self.stats["requests_successful"] += 1
                return response
                
            except requests.ConnectionError as e:
                logger.error(f"Connection error: {e}")
                if attempt < self.evasion_config.max_retries:
                    time.sleep(self.evasion.calculate_backoff(attempt + 1))
                    continue
                self.stats["requests_failed"] += 1
                return None
                
            except requests.Timeout as e:
                logger.error(f"Timeout: {e}")
                if attempt < self.evasion_config.max_retries:
                    continue
                self.stats["requests_failed"] += 1
                return None
                
            except requests.RequestException as e:
                logger.error(f"Request failed: {e}")
                if attempt < self.evasion_config.max_retries:
                    time.sleep(self.evasion.calculate_backoff(attempt + 1))
                    continue
                self.stats["requests_failed"] += 1
                return None
        
        return None
    
    def post(
        self,
        path: str = '/',
        data: Dict = None,
        json: Dict = None,
        files: Dict = None,
        custom_headers: Dict = None,
        use_evasion: bool = True,
        timeout: int = 30
    ) -> Optional[requests.Response]:
        """
        Send POST request with evasion techniques.
        
        Args:
            path: URL path
            data: Form data dictionary
            json: JSON data dictionary
            files: Files dictionary for multipart upload
            custom_headers: Additional headers
            use_evasion: Whether to apply evasion
            timeout: Request timeout
        
        Returns:
            Response object or None on failure
        """
        url = self._build_url(path)
        
        if use_evasion:
            self.evasion.apply_delay()
        
        headers = {}
        if use_evasion:
            headers = self.evasion.get_stealth_headers(path)
        if custom_headers:
            headers.update(custom_headers)
        
        proxies = None
        if use_evasion and self.evasion.proxies:
            proxies = self.evasion.get_next_proxy()
        
        try:
            response = self.session.post(
                url,
                headers=headers,
                data=data,
                json=json,
                files=files,
                proxies=proxies,
                timeout=timeout
            )
            
            self.stats["requests_sent"] += 1
            if response.status_code < 400:
                self.stats["requests_successful"] += 1
            else:
                self.stats["requests_blocked"] += 1
            
            self.stats["bytes_received"] += len(response.content)
            
            return response
            
        except requests.RequestException as e:
            logger.error(f"POST request failed: {e}")
            self.stats["requests_failed"] += 1
            return None
    
    def head(
        self,
        path: str = '/',
        timeout: int = 10
    ) -> Optional[requests.Response]:
        """
        Send HEAD request for lightweight checks.
        
        Args:
            path: URL path
            timeout: Request timeout
        
        Returns:
            Response object or None
        """
        url = self._build_url(path)
        
        try:
            response = self.session.head(url, timeout=timeout, allow_redirects=True)
            self.stats["requests_sent"] += 1
            return response
        except requests.RequestException:
            return None
    
    def options(
        self,
        path: str = '/',
        timeout: int = 10
    ) -> Optional[requests.Response]:
        """
        Send OPTIONS request to check allowed methods.
        
        Args:
            path: URL path
            timeout: Request timeout
        
        Returns:
            Response object or None
        """
        url = self._build_url(path)
        
        try:
            response = self.session.options(url, timeout=timeout)
            self.stats["requests_sent"] += 1
            return response
        except requests.RequestException:
            return None
    
    def _build_url(self, path: str) -> str:
        """
        Build full URL from path.
        
        Args:
            path: URL path
        
        Returns:
            Full URL string
        """
        if path.startswith('http'):
            return path
        if path.startswith(':'):
            # Port-only path (e.g., ':8443')
            parsed = __import__('urllib.parse').urlparse(self.target_url)
            return f"{parsed.scheme}://{parsed.hostname}{path}"
        return urljoin(self.target_url, path)
    
    def reset_session(self):
        """Reset the HTTP session to clear cookies and cache."""
        self.session.close()
        self.session = self._create_session()
        logger.info("Session reset")
    
    def add_proxy(self, proxy_url: str):
        """
        Add a proxy to the rotation pool.
        
        Args:
            proxy_url: Proxy URL (e.g., 'http://user:pass@host:port')
        """
        self.evasion.add_proxy(proxy_url)
    
    def load_proxies_from_file(self, filepath: str):
        """
        Load proxies from a file (one per line).
        
        Args:
            filepath: Path to proxy list file
        """
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    proxy = line.strip()
                    if proxy and not proxy.startswith('#'):
                        self.evasion.add_proxy(proxy)
            logger.info(f"Loaded proxies from {filepath}")
        except FileNotFoundError:
            logger.warning(f"Proxy file not found: {filepath}")
    
    def get_stats(self) -> Dict:
        """
        Get browser statistics.
        
        Returns:
            Dictionary with request statistics
        """
        elapsed = time.time() - self.stats["start_time"]
        stats = {
            **self.stats,
            "elapsed_seconds": round(elapsed, 1),
            "requests_per_second": round(self.stats["requests_sent"] / max(elapsed, 1), 2),
            "success_rate": round(
                self.stats["requests_successful"] / max(self.stats["requests_sent"], 1) * 100, 1
            ),
            "block_rate": round(
                self.stats["requests_blocked"] / max(self.stats["requests_sent"], 1) * 100, 1
            ),
            "evasion_stats": self.evasion.get_stats(),
        }
        return stats
    
    def close(self):
        """Close the browser session cleanly."""
        self.session.close()
        logger.info("Browser session closed")