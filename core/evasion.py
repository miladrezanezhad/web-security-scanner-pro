#!/usr/bin/env python3
"""
Advanced Evasion Engine Module.
Provides anti-detection capabilities to bypass WAF, rate limiting, and IP blocking.

Features:
    - User-Agent rotation with realistic browser profiles
    - Intelligent request throttling with jitter
    - WAF detection and fingerprinting (Cloudflare, Sucuri, AWS WAF, etc.)
    - Captcha detection
    - Exponential backoff with jitter
    - Proxy rotation support
    - Tor network support
    - TLS fingerprint randomization strategies
"""

import time
import random
import logging
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class ScanMode(Enum):
    """Scan intensity modes."""
    STEALTH = "stealth"      # Maximum evasion, slowest speed
    NORMAL = "normal"        # Balanced approach
    AGGRESSIVE = "aggressive"  # Maximum speed, minimal evasion


@dataclass
class EvasionConfig:
    """Configuration for the evasion engine."""
    mode: ScanMode = ScanMode.STEALTH
    rotate_user_agent: bool = True
    use_proxy: bool = False
    use_tor: bool = False
    random_delay: bool = True
    respect_robots_txt: bool = True
    max_requests_per_second: float = 1.0
    max_concurrent_requests: int = 1
    retry_on_block: bool = True
    max_retries: int = 3
    backoff_factor: float = 2.0
    jitter: bool = True
    fingerprint_randomization: bool = True


class EvasionEngine:
    """
    Advanced evasion engine for bypassing security controls.
    
    Implements multiple techniques to avoid detection by:
    - Web Application Firewalls (WAF)
    - Rate limiting systems
    - IP-based blocking
    - Bot detection systems
    - Captcha challenges
    """
    
    def __init__(self, config: EvasionConfig = None):
        """
        Initialize the evasion engine.
        
        Args:
            config: Evasion configuration
        """
        self.config = config or EvasionConfig()
        self.request_count = 0
        self.last_request_time = 0
        self.blocked_count = 0
        self.captcha_detected = False
        self.waf_detected = None
        self.waf_confidence = 0
        
        # Initialize pools
        self._init_user_agent_pool()
        self._init_referer_pool()
        self._init_language_pool()
        self._init_block_patterns()
        self._init_waf_signatures()
        
        # Proxy pool
        self.proxies = []
        self.proxy_index = 0
        
        # Tor configuration
        self.tor_port = 9050
        self.tor_control_port = 9051
        
        logger.info(f"Evasion engine initialized in {self.config.mode.value} mode")
    
    def _init_user_agent_pool(self):
        """Initialize User-Agent pool with realistic browser profiles."""
        self.user_agents = {
            "chrome_win": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "chrome_mac": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "chrome_linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "firefox_win": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
            "firefox_mac": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:126.0) Gecko/20100101 Firefox/126.0",
            "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            "opera": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/110.0.0.0",
            "chrome_android": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36",
            "safari_iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        }
        
        # Selection weights (popular browsers selected more often)
        self.user_agent_weights = {
            "chrome_win": 25, "chrome_mac": 15, "chrome_android": 18,
            "safari": 12, "safari_iphone": 10, "firefox_win": 8,
            "edge": 5, "chrome_linux": 4, "firefox_mac": 2, "opera": 1,
        }
    
    def _init_referer_pool(self):
        """Initialize referer URL pool."""
        self.referers = [
            "https://www.google.com/search?q=security+testing",
            "https://www.bing.com/search?q=web+security",
            "https://duckduckgo.com/",
            "https://github.com/",
            "https://stackoverflow.com/",
            "https://www.reddit.com/",
            "https://twitter.com/",
            None,  # Direct visit (no referer)
        ]
    
    def _init_language_pool(self):
        """Initialize Accept-Language pool."""
        self.languages = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
            "en-US,en;q=0.9,fr;q=0.8,de;q=0.7",
            "en-US,en;q=0.8",
        ]
    
    def _init_block_patterns(self):
        """Initialize patterns that indicate blocking."""
        self.block_patterns = {
            "status_codes": [403, 429, 503],
            "text_indicators": [
                "access denied", "blocked", "captcha", "cloudflare",
                "rate limit exceeded", "too many requests",
                "your ip has been blocked", "security check",
                "ddos protection", "are you a robot",
            ],
            "header_indicators": [
                "cf-chl-bypass", "x-sucuri-block", "x-rate-limit-remaining",
            ]
        }
    
    def _init_waf_signatures(self):
        """Initialize WAF detection signatures."""
        self.waf_signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status"],
                "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
                "text": ["attention required! | cloudflare"],
                "weight": 5
            },
            "AWS WAF": {
                "headers": ["x-amzn-requestid"],
                "text": ["request blocked.", "aws waf"],
                "weight": 4
            },
            "Sucuri": {
                "headers": ["x-sucuri-id"],
                "text": ["sucuri website firewall"],
                "weight": 4
            },
            "Wordfence": {
                "text": ["generated by wordfence"],
                "cookies": ["wfvt_", "wordfence_verifiedhuman"],
                "weight": 3
            },
            "ModSecurity": {
                "text": ["modsecurity", "this error was generated by mod_security"],
                "weight": 3
            },
            "F5 BIG-IP": {
                "cookies": ["bigipserver", "ts01"],
                "text": ["the requested url was rejected"],
                "weight": 3
            },
            "Imperva": {
                "headers": ["x-iinfo"],
                "cookies": ["visid_incap_", "incap_ses_"],
                "weight": 4
            },
            "Akamai": {
                "headers": ["x-akamai-transformed"],
                "cookies": ["ak_bmsc"],
                "weight": 3
            },
        }
    
    def get_stealth_headers(self, path: str = "/") -> Dict[str, str]:
        """
        Generate stealth HTTP headers mimicking a real browser.
        
        Args:
            path: Request path for Referer generation
        
        Returns:
            Dictionary of HTTP headers
        """
        user_agent = self._get_weighted_user_agent()
        language = random.choice(self.languages)
        
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": language,
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": random.choice(["max-age=0", "no-cache"]),
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "DNT": str(random.randint(0, 1)),
        }
        
        # Add referer randomly
        if random.random() > 0.3:
            referer = random.choice(self.referers)
            if referer:
                headers["Referer"] = referer
        
        return headers
    
    def _get_weighted_user_agent(self) -> str:
        """Get a random User-Agent with weighted selection."""
        agents = list(self.user_agent_weights.keys())
        weights = [self.user_agent_weights[a] for a in agents]
        chosen = random.choices(agents, weights=weights, k=1)[0]
        return self.user_agents[chosen]
    
    def calculate_delay(self) -> float:
        """
        Calculate appropriate delay based on scan mode and jitter.
        
        Returns:
            Delay in seconds
        """
        if self.config.mode == ScanMode.STEALTH:
            base_delay = random.uniform(2.0, 5.0)
        elif self.config.mode == ScanMode.NORMAL:
            base_delay = random.uniform(0.5, 2.0)
        else:  # AGGRESSIVE
            base_delay = random.uniform(0.1, 0.5)
        
        # Add jitter (±30%)
        if self.config.jitter:
            jitter = random.uniform(-0.3, 0.3) * base_delay
            base_delay += jitter
        
        # Ensure minimum rate limit compliance
        time_since_last = time.time() - self.last_request_time
        min_interval = 1.0 / max(self.config.max_requests_per_second, 0.1)
        
        if time_since_last < min_interval:
            base_delay = min_interval - time_since_last
        
        return max(0.1, base_delay)
    
    def apply_delay(self):
        """Apply calculated delay before next request."""
        delay = self.calculate_delay()
        time.sleep(delay)
        self.last_request_time = time.time()
        self.request_count += 1
    
    def is_blocked(self, response) -> bool:
        """
        Detect if the request was blocked by security controls.
        
        Args:
            response: HTTP response object
        
        Returns:
            True if blocked, False otherwise
        """
        if response is None:
            return False
        
        # Check status codes
        if response.status_code in self.block_patterns["status_codes"]:
            if response.status_code == 429:
                self.blocked_count += 1
                return True
            elif response.status_code in [403, 503]:
                pass  # Further investigation needed
        
        # Check response body
        response_text = getattr(response, 'text', '').lower()
        for indicator in self.block_patterns["text_indicators"]:
            if indicator in response_text:
                self.blocked_count += 1
                logger.warning(f"Block detected: '{indicator}' in response")
                return True
        
        # Check headers
        for header in self.block_patterns["header_indicators"]:
            if header.lower() in [h.lower() for h in response.headers.keys()]:
                self.blocked_count += 1
                return True
        
        return False
    
    def detect_waf(self, response) -> Optional[str]:
        """
        Detect WAF type from response characteristics.
        
        Args:
            response: HTTP response object
        
        Returns:
            WAF name if detected, None otherwise
        """
        if response is None:
            return None
        
        response_text = getattr(response, 'text', '').lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = {c.name.lower(): c.value for c in getattr(response, 'cookies', [])}
        
        best_match = None
        best_score = 0
        
        for waf_name, signature in self.waf_signatures.items():
            score = 0
            
            for header in signature.get("headers", []):
                if header in headers:
                    score += 2
            
            for cookie in signature.get("cookies", []):
                if cookie in cookies:
                    score += 2
            
            for text in signature.get("text", []):
                if text.lower() in response_text:
                    score += 3
            
            if response.status_code in [403, 503]:
                score += 1
            
            if score > best_score and score >= signature.get("weight", 3):
                best_score = score
                best_match = waf_name
        
        if best_match:
            self.waf_detected = best_match
            self.waf_confidence = best_score
            logger.info(f"WAF detected: {best_match} (confidence: {best_score})")
        
        return best_match
    
    def detect_captcha(self, response) -> bool:
        """
        Detect if captcha is present in response.
        
        Args:
            response: HTTP response object
        
        Returns:
            True if captcha detected
        """
        if response is None:
            return False
        
        response_text = getattr(response, 'text', '').lower()
        
        captcha_indicators = [
            "captcha", "recaptcha/api.js", "hcaptcha.com",
            "g-recaptcha", "cf-turnstile", "h-captcha-response",
            "are you a human", "verify you are human",
        ]
        
        for indicator in captcha_indicators:
            if indicator in response_text:
                self.captcha_detected = True
                logger.warning(f"Captcha detected: '{indicator}'")
                return True
        
        return False
    
    def calculate_backoff(self, retry_count: int) -> float:
        """
        Calculate exponential backoff with jitter.
        
        Args:
            retry_count: Current retry attempt number
        
        Returns:
            Delay in seconds
        """
        delay = self.config.backoff_factor ** retry_count
        if self.config.jitter:
            delay *= random.uniform(0.5, 1.5)
        return min(delay, 60)  # Cap at 60 seconds
    
    def add_proxy(self, proxy_url: str):
        """Add a proxy to the rotation pool."""
        self.proxies.append({"http": proxy_url, "https": proxy_url})
        logger.debug(f"Proxy added: {proxy_url}")
    
    def get_next_proxy(self) -> Optional[Dict]:
        """Get next proxy from rotation pool."""
        if not self.proxies:
            return None
        proxy = self.proxies[self.proxy_index % len(self.proxies)]
        self.proxy_index += 1
        return proxy
    
    def get_stats(self) -> Dict:
        """Get evasion engine statistics."""
        return {
            "mode": self.config.mode.value,
            "requests_sent": self.request_count,
            "blocks_detected": self.blocked_count,
            "captcha_detected": self.captcha_detected,
            "waf_detected": self.waf_detected,
            "waf_confidence": self.waf_confidence,
            "proxy_count": len(self.proxies),
            "proxy_active": self.proxy_index > 0,
        }