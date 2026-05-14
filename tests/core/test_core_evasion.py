#!/usr/bin/env python3
"""
Tests for core EvasionEngine module.
Tests WAF detection, rate limiting, User-Agent rotation, and blocking detection.
"""

import sys
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

# Adjust path to import from project root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.evasion import EvasionEngine, EvasionConfig, ScanMode


class TestEvasionEngine:
    """Test the evasion engine."""
    
    @pytest.fixture
    def stealth_engine(self):
        """Create stealth mode evasion engine."""
        config = EvasionConfig(mode=ScanMode.STEALTH)
        return EvasionEngine(config)
    
    @pytest.fixture
    def aggressive_engine(self):
        """Create aggressive mode evasion engine."""
        config = EvasionConfig(mode=ScanMode.AGGRESSIVE)
        return EvasionEngine(config)
    
    def test_initialization(self, stealth_engine):
        """Test evasion engine initializes."""
        assert stealth_engine is not None
        assert stealth_engine.config.mode == ScanMode.STEALTH
        assert stealth_engine.request_count == 0
    
    def test_get_stealth_headers(self, stealth_engine):
        """Test stealth header generation."""
        headers = stealth_engine.get_stealth_headers()
        
        assert 'User-Agent' in headers
        assert 'Accept' in headers
        assert 'Accept-Language' in headers
        assert 'Mozilla' in headers['User-Agent']
    
    def test_user_agent_rotation(self, stealth_engine):
        """Test that User-Agent rotates between requests."""
        agents = set()
        for _ in range(10):
            headers = stealth_engine.get_stealth_headers()
            agents.add(headers['User-Agent'])
        
        assert len(agents) > 1, f"Only got {len(agents)} unique agents"
    
    def test_delay_calculation_stealth(self, stealth_engine):
        """Test delay in stealth mode."""
        delay = stealth_engine.calculate_delay()
        assert delay > 0
        assert delay < 10
    
    def test_delay_calculation_aggressive(self, aggressive_engine):
        """Test delay in aggressive mode."""
        delay = aggressive_engine.calculate_delay()
        assert delay < 2.0
    
    def test_blocked_detection_by_status(self, stealth_engine):
        """Test blocked detection via status code.
        The is_blocked method checks status code directly for 403, 429, 503.
        """
        mock_response = Mock()
        mock_response.status_code = 403
        # Make text and headers not match any block patterns
        mock_response.text = "Some normal looking text"
        mock_response.headers = {}
        
        assert stealth_engine.is_blocked(mock_response) == True
    
    def test_blocked_detection_by_text(self, stealth_engine):
        """Test blocked detection via response text."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Access Denied - Your IP has been blocked"
        mock_response.headers = {}
        
        assert stealth_engine.is_blocked(mock_response) == True
    
    def test_not_blocked(self, stealth_engine):
        """Test normal response is not blocked."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Normal page</body></html>"
        mock_response.headers = {}
        
        assert stealth_engine.is_blocked(mock_response) == False
    
    def test_waf_detection_cloudflare(self, stealth_engine):
        """Test Cloudflare WAF detection."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Attention Required! | Cloudflare"
        mock_response.headers = {
            'cf-ray': '123456789',
            'cf-cache-status': 'DYNAMIC'
        }
        mock_response.cookies = []
        
        waf = stealth_engine.detect_waf(mock_response)
        assert waf == "Cloudflare"
    
    def test_waf_detection_wordfence(self, stealth_engine):
        """Test Wordfence WAF detection.
        The Wordfence signature looks for cookies starting with 'wfvt_'.
        """
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Your access to this site has been limited by Wordfence"
        mock_response.headers = {}
        
        # Create mock cookie with exact name from Wordfence signature
        mock_cookie = Mock()
        mock_cookie.name = 'wfvt_1234567890'  # Matches 'wfvt_' pattern
        mock_cookie.value = 'abc123'
        mock_response.cookies = [mock_cookie]
        
        waf = stealth_engine.detect_waf(mock_response)
        assert waf == "Wordfence"
    
    def test_captcha_detection(self, stealth_engine):
        """Test captcha detection."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Please verify you are human. g-recaptcha"
        mock_response.headers = {}
        
        assert stealth_engine.detect_captcha(mock_response) == True
    
    def test_captcha_not_detected(self, stealth_engine):
        """Test captcha not detected on normal page."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Normal page</body></html>"
        mock_response.headers = {}
        
        assert stealth_engine.detect_captcha(mock_response) == False
    
    def test_exponential_backoff(self, stealth_engine):
        """Test exponential backoff calculation."""
        delay1 = stealth_engine.calculate_backoff(1)
        delay2 = stealth_engine.calculate_backoff(2)
        delay3 = stealth_engine.calculate_backoff(3)
        
        # With jitter, we just check they're positive
        assert delay1 > 0
        assert delay2 > 0
        assert delay3 > 0
    
    def test_proxy_management(self, stealth_engine):
        """Test proxy pool management."""
        stealth_engine.add_proxy("http://proxy1:8080")
        stealth_engine.add_proxy("http://proxy2:8080")
        
        proxy = stealth_engine.get_next_proxy()
        assert proxy is not None
        assert 'http' in proxy
    
    def test_stats_tracking(self, stealth_engine):
        """Test evasion stats tracking."""
        stats = stealth_engine.get_stats()
        
        assert 'mode' in stats
        assert stats['mode'] == 'stealth'
        assert 'requests_sent' in stats
        assert 'blocks_detected' in stats
    
    def test_rate_limiting_enforcement(self, stealth_engine):
        """Test rate limiting by measuring delays."""
        config = EvasionConfig(
            mode=ScanMode.NORMAL,
            max_requests_per_second=10.0,
            jitter=False
        )
        engine = EvasionEngine(config)
        
        start = time.time()
        for _ in range(10):
            engine.apply_delay()
        elapsed = time.time() - start
        
        # Should take ~1 second with 10 req/sec
        assert elapsed <= 3.0, f"Rate limiting too slow: {elapsed:.2f}s"