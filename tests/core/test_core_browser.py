#!/usr/bin/env python3
"""
Tests for core StealthBrowser module.
Tests HTTP client functionality, evasion, and error handling.
"""

import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, PropertyMock
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.browser import StealthBrowser
from core.evasion import EvasionConfig, ScanMode


class TestStealthBrowser:
    """Test the StealthBrowser HTTP client."""
    
    @pytest.fixture
    def browser(self):
        """Create a test browser instance."""
        config = EvasionConfig(mode=ScanMode.AGGRESSIVE)
        return StealthBrowser("https://example.com", config)
    
    def test_initialization(self, browser):
        """Test browser initializes correctly."""
        assert browser is not None
        assert browser.target_url == "https://example.com"
        assert browser.session is not None
        assert hasattr(browser, 'get')
        assert hasattr(browser, 'post')
        assert hasattr(browser, 'head')
    
    @patch('requests.Session.get')
    def test_get_request_success(self, mock_get, browser):
        """Test successful GET request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.content = b"<html><body>Test</body></html>"
        mock_response.headers = {'Server': 'Apache'}
        mock_response.cookies = {}
        mock_get.return_value = mock_response
        
        response = browser.get('/test')
        
        assert response is not None
        assert response.status_code == 200
        assert 'Test' in response.text
    
    @patch('requests.Session.get')
    def test_get_request_timeout(self, mock_get, browser):
        """Test GET request with timeout."""
        import requests
        mock_get.side_effect = requests.Timeout("Connection timed out")
        
        response = browser.get('/test')
        assert response is None
    
    @patch('requests.Session.get')
    def test_get_request_connection_error(self, mock_get, browser):
        """Test GET request with connection error."""
        import requests
        mock_get.side_effect = requests.ConnectionError("Connection refused")
        
        response = browser.get('/test')
        assert response is None
    
    @patch('requests.Session.post')
    def test_post_request(self, mock_post, browser):
        """Test POST request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "ok"}'
        mock_response.content = b'{"status": "ok"}'
        mock_response.headers = {}
        mock_response.cookies = {}
        mock_post.return_value = mock_response
        
        response = browser.post('/api', data={'key': 'value'})
        
        assert response is not None
        assert response.status_code == 200
    
    @patch('requests.Session.head')
    def test_head_request(self, mock_head, browser):
        """Test HEAD request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_head.return_value = mock_response
        
        response = browser.head('/')
        
        assert response is not None
        assert response.status_code == 200
    
    def test_stats_tracking(self, browser):
        """Test that stats are tracked correctly."""
        initial_stats = browser.get_stats()
        
        assert isinstance(initial_stats, dict)
        # Stats should have basic keys
        assert len(initial_stats) > 0
    
    @patch('requests.Session.get')
    def test_retry_on_failure(self, mock_get, browser):
        """Test retry mechanism on failure."""
        import requests
        
        mock_success = Mock()
        mock_success.status_code = 200
        mock_success.text = "Success"
        mock_success.content = b"Success"
        mock_success.headers = {}
        mock_success.cookies = {}
        
        # First two calls fail, third succeeds
        mock_get.side_effect = [
            requests.Timeout("Timeout"),
            requests.ConnectionError("Error"),
            mock_success
        ]
        
        response = browser.get('/test')
        
        # Should eventually succeed after retries
        assert response is not None
        assert response.status_code == 200
    
    @patch('requests.Session.get')
    def test_user_agent_rotation(self, mock_get, browser):
        """Test that User-Agent header is set."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.content = b"OK"
        mock_response.headers = {}
        mock_response.cookies = {}
        mock_get.return_value = mock_response
        
        # Make multiple requests
        for _ in range(3):
            browser.get('/test')
        
        # Each call should have headers
        assert mock_get.call_count == 3
        for call in mock_get.call_args_list:
            assert 'headers' in call[1]


class TestBrowserEvasionIntegration:
    """Test browser and evasion engine integration."""
    
    @pytest.fixture
    def browser_with_evasion(self):
        """Create browser with specific evasion config."""
        config = EvasionConfig(
            mode=ScanMode.STEALTH,
            max_requests_per_second=0.5,
            jitter=True
        )
        return StealthBrowser("https://example.com", config)
    
    def test_stealth_mode_configured(self, browser_with_evasion):
        """Test stealth mode is configured."""
        assert browser_with_evasion.evasion.config.mode == ScanMode.STEALTH
        assert browser_with_evasion.evasion.config.max_requests_per_second == 0.5
    
    def test_evasion_engine_accessible(self, browser_with_evasion):
        """Test evasion engine is accessible from browser."""
        assert browser_with_evasion.evasion is not None
        assert hasattr(browser_with_evasion.evasion, 'get_stealth_headers')
        assert hasattr(browser_with_evasion.evasion, 'apply_delay')
    
    @patch('requests.Session.get')
    def test_blocked_detection(self, mock_get, browser_with_evasion):
        """Test that blocked responses are detected."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Access Denied - Your IP has been blocked"
        mock_response.content = b"Access Denied - Your IP has been blocked"
        mock_response.headers = {}
        mock_response.cookies = {}
        mock_get.return_value = mock_response
        
        response = browser_with_evasion.get('/test')
        
        # Should detect the block
        assert browser_with_evasion.evasion.is_blocked(response) == True