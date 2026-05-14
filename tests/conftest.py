#!/usr/bin/env python3
"""
Shared test fixtures for all tests.
Prevents real HTTP requests and provides mock objects.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from unittest.mock import Mock, patch, MagicMock

from core.browser import StealthBrowser
from core.evasion import EvasionConfig, ScanMode


@pytest.fixture
def sample_target():
    """Sample target URL for testing."""
    return "https://test-site.local"


@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return {
        'scan_mode': {
            'default': 'normal',
            'timeout': 5,
            'max_requests_per_second': 10.0
        },
        'modules': {},
        'reporting': {
            'output_directory': 'tests/test_output'
        }
    }


@pytest.fixture
def browser(sample_target):
    """Create a test browser with aggressive mode."""
    config = EvasionConfig(mode=ScanMode.AGGRESSIVE)
    return StealthBrowser(sample_target, config)


@pytest.fixture(autouse=True)
def prevent_real_http():
    """
    Prevent any real HTTP requests during testing.
    Creates proper mock with all required attributes.
    """
    def create_mock_response(status=404, text=""):
        mock = MagicMock()
        mock.status_code = status
        mock.text = text
        mock.content = text.encode('utf-8') if isinstance(text, str) else b""
        mock.headers = {}
        mock.cookies = []
        mock.url = "https://test-site.local/"
        
        def json_method():
            import json
            try:
                return json.loads(text) if text else {}
            except:
                return {}
        mock.json = json_method
        
        return mock
    
    default_mock = create_mock_response()
    
    with patch('requests.Session.get', return_value=default_mock), \
         patch('requests.Session.post', return_value=default_mock), \
         patch('requests.Session.head', return_value=default_mock), \
         patch('requests.get', return_value=default_mock), \
         patch('requests.post', return_value=default_mock), \
         patch('requests.head', return_value=default_mock):
        yield