#!/usr/bin/env python3
"""
Unit tests for Authenticated and Whitelisted Scans (Custom Headers & Cookies).
"""

import pytest
from unittest.mock import MagicMock, patch
from core.browser import StealthBrowser
from core.scanner import SecurityScanner
from core.evasion import EvasionConfig, ScanMode


def test_browser_applies_auth_headers_and_cookies():
    """Verify that StealthBrowser automatically injects whitelisted headers, tokens, and cookies."""
    auth_config = {
        'enabled': True,
        'custom_headers': {
            'X-Scanner-Auth': 'SecretKey-123456',
            'X-Forwarded-For': '127.0.0.1'
        },
        'bearer_token': 'jwt.token.here',
        'cookies': {
            'session_id': 'sess_abc123',
            'user_role': 'auditor'
        }
    }

    browser = StealthBrowser(
        target_url="https://example.com",
        evasion_config=EvasionConfig(mode=ScanMode.NORMAL),
        auth_config=auth_config
    )

    # Check session default headers
    assert browser.session.headers.get('X-Scanner-Auth') == 'SecretKey-123456'
    assert browser.session.headers.get('X-Forwarded-For') == '127.0.0.1'
    assert browser.session.headers.get('Authorization') == 'Bearer jwt.token.here'

    # Check session cookies
    cookie_dict = browser.session.cookies.get_dict()
    assert cookie_dict.get('session_id') == 'sess_abc123'
    assert cookie_dict.get('user_role') == 'auditor'


def test_browser_set_auth_dynamically():
    """Verify dynamic update methods on StealthBrowser."""
    browser = StealthBrowser(
        target_url="https://example.com",
        evasion_config=EvasionConfig(mode=ScanMode.NORMAL)
    )

    browser.set_auth_header('X-Custom-Bypass', 'BypassValue99')
    browser.set_bearer_token('new.bearer.token')
    browser.set_cookie('custom_cookie', 'val123')

    assert browser.session.headers.get('X-Custom-Bypass') == 'BypassValue99'
    assert browser.session.headers.get('Authorization') == 'Bearer new.bearer.token'
    assert browser.session.cookies.get('custom_cookie') == 'val123'


@patch('requests.Session.get')
def test_scanner_passes_auth_to_browser(mock_get):
    """Verify SecurityScanner correctly initializes StealthBrowser with authentication config."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "OK"
    mock_resp.content = b"OK"
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    config = {
        'scan_mode': {'default': 'normal'},
        'authentication': {
            'custom_headers': {'X-Audit-Token': 'TokenXYZ'},
            'cookies': {'admin_session': 'active'}
        }
    }

    scanner = SecurityScanner("https://example.com", config)

    # Check that scanner's browser carries the config
    assert scanner.browser.session.headers.get('X-Audit-Token') == 'TokenXYZ'
    assert scanner.browser.session.cookies.get('admin_session') == 'active'
