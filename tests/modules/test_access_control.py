#!/usr/bin/env python3
"""
Unit tests for Broken Access Control & Business Logic scanner module.
"""

import pytest
from unittest.mock import MagicMock
from modules.vulnerabilities.access_control import Scanner


def test_access_control_idor_detection(sample_target, sample_config):
    """Test detecting Insecure Direct Object References (IDOR/BOLA)."""
    mock_browser = MagicMock()

    def mock_get(path, params=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if path == '/api/users' and params and params.get('id') == '1':
            resp.text = '{"id": 1, "username": "alice", "email": "alice@corp.local", "role": "admin"}'
            return resp
        elif path == '/api/users' and params and params.get('id') == '2':
            resp.text = '{"id": 2, "username": "bob", "email": "bob@corp.local", "role": "user"}'
            return resp
        resp.status_code = 404
        resp.text = "Not found"
        return resp

    mock_browser.get.side_effect = mock_get
    scanner = Scanner(mock_browser, sample_target, sample_config)
    result = scanner.run()

    assert '/api/users' in result['idor_vulnerabilities']
    assert len(result['findings']) >= 1
    idor_finding = next(f for f in result['findings'] if 'IDOR' in f['title'])
    assert idor_finding['severity'] == 'high'
    assert 'email' in idor_finding['evidence']


def test_access_control_method_tampering_bypass(sample_target, sample_config):
    """Test detecting authentication bypass via HTTP Verb Tampering."""
    mock_browser = MagicMock()

    # GET /admin returns 403 Forbidden
    def mock_get(path, **kwargs):
        resp = MagicMock()
        if path == '/admin':
            resp.status_code = 403
            resp.text = "Forbidden"
            return resp
        resp.status_code = 200
        resp.text = "OK"
        return resp

    # POST /admin returns 200 OK (Verb bypass)
    def mock_post(path, **kwargs):
        resp = MagicMock()
        if path == '/admin':
            resp.status_code = 200
            resp.text = '{"status": "admin dashboard unlocked"}'
            return resp
        resp.status_code = 404
        return resp

    mock_browser.get.side_effect = mock_get
    mock_browser.post.side_effect = mock_post
    scanner = Scanner(mock_browser, sample_target, sample_config)
    result = scanner.run()

    assert '/admin' in result['method_tampering_bypasses']
    bypass_finding = next(f for f in result['findings'] if 'Verb Tampering' in f['title'])
    assert bypass_finding['severity'] == 'critical'
    assert 'GET status: 403' in bypass_finding['evidence']
    assert 'POST status: 200' in bypass_finding['evidence']


def test_access_control_cors_misconfiguration(sample_target, sample_config):
    """Test detecting arbitrary origin reflection with credentials in CORS."""
    mock_browser = MagicMock()

    def mock_get(path, custom_headers=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "OK"
        if custom_headers and 'Origin' in custom_headers:
            resp.headers = {
                'Access-Control-Allow-Origin': custom_headers['Origin'],
                'Access-Control-Allow-Credentials': 'true'
            }
        else:
            resp.headers = {}
        return resp

    mock_browser.get.side_effect = mock_get
    scanner = Scanner(mock_browser, sample_target, sample_config)
    result = scanner.run()

    assert 'arbitrary_origin_with_credentials' in result['cors_misconfigurations']
    cors_finding = next(f for f in result['findings'] if 'CORS' in f['title'])
    assert cors_finding['severity'] == 'critical'
    assert 'Credentials: true' in cors_finding['evidence']
