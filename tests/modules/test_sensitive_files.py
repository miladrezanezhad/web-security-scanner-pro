#!/usr/bin/env python3
"""
Tests for Sensitive Files & Secrets Disclosure scanner module.
"""

import pytest
from unittest.mock import MagicMock
from modules.vulnerabilities.sensitive_files import Scanner


def test_sensitive_files_instantiation(sample_target, sample_config):
    """Test scanner initializes correctly."""
    mock_browser = MagicMock()
    scanner = Scanner(mock_browser, sample_target, sample_config)

    assert scanner.target_url == sample_target.rstrip('/')
    assert len(scanner.sensitive_targets) > 0
    assert len(scanner.secret_patterns) > 0


def test_sensitive_files_detects_exposed_env(sample_target, sample_config):
    """Test detection of an exposed .env file with secrets."""
    mock_browser = MagicMock()

    # Mock response for /.env
    def mock_get(path, **kwargs):
        resp = MagicMock()
        if path == '/.env':
            resp.status_code = 200
            resp.text = "APP_KEY=base64:abcdef123456\nDB_PASSWORD=SuperSecretPass123!\nDATABASE_URL=postgres://user:pass@localhost/db"
            return resp
        elif path == '/':
            resp.status_code = 200
            resp.text = "<html><body>Welcome</body></html>"
            return resp
        resp.status_code = 404
        resp.text = "Not found"
        return resp

    mock_browser.get.side_effect = mock_get
    scanner = Scanner(mock_browser, sample_target, sample_config)
    result = scanner.run()

    assert '/.env' in result['exposed_files']
    assert len(result['findings']) >= 1
    env_finding = next(f for f in result['findings'] if '.env' in f['title'])
    assert env_finding['severity'] == 'critical'
    assert 'DB_PASSWORD' in env_finding['evidence'] or 'APP_KEY' in env_finding['evidence']


def test_sensitive_files_detects_git_head(sample_target, sample_config):
    """Test detection of an exposed .git/HEAD file."""
    mock_browser = MagicMock()

    def mock_get(path, **kwargs):
        resp = MagicMock()
        if path == '/.git/HEAD':
            resp.status_code = 200
            resp.text = "ref: refs/heads/main\n"
            return resp
        resp.status_code = 404
        resp.text = "Not found"
        return resp

    mock_browser.get.side_effect = mock_get
    scanner = Scanner(mock_browser, sample_target, sample_config)
    result = scanner.run()

    assert '/.git/HEAD' in result['exposed_files']
    git_finding = next(f for f in result['findings'] if '.git' in f['title'])
    assert git_finding['severity'] == 'critical'


def test_sensitive_files_ignores_soft_404(sample_target, sample_config):
    """Test that soft 404 HTML responses are ignored and not flagged as findings."""
    mock_browser = MagicMock()

    # Return HTML 200 page for all requests (typical SPA or custom 404)
    def mock_get(path, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<!DOCTYPE html><html><body>Page Not Found 404</body></html>"
        return resp

    mock_browser.get.side_effect = mock_get
    scanner = Scanner(mock_browser, sample_target, sample_config)
    result = scanner.run()

    assert len(result['exposed_files']) == 0
    assert len(result['findings']) == 0


def test_sensitive_files_detects_leaked_aws_key(sample_target, sample_config):
    """Test regex detection of hardcoded AWS Access Key in response."""
    mock_browser = MagicMock()

    def mock_get(path, **kwargs):
        resp = MagicMock()
        if path == '/':
            resp.status_code = 200
            resp.text = 'const aws_key = "AKIAIOSFODNN7EXAMPLE";'
            return resp
        resp.status_code = 404
        resp.text = "Not found"
        return resp

    mock_browser.get.side_effect = mock_get
    scanner = Scanner(mock_browser, sample_target, sample_config)
    result = scanner.run()

    assert 'AWS Access Key ID' in result['leaked_secrets']
    aws_finding = next(f for f in result['findings'] if 'AWS Access Key' in f['title'])
    assert aws_finding['severity'] == 'high'
