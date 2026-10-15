#!/usr/bin/env python3
"""
Unit tests for SARIF report generation and Notifier system.
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from core.reporter import ReportGenerator
from core.notifier import Notifier
from core.scanner import Finding, ScanResult


@pytest.fixture
def mock_scan_result():
    """Create a sample ScanResult object with diverse findings."""
    result = ScanResult(
        target_url="https://example.com",
        scan_mode="stealth",
        timeout=30,
        rps=1.0
    )
    result.modules_run = ['xss', 'sqli', 'sensitive_files']

    finding1 = Finding(
        title="Reflected Cross-Site Scripting (XSS)",
        severity="high",
        description="XSS payload reflected in 'q' parameter.",
        recommendation="Sanitize user input and encode HTML entities.",
        module="xss",
        cwe_id="CWE-79",
        cvss_score=8.2,
        evidence="<script>alert(1)</script>"
    )

    finding2 = Finding(
        title="Exposed .env configuration file",
        severity="critical",
        description="Database credentials and app secrets exposed.",
        recommendation="Deny public access via web server config.",
        module="sensitive_files",
        cve_id="CVE-2024-9999",
        cwe_id="CWE-538",
        cvss_score=9.8,
        evidence="DB_PASSWORD=secret"
    )

    result.add_finding(finding1)
    result.add_finding(finding2)
    result.scan_duration = 12.5
    return result


def test_sarif_generation(mock_scan_result, tmp_path):
    """Test generating a compliant SARIF v2.1.0 document."""
    config = {
        'reporting': {
            'output_directory': str(tmp_path)
        }
    }

    reporter = ReportGenerator(mock_scan_result, config)
    sarif_path = reporter.generate(format='sarif', filename='test_sarif')

    assert os.path.exists(sarif_path)
    assert sarif_path.endswith('.sarif')

    with open(sarif_path, 'r', encoding='utf-8') as f:
        doc = json.load(f)

    # Validate SARIF schema and structure
    assert doc['version'] == '2.1.0'
    assert '$schema' in doc
    assert len(doc['runs']) == 1

    run = doc['runs'][0]
    assert run['tool']['driver']['name'] == 'Web Security Analyzer Pro'
    assert len(run['tool']['driver']['rules']) == 2
    assert len(run['results']) == 2

    # Check rule IDs and levels
    rule_ids = [r['id'] for r in run['tool']['driver']['rules']]
    assert 'CWE-79' in rule_ids
    assert 'CVE-2024-9999' in rule_ids

    # Critical and High map to 'error'
    assert run['results'][0]['level'] == 'error'
    assert run['results'][1]['level'] == 'error'


@patch('requests.post')
def test_notifier_discord(mock_post, mock_scan_result):
    """Test Discord webhook dispatching."""
    mock_resp = MagicMock()
    mock_resp.status_code = 204
    mock_post.return_value = mock_resp

    config = {
        'notifications': {
            'enabled': True,
            'discord_webhook': 'https://discord.com/api/webhooks/test/123',
            'critical_only': False
        }
    }

    notifier = Notifier(config)
    results = notifier.send_scan_summary(mock_scan_result)

    assert results.get('discord') is True
    assert mock_post.called
    called_url = mock_post.call_args[0][0]
    called_json = mock_post.call_args[1]['json']
    assert called_url == 'https://discord.com/api/webhooks/test/123'
    assert 'embeds' in called_json
    assert 'example.com' in called_json['embeds'][0]['title']


@patch('requests.post')
def test_notifier_slack(mock_post, mock_scan_result):
    """Test Slack webhook dispatching."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    config = {
        'notifications': {
            'enabled': True,
            'slack_webhook': 'https://hooks.slack.com/services/test/456',
            'critical_only': False
        }
    }

    notifier = Notifier(config)
    results = notifier.send_scan_summary(mock_scan_result)

    assert results.get('slack') is True
    assert mock_post.called
    called_json = mock_post.call_args[1]['json']
    assert 'text' in called_json
    assert 'Critical: 1' in called_json['text']


@patch('requests.post')
def test_notifier_telegram(mock_post, mock_scan_result):
    """Test Telegram notification dispatching."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    config = {
        'notifications': {
            'enabled': True,
            'telegram_bot_token': '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11',
            'telegram_chat_id': '987654321',
            'critical_only': False
        }
    }

    notifier = Notifier(config)
    results = notifier.send_scan_summary(mock_scan_result)

    assert results.get('telegram') is True
    assert mock_post.called
    called_url = mock_post.call_args[0][0]
    called_payload = mock_post.call_args[1]['json']
    assert '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11' in called_url
    assert called_payload['chat_id'] == '987654321'
    assert 'Critical: 1' in called_payload['text']
