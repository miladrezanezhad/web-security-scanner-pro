#!/usr/bin/env python3
"""
Unit tests for the Nuclei-style YAML template scanner engine.
"""

import os
import pytest
from unittest.mock import MagicMock
from core.templates import TemplateScanner


@pytest.fixture
def sample_template_content():
    return """
id: test-vulnerability
info:
  name: Test Exposure Vulnerability
  author: Test Author
  severity: high
  description: Test description for template match.
  cve_id: CVE-2024-1111
  cvss_score: 8.5
  recommendation: Test recommendation.
requests:
  - method: GET
    path:
      - "/test-endpoint"
    matchers_condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "vulnerable_key"
        condition: or
"""


def test_template_loading_and_parsing(tmp_path, sample_template_content, sample_config):
    """Test loading and parsing of YAML template files."""
    template_file = tmp_path / "test-template.yaml"
    template_file.write_text(sample_template_content, encoding='utf-8')

    mock_browser = MagicMock()
    scanner = TemplateScanner(mock_browser, "https://example.com", sample_config, templates_dir=str(tmp_path))

    assert len(scanner.templates) == 1
    t = scanner.templates[0]
    assert t['id'] == 'test-vulnerability'
    assert t['info']['severity'] == 'high'
    assert len(t['requests']) == 1


def test_template_execution_match(tmp_path, sample_template_content, sample_config):
    """Test matching an HTTP response with a word and status matcher."""
    template_file = tmp_path / "test-template.yaml"
    template_file.write_text(sample_template_content, encoding='utf-8')

    mock_browser = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {'Content-Type': 'application/json'}
    mock_resp.text = '{"status": "ok", "data": "vulnerable_key_found"}'
    mock_browser.get.return_value = mock_resp

    scanner = TemplateScanner(mock_browser, "https://example.com", sample_config, templates_dir=str(tmp_path))
    result = scanner.run()

    assert result['templates_matched'] == 1
    assert len(result['findings']) == 1

    finding = result['findings'][0]
    assert finding['severity'] == 'high'
    assert finding['cve_id'] == 'CVE-2024-1111'
    assert '[Template]' in finding['title']
    assert 'test-endpoint' in finding['evidence']


def test_template_execution_no_match(tmp_path, sample_template_content, sample_config):
    """Test that non-matching responses do not produce findings."""
    template_file = tmp_path / "test-template.yaml"
    template_file.write_text(sample_template_content, encoding='utf-8')

    mock_browser = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = 'Not Found'
    mock_browser.get.return_value = mock_resp

    scanner = TemplateScanner(mock_browser, "https://example.com", sample_config, templates_dir=str(tmp_path))
    result = scanner.run()

    assert result['templates_matched'] == 0
    assert len(result['findings']) == 0
