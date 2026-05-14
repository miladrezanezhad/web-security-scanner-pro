#!/usr/bin/env python3
"""
Tests for Drupal CMS detection module.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestDrupal:
    """Test Drupal CMS module."""
    
    def test_module_imports(self):
        """Test that Drupal module can be imported."""
        try:
            from modules.cms.drupal import scanner
            assert hasattr(scanner, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import Drupal scanner: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.cms.drupal.scanner import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_drupal(self, mock_get, browser, sample_target, sample_config):
        """Test Drupal detection."""
        from modules.cms.drupal.scanner import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<meta name="Generator" content="Drupal 10"/>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)