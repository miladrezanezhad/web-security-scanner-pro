#!/usr/bin/env python3
"""
Tests for Joomla CMS detection module.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestJoomla:
    """Test Joomla CMS module."""
    
    def test_module_imports(self):
        """Test that Joomla module can be imported."""
        try:
            from modules.cms.joomla import scanner
            assert hasattr(scanner, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import Joomla scanner: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.cms.joomla.scanner import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_joomla(self, mock_get, browser, sample_target, sample_config):
        """Test Joomla detection."""
        from modules.cms.joomla.scanner import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<meta name="generator" content="Joomla! 4"/>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)