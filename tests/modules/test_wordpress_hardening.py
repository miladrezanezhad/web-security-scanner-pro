#!/usr/bin/env python3
"""
Tests for WordPress hardening module.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestWordPressHardening:
    """Test WordPress hardening checks."""
    
    def test_module_imports(self):
        """Test that hardening module can be imported."""
        try:
            from modules.cms.wordpress import hardening
            assert hasattr(hardening, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import WordPress hardening: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.cms.wordpress.hardening import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_checks_debug_mode(self, mock_get, browser, sample_target, sample_config):
        """Test debug mode detection."""
        from modules.cms.wordpress.hardening import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<b>Warning</b>:  Undefined variable'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)