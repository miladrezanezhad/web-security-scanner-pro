#!/usr/bin/env python3
"""
Tests for control panel security modules.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestcPanel:
    """Test cPanel security module."""
    
    def test_module_imports(self):
        """Test that cPanel module can be imported."""
        try:
            from modules.control_panels import cpanel
            assert hasattr(cpanel, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import cPanel module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.control_panels.cpanel import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_cpanel(self, mock_get, browser, sample_target, sample_config):
        """Test cPanel detection."""
        from modules.control_panels.cpanel import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<title>cPanel Login</title>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        # Check for any detection key the module returns
        detection_found = any(key in result for key in [
            'cpanel_detected', 'detected', 'cpanel_found', 'is_cpanel'
        ])
        assert detection_found, f"No detection key found. Keys: {list(result.keys())}"


class TestDirectAdmin:
    """Test DirectAdmin security module."""
    
    def test_module_imports(self):
        """Test that DirectAdmin module can be imported."""
        try:
            from modules.control_panels import directadmin
            assert hasattr(directadmin, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import DirectAdmin module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.control_panels.directadmin import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestPlesk:
    """Test Plesk security module."""
    
    def test_module_imports(self):
        """Test that Plesk module can be imported."""
        try:
            from modules.control_panels import plesk
            assert hasattr(plesk, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import Plesk module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.control_panels.plesk import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')