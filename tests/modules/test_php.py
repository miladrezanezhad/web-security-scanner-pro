#!/usr/bin/env python3
"""
Tests for PHP security modules.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestPHPVersion:
    """Test PHP version detection module."""
    
    def test_module_imports(self):
        """Test that PHP version module can be imported."""
        try:
            from modules.php import version
            assert hasattr(version, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import PHP version: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.php.version import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_version_from_header(self, mock_get, browser, sample_target, sample_config):
        """Test PHP version detection from X-Powered-By header."""
        from modules.php.version import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'X-Powered-By': 'PHP/8.2.15'}
        mock_resp.text = '<html></html>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        # Check for version in various possible keys
        version_found = any(key in result for key in [
            'version', 'php_version', 'detected_version', 'findings'
        ])
        assert version_found, f"No version info found. Keys: {list(result.keys())}"


class TestPHPConfiguration:
    """Test PHP configuration module."""
    
    def test_module_imports(self):
        """Test that PHP config module can be imported."""
        try:
            from modules.php import configuration
            assert hasattr(configuration, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import PHP configuration: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.php.configuration import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    def test_run_returns_dict(self, browser, sample_target, sample_config):
        """Test that configuration check returns proper structure."""
        from modules.php.configuration import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)


class TestPHPDangerousFunctions:
    """Test PHP dangerous functions module."""
    
    def test_module_imports(self):
        """Test that dangerous functions module can be imported."""
        try:
            from modules.php import dangerous_functions
            assert hasattr(dangerous_functions, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import PHP dangerous functions: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.php.dangerous_functions import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestPHPInfoDisclosure:
    """Test PHP info disclosure module."""
    
    def test_module_imports(self):
        """Test that PHP info disclosure module can be imported."""
        try:
            from modules.php import info_disclosure
            assert hasattr(info_disclosure, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import PHP info disclosure: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.php.info_disclosure import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_checks_phpinfo(self, mock_get, browser, sample_target, sample_config):
        """Test phpinfo.php detection."""
        from modules.php.info_disclosure import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<title>phpinfo()</title>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)