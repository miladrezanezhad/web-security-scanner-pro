#!/usr/bin/env python3
"""
Tests for web server detection modules (Apache, Nginx, LiteSpeed, IIS, Tomcat).
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestApache:
    """Test Apache web server module."""
    
    def test_module_imports(self):
        """Test that Apache module can be imported."""
        try:
            from modules.webserver import apache
            assert hasattr(apache, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import Apache module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.webserver.apache import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_apache(self, mock_get, browser, sample_target, sample_config):
        """Test Apache detection from Server header."""
        from modules.webserver.apache import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Server': 'Apache/2.4.59 (Ubuntu)'}
        mock_resp.text = '<html></html>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)


class TestNginx:
    """Test Nginx web server module."""
    
    def test_module_imports(self):
        """Test that Nginx module can be imported."""
        try:
            from modules.webserver import nginx
            assert hasattr(nginx, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import Nginx module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.webserver.nginx import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_nginx(self, mock_get, browser, sample_target, sample_config):
        """Test Nginx detection."""
        from modules.webserver.nginx import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Server': 'nginx/1.26.0'}
        mock_resp.text = '<html></html>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)


class TestLiteSpeed:
    """Test LiteSpeed web server module."""
    
    def test_module_imports(self):
        """Test that LiteSpeed module can be imported."""
        try:
            from modules.webserver import litespeed
            assert hasattr(litespeed, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import LiteSpeed module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.webserver.litespeed import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_litespeed(self, mock_get, browser, sample_target, sample_config):
        """Test LiteSpeed detection."""
        from modules.webserver.litespeed import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Server': 'LiteSpeed', 'X-LiteSpeed-Cache': 'hit'}
        mock_resp.text = '<html></html>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)


class TestIIS:
    """Test IIS web server module."""
    
    def test_module_imports(self):
        """Test that IIS module can be imported."""
        try:
            from modules.webserver import iis
            assert hasattr(iis, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import IIS module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.webserver.iis import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_iis(self, mock_get, browser, sample_target, sample_config):
        """Test IIS detection."""
        from modules.webserver.iis import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Server': 'Microsoft-IIS/10.0'}
        mock_resp.text = '<html></html>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)


class TestTomcat:
    """Test Tomcat web server module."""
    
    def test_module_imports(self):
        """Test that Tomcat module can be imported."""
        try:
            from modules.webserver import tomcat
            assert hasattr(tomcat, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import Tomcat module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.webserver.tomcat import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')