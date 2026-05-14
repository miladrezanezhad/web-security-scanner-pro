#!/usr/bin/env python3
"""
Tests for SSL/TLS and security header modules.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestSSLCertificate:
    """Test SSL certificate module."""
    
    def test_module_imports(self):
        """Test that SSL certificate module can be imported."""
        try:
            from modules.ssl_tls import certificate
            assert hasattr(certificate, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import SSL certificate module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.ssl_tls.certificate import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestSSLProtocols:
    """Test SSL protocols module."""
    
    def test_module_imports(self):
        """Test that SSL protocols module can be imported."""
        try:
            from modules.ssl_tls import protocols
            assert hasattr(protocols, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import SSL protocols module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.ssl_tls.protocols import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestSecurityHeaders:
    """Test security headers module."""
    
    def test_module_imports(self):
        """Test that security headers module can be imported."""
        try:
            from modules.headers import security_headers
            assert hasattr(security_headers, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import security headers module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.headers.security_headers import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_checks_headers(self, mock_get, browser, sample_target, sample_config):
        """Test header checking."""
        from modules.headers.security_headers import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff'
        }
        mock_resp.text = '<html></html>'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)