#!/usr/bin/env python3
"""
Tests for vulnerability scanning modules.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestXSS:
    """Test XSS vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that XSS module can be imported."""
        try:
            from modules.vulnerabilities import xss
            assert hasattr(xss, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import XSS module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.xss import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    def test_run_returns_proper_structure(self, browser, sample_target, sample_config):
        """Test that XSS scanner returns correct data structure."""
        from modules.vulnerabilities.xss import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        assert 'findings' in result
        assert isinstance(result['findings'], list)


class TestSQLInjection:
    """Test SQL Injection vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that SQLi module can be imported."""
        try:
            from modules.vulnerabilities import sqli
            assert hasattr(sqli, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import SQLi module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.sqli import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    def test_run_returns_proper_structure(self, browser, sample_target, sample_config):
        """Test that SQLi scanner returns correct data structure."""
        from modules.vulnerabilities.sqli import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        assert 'findings' in result


class TestLFI:
    """Test LFI vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that LFI module can be imported."""
        try:
            from modules.vulnerabilities import lfi
            assert hasattr(lfi, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import LFI module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.lfi import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestXXE:
    """Test XXE vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that XXE module can be imported."""
        try:
            from modules.vulnerabilities import xxe
            assert hasattr(xxe, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import XXE module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.xxe import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestSSTI:
    """Test SSTI vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that SSTI module can be imported."""
        try:
            from modules.vulnerabilities import ssti
            assert hasattr(ssti, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import SSTI module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.ssti import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestCSRF:
    """Test CSRF vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that CSRF module can be imported."""
        try:
            from modules.vulnerabilities import csrf
            assert hasattr(csrf, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import CSRF module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.csrf import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestCommandInjection:
    """Test Command Injection vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that Command Injection module can be imported."""
        try:
            from modules.vulnerabilities import command_injection
            assert hasattr(command_injection, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import Command Injection module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.command_injection import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestFileUpload:
    """Test File Upload vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that File Upload module can be imported."""
        try:
            from modules.vulnerabilities import file_upload
            assert hasattr(file_upload, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import File Upload module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.file_upload import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestSSRF:
    """Test SSRF vulnerability scanner module."""
    
    def test_module_imports(self):
        """Test that SSRF module can be imported."""
        try:
            from modules.vulnerabilities import ssrf
            assert hasattr(ssrf, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import SSRF module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.vulnerabilities.ssrf import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')