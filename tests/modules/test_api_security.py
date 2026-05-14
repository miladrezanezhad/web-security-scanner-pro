#!/usr/bin/env python3
"""
Tests for API security modules.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestGraphQL:
    """Test GraphQL security module."""
    
    def test_module_imports(self):
        """Test that GraphQL module can be imported."""
        try:
            from modules.api_security import graphql
            assert hasattr(graphql, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import GraphQL module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.api_security.graphql import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    @patch('core.browser.StealthBrowser.get')
    def test_run_detects_graphql(self, mock_get, browser, sample_target, sample_config):
        """Test GraphQL endpoint detection."""
        from modules.api_security.graphql import Scanner
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"data": {"__schema": {"types": []}}}'
        mock_get.return_value = mock_resp
        
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)


class TestRESTAPI:
    """Test REST API security module."""
    
    def test_module_imports(self):
        """Test that REST API module can be imported."""
        try:
            from modules.api_security import rest_api
            assert hasattr(rest_api, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import REST API module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.api_security.rest_api import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestJWT:
    """Test JWT security module."""
    
    def test_module_imports(self):
        """Test that JWT module can be imported."""
        try:
            from modules.api_security import jwt
            assert hasattr(jwt, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import JWT module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.api_security.jwt import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')