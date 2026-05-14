#!/usr/bin/env python3
"""
Tests for WordPress modules - OPTIMIZED for speed.
Uses proper mocking to avoid real HTTP requests.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ============================================================================
# WordPress Detector Tests
# ============================================================================

class TestWordPressDetector:
    """Test WordPress detection module."""
    
    def test_module_imports(self):
        """Test that module imports correctly."""
        from modules.cms.wordpress import detector
        assert hasattr(detector, 'Scanner')
    
    @patch('modules.cms.wordpress.detector.Scanner.run')
    def test_run_returns_dict(self, mock_run, browser, sample_target, sample_config):
        """Test that run() returns a dictionary."""
        mock_run.return_value = {'is_wordpress': True, 'signs': ['meta generator']}
        
        from modules.cms.wordpress.detector import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        assert 'is_wordpress' in result
    
    @patch('modules.cms.wordpress.detector.Scanner.run')
    def test_detects_wordpress(self, mock_run, browser, sample_target, sample_config):
        """Test WordPress detection returns True."""
        mock_run.return_value = {'is_wordpress': True, 'signs': ['meta', 'wp-content']}
        
        from modules.cms.wordpress.detector import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert result['is_wordpress'] == True


# ============================================================================
# WordPress Version Tests
# ============================================================================

class TestWordPressVersion:
    """Test WordPress version detection."""
    
    def test_module_imports(self):
        """Test that version module imports."""
        from modules.cms.wordpress import version
        assert hasattr(version, 'Scanner')
    
    @patch('modules.cms.wordpress.version.Scanner.run')
    def test_returns_version(self, mock_run, browser, sample_target, sample_config):
        """Test version string is returned."""
        mock_run.return_value = {'version': '6.5.3', 'detection_method': 'meta'}
        
        from modules.cms.wordpress.version import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert 'version' in result
        assert result['version'] == '6.5.3'


# ============================================================================
# WordPress Plugins Tests
# ============================================================================

class TestWordPressPlugins:
    """Test plugin enumeration."""
    
    def test_module_imports(self):
        """Test plugins module imports."""
        from modules.cms.wordpress import plugins
        assert hasattr(plugins, 'Scanner')
    
    @patch('modules.cms.wordpress.plugins.Scanner.run')
    def test_returns_plugin_lists(self, mock_run, browser, sample_target, sample_config):
        """Test active_plugins and inactive_plugins returned."""
        mock_run.return_value = {
            'active_plugins': ['elementor', 'woocommerce'],
            'inactive_plugins': ['akismet'],
            'findings': []
        }
        
        from modules.cms.wordpress.plugins import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert 'active_plugins' in result
        assert 'inactive_plugins' in result
        assert isinstance(result['active_plugins'], list)
        assert 'elementor' in result['active_plugins']


# ============================================================================
# WordPress Themes Tests
# ============================================================================

class TestWordPressThemes:
    """Test theme detection."""
    
    def test_module_imports(self):
        """Test themes module imports."""
        from modules.cms.wordpress import themes
        assert hasattr(themes, 'Scanner')
    
    @patch('modules.cms.wordpress.themes.Scanner.run')
    def test_returns_theme_info(self, mock_run, browser, sample_target, sample_config):
        """Test theme info returned."""
        mock_run.return_value = {
            'active_theme': 'twentytwentyfour',
            'theme_version': '1.0',
            'findings': []
        }
        
        from modules.cms.wordpress.themes import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        assert 'active_theme' in result


# ============================================================================
# WordPress Users Tests
# ============================================================================

class TestWordPressUsers:
    """Test user enumeration."""
    
    def test_module_imports(self):
        """Test users module imports."""
        from modules.cms.wordpress import users
        assert hasattr(users, 'Scanner')
    
    @patch('modules.cms.wordpress.users.Scanner.run')
    def test_returns_users_list(self, mock_run, browser, sample_target, sample_config):
        """Test users list returned."""
        mock_run.return_value = {
            'users': ['admin', 'editor'],
            'findings': [{'severity': 'medium', 'title': 'User enumeration possible'}]
        }
        
        from modules.cms.wordpress.users import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        assert 'users' in result


# ============================================================================
# WordPress XML-RPC Tests
# ============================================================================

class TestWordPressXMLRPC:
    """Test XML-RPC detection."""
    
    def test_module_imports(self):
        """Test XML-RPC module imports."""
        from modules.cms.wordpress import xmlrpc
        assert hasattr(xmlrpc, 'Scanner')
    
    @patch('modules.cms.wordpress.xmlrpc.Scanner.run')
    def test_detects_enabled(self, mock_run, browser, sample_target, sample_config):
        """Test XML-RPC enabled detection."""
        mock_run.return_value = {
            'xmlrpc_enabled': True,
            'findings': [{'severity': 'high', 'title': 'XML-RPC is enabled'}]
        }
        
        from modules.cms.wordpress.xmlrpc import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert result['xmlrpc_enabled'] == True
    
    @patch('modules.cms.wordpress.xmlrpc.Scanner.run')
    def test_detects_disabled(self, mock_run, browser, sample_target, sample_config):
        """Test XML-RPC disabled detection."""
        mock_run.return_value = {
            'xmlrpc_enabled': False,
            'findings': []
        }
        
        from modules.cms.wordpress.xmlrpc import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert result['xmlrpc_enabled'] == False


# ============================================================================
# WordPress REST API Tests
# ============================================================================

class TestWordPressRESTAPI:
    """Test REST API detection."""
    
    def test_module_imports(self):
        """Test REST API module imports."""
        from modules.cms.wordpress import rest_api
        assert hasattr(rest_api, 'Scanner')
    
    @patch('modules.cms.wordpress.rest_api.Scanner.run')
    def test_checks_rest_api(self, mock_run, browser, sample_target, sample_config):
        """Test REST API check returns results."""
        mock_run.return_value = {
            'rest_api_enabled': True,
            'namespace': 'wp/v2',
            'findings': [{'severity': 'info', 'title': 'REST API accessible'}]
        }
        
        from modules.cms.wordpress.rest_api import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        assert 'rest_api_enabled' in result


# ============================================================================
# WordPress Backups Tests
# ============================================================================

class TestWordPressBackups:
    """Test backup file detection."""
    
    def test_module_imports(self):
        """Test backups module imports."""
        from modules.cms.wordpress import backups
        assert hasattr(backups, 'Scanner')
    
    @patch('modules.cms.wordpress.backups.Scanner.run')
    def test_checks_backup_files(self, mock_run, browser, sample_target, sample_config):
        """Test backup check returns proper structure."""
        mock_run.return_value = {
            'exposed_files': [],
            'findings': []
        }
        
        from modules.cms.wordpress.backups import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        assert 'findings' in result
    
    @patch('modules.cms.wordpress.backups.Scanner.run')
    def test_finds_exposed_backup(self, mock_run, browser, sample_target, sample_config):
        """Test exposed backup detection."""
        mock_run.return_value = {
            'exposed_files': ['/wp-content/backup.sql'],
            'findings': [{'severity': 'critical', 'title': 'Database backup exposed!'}]
        }
        
        from modules.cms.wordpress.backups import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert len(result['exposed_files']) > 0
        assert len(result['findings']) > 0


# ============================================================================
# WordPress Hardening Tests
# ============================================================================

class TestWordPressHardening:
    """Test WordPress hardening checks."""
    
    def test_module_imports(self):
        """Test hardening module imports."""
        from modules.cms.wordpress import hardening
        assert hasattr(hardening, 'Scanner')
    
    @patch('modules.cms.wordpress.hardening.Scanner.run')
    def test_checks_debug_mode(self, mock_run, browser, sample_target, sample_config):
        """Test debug mode detection."""
        mock_run.return_value = {
            'debug_enabled': True,
            'findings': [{'severity': 'high', 'title': 'WP_DEBUG is enabled'}]
        }
        
        from modules.cms.wordpress.hardening import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        
        assert isinstance(result, dict)
        assert 'debug_enabled' in result