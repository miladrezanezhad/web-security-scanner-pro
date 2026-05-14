#!/usr/bin/env python3
"""
Tests for database security modules.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestMySQL:
    """Test MySQL security module."""
    
    def test_module_imports(self):
        """Test that MySQL module can be imported."""
        try:
            from modules.database import mysql
            assert hasattr(mysql, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import MySQL module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.database.mysql import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestPostgreSQL:
    """Test PostgreSQL security module."""
    
    def test_module_imports(self):
        """Test that PostgreSQL module can be imported."""
        try:
            from modules.database import postgresql
            assert hasattr(postgresql, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import PostgreSQL module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.database.postgresql import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestRedis:
    """Test Redis security module."""
    
    def test_module_imports(self):
        """Test that Redis module can be imported."""
        try:
            from modules.database import redis
            assert hasattr(redis, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import Redis module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.database.redis import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')


class TestMongoDB:
    """Test MongoDB security module."""
    
    def test_module_imports(self):
        """Test that MongoDB module can be imported."""
        try:
            from modules.database import mongodb
            assert hasattr(mongodb, 'Scanner')
        except ImportError as e:
            pytest.fail(f"Failed to import MongoDB module: {e}")
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        """Test scanner initialization."""
        from modules.database.mongodb import Scanner
        
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')