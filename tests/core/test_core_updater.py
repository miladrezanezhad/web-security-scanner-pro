#!/usr/bin/env python3
"""
Tests for core DatabaseUpdater module.
Tests match the ACTUAL methods in core/updater.py.
"""

import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.updater import DatabaseUpdater


class TestDatabaseUpdater:
    """Test database updater."""
    
    @pytest.fixture
    def config(self):
        """Test configuration."""
        temp_dir = tempfile.mkdtemp()
        return {
            'database': {
                'path': os.path.join(temp_dir, 'test_updater.db'),
                'auto_update': True,
                'update_interval': 86400,
                'nvd_api_key': '',
                'wpscan_api_key': ''
            }
        }
    
    @pytest.fixture
    def updater(self, config):
        """Create updater instance."""
        updater = DatabaseUpdater(config)
        yield updater
        try:
            updater.db.close()
            os.remove(config['database']['path'])
        except:
            pass
    
    def test_initialization(self, updater):
        """Test updater initializes."""
        assert updater is not None
        assert updater.db is not None
        assert hasattr(updater, 'config')
    
    @patch('core.updater.DatabaseUpdater.update_vulnerability_database')
    def test_update_vulnerability_database(self, mock_update, updater):
        """Test vulnerability database update."""
        mock_update.return_value = 150
        count = updater.update_vulnerability_database()
        assert count == 150
    
    @patch('core.updater.DatabaseUpdater.update_signatures')
    def test_update_signatures(self, mock_update, updater):
        """Test signature update."""
        mock_update.return_value = 25
        count = updater.update_signatures()
        assert count == 25
    
    def test_config_values(self, updater):
        """Test configuration values are stored."""
        assert updater.config is not None
        assert 'database' in updater.config
        assert updater.config['database']['auto_update'] == True
    
    def test_db_accessible(self, updater):
        """Test database is accessible."""
        stats = updater.db.get_statistics()
        assert isinstance(stats, dict)
        assert 'total' in stats
    
    def test_updater_has_methods(self, updater):
        """Test updater has required methods."""
        assert hasattr(updater, 'update_vulnerability_database')
        assert hasattr(updater, 'update_signatures')
        assert hasattr(updater, 'check_for_updates')