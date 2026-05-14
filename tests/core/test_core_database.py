#!/usr/bin/env python3
"""
Tests for core VulnerabilityDatabase module.
Tests database operations, version checking, and CVE lookups.
"""

import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.database import VulnerabilityDatabase


class TestVulnerabilityDatabase:
    """Test the vulnerability database."""
    
    @pytest.fixture
    def db(self):
        """Create a temporary database for testing."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test_vulns.db")
        
        db = VulnerabilityDatabase(db_path)
        yield db
        
        db.close()
        try:
            os.remove(db_path)
            os.rmdir(temp_dir)
        except:
            pass
    
    def test_database_creation(self, db):
        """Test database is created with tables."""
        assert db is not None
        assert db.conn is not None
        
        db.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in db.cursor.fetchall()]
        
        assert 'vulnerabilities' in tables
        assert 'safe_versions' in tables
    
    def test_seed_data(self, db):
        """Test seed data is populated."""
        db.cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        count = db.cursor.fetchone()[0]
        assert count > 0, f"Expected vulnerabilities, got {count}"
    
    def test_check_core_version_vulnerable(self, db):
        """Test checking a vulnerable WordPress version."""
        vulns = db.check_component("WordPress Core", "6.0")
        assert isinstance(vulns, list)
    
    def test_check_core_version_safe(self, db):
        """Test checking a safe version."""
        vulns = db.check_component("WordPress Core", "99.0")
        assert isinstance(vulns, list)
        assert len(vulns) == 0
    
    def test_check_php_version(self, db):
        """Test PHP version checking."""
        vulns = db.check_component("PHP", "8.1.0")
        assert isinstance(vulns, list)
    
    def test_check_plugin_version(self, db):
        """Test plugin version checking."""
        vulns = db.check_component("Elementor", "3.10.0")
        assert isinstance(vulns, list)
    
    def test_search_by_cve(self, db):
        """Test CVE search."""
        result = db.search_by_cve("CVE-2024-4577")
        if result:
            assert result['component'] == "PHP"
    
    def test_get_latest_safe_version(self, db):
        """Test getting latest safe version."""
        version = db.get_latest_safe_version("WordPress")
        if version:
            assert 'latest_safe_version' in version
    
    def test_get_statistics(self, db):
        """Test database statistics."""
        stats = db.get_statistics()
        assert isinstance(stats, dict)
        assert 'total' in stats
    
    def test_version_comparison_logic(self, db):
        """Test version comparison."""
        assert db._is_version_affected("5.0", "< 6.0") == True
        assert db._is_version_affected("7.0", "< 6.0") == False
        assert db._is_version_affected("5.0", "<= 5.0") == True
        assert db._is_version_affected("5.5", "5.0 - 6.0") == True
        assert db._is_version_affected("7.0", "5.0 - 6.0") == False
    
    def test_add_custom_vulnerability(self, db):
        """Test adding custom vulnerability."""
        db.cursor.execute("""
            INSERT INTO vulnerabilities 
            (id, category, component, title, description, affected_versions, 
             fixed_version, severity, cvss_score, cve_id, refs, publish_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ('TEST-001', 'test', 'Test Component', 'Test Vuln',
              'A test', '< 1.0', '1.0', 'critical', 10.0, 'CVE-TEST-001', '', '2026-01-01'))
        db.conn.commit()
        
        vulns = db.check_component("Test Component", "0.5")
        assert len(vulns) >= 1
    
    def test_multiple_categories(self, db):
        """Test multiple categories exist."""
        db.cursor.execute("SELECT DISTINCT category FROM vulnerabilities")
        categories = [row[0] for row in db.cursor.fetchall()]
        assert len(categories) > 0