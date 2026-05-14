#!/usr/bin/env python3
"""
Tests for core SecurityScanner module.
"""

import sys
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.scanner import SecurityScanner, ScanResult, Finding


class TestFinding:
    """Test Finding data model."""
    
    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            title="Test Vulnerability",
            severity="high",
            description="A test finding",
            recommendation="Fix it",
            module="test_module",
            cve_id="CVE-TEST-001",
            cvss_score=8.5
        )
        
        assert finding.title == "Test Vulnerability"
        assert finding.severity == "high"
        assert finding.cve_id == "CVE-TEST-001"
        assert finding.cvss_score == 8.5
    
    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = Finding(
            title="Test",
            severity="critical",
            description="Description",
            recommendation="Recommendation",
            module="test"
        )
        
        result = finding.to_dict()
        
        assert isinstance(result, dict)
        assert result['title'] == "Test"
        assert result['severity'] == "critical"
        assert 'timestamp' in result


class TestScanResult:
    """Test ScanResult container."""
    
    @pytest.fixture
    def scan_result(self):
        """Create a scan result."""
        return ScanResult(target_url="https://example.com")
    
    def test_initialization(self, scan_result):
        """Test scan result initialization."""
        assert scan_result.target_url == "https://example.com"
        assert scan_result.scan_time is not None
        assert scan_result.statistics['total'] == 0
    
    def test_add_finding(self, scan_result):
        """Test adding findings updates statistics."""
        finding = Finding(
            title="Critical Bug",
            severity="critical",
            description="Very bad",
            recommendation="Fix ASAP",
            module="test"
        )
        
        scan_result.add_finding(finding)
        
        assert scan_result.statistics['critical'] == 1
        assert scan_result.statistics['total'] == 1
    
    def test_to_dict(self, scan_result):
        """Test converting to dictionary."""
        scan_result.add_finding(
            Finding("Test", "info", "Desc", "Rec", "test")
        )
        
        result = scan_result.to_dict()
        
        assert isinstance(result, dict)
        assert result['target_url'] == "https://example.com"
        assert 'statistics' in result
        assert 'findings' in result


class TestSecurityScanner:
    """Test the main scanner orchestrator."""
    
    @pytest.fixture
    def config(self):
        return {
            'scan_mode': {
                'default': 'normal',
                'timeout': 5,
                'max_requests_per_second': 10.0
            },
            'modules': {
                'cms': {'wordpress': True},
                'php': True,
                'headers': True
            }
        }
    
    @pytest.fixture
    def scanner(self, config):
        """Create a scanner instance."""
        return SecurityScanner("https://example.com", config)
    
    def test_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner is not None
        assert scanner.target_url == "https://example.com"
        assert scanner.browser is not None
        assert scanner.evasion is not None
        assert scanner.result is not None
    
    def test_module_map_has_entries(self, scanner):
        """Test that module map has entries."""
        assert len(scanner.MODULE_MAP) > 0
        assert 'wordpress' in scanner.MODULE_MAP
        assert 'xss' in scanner.MODULE_MAP
        assert 'sqli' in scanner.MODULE_MAP
    
    def test_resolve_modules_returns_list(self, scanner):
        """Test module resolution returns a list."""
        modules = scanner._resolve_modules(None)
        assert isinstance(modules, list)
        assert len(modules) > 0
    
    def test_invalid_module_returns_none(self, scanner):
        """Test that invalid module returns None."""
        result = scanner._run_module_sync('nonexistent_module')
        assert result is None
    
    def test_process_module_result(self, scanner):
        """Test processing module results."""
        scanner._process_module_result('test_module', {
            'findings': [
                {
                    'title': 'Test Bug',
                    'severity': 'critical',
                    'description': 'A test bug',
                    'recommendation': 'Fix it',
                    'module': 'test_module',
                    'cvss_score': 9.5
                }
            ]
        })
        
        assert 'test_module' in scanner.result.modules_run
        assert scanner.result.statistics['critical'] >= 1
    
    def test_print_summary_no_crash(self, scanner):
        """Test that print_summary doesn't crash."""
        scanner.result.add_finding(
            Finding("Test", "high", "Desc", "Rec", "test")
        )
        scanner.print_summary()
    
    def test_to_json(self, scanner):
        """Test JSON export."""
        scanner.result.add_finding(
            Finding("Test", "medium", "Desc", "Rec", "test")
        )
        
        json_str = scanner.to_json()
        
        assert isinstance(json_str, str)
        import json
        data = json.loads(json_str)
        assert data['target_url'] == "https://example.com"