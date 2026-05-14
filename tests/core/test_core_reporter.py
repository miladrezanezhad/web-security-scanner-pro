#!/usr/bin/env python3
"""
Tests for core ReportGenerator module.
"""

import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.reporter import ReportGenerator


class TestReportGenerator:
    """Test report generation."""
    
    @pytest.fixture
    def sample_results(self):
        """Create sample scan results."""
        return {
            'target_url': 'https://example.com',
            'scan_time': '2026-05-14 10:00:00',
            'scan_duration': 45.5,
            'scan_mode': 'stealth',
            'timeout': 30,
            'rps': 1.0,
            'modules_run': ['wordpress', 'xss', 'sqli'],
            'findings': [
                {
                    'title': 'SQL Injection Vulnerability',
                    'severity': 'critical',
                    'description': 'SQL injection found in search parameter',
                    'recommendation': 'Use parameterized queries',
                    'module': 'sqli',
                    'cve_id': 'CVE-2024-1234',
                    'cvss_score': 9.8,
                },
                {
                    'title': 'XSS Vulnerability',
                    'severity': 'high',
                    'description': 'Reflected XSS in comment field',
                    'recommendation': 'Implement output encoding',
                    'module': 'xss',
                    'cvss_score': 7.5
                },
                {
                    'title': 'Missing Security Headers',
                    'severity': 'medium',
                    'description': 'HSTS header not set',
                    'recommendation': 'Add Strict-Transport-Security header',
                    'module': 'headers',
                    'cvss_score': 5.0
                }
            ],
            'module_results': {},
            'statistics': {
                'critical': 1,
                'high': 1,
                'medium': 1,
                'low': 0,
                'info': 0,
                'total': 3
            }
        }
    
    @pytest.fixture
    def config(self):
        """Sample config."""
        return {
            'reporting': {
                'output_directory': 'tests/test_output',
                'formats': ['html', 'json', 'markdown']
            }
        }
    
    @pytest.fixture
    def reporter(self, sample_results, config):
        """Create reporter instance."""
        return ReportGenerator(sample_results, config)
    
    def test_initialization(self, reporter):
        """Test reporter initializes."""
        assert reporter is not None
        assert reporter.results is not None
    
    def test_prepare_data(self, reporter):
        """Test data preparation."""
        data = reporter._prepare_data()
        
        assert isinstance(data, dict)
        assert data['target_url'] == 'https://example.com'
        assert data['critical_count'] == 1
        assert data['high_count'] == 1
        assert data['total_count'] == 3
        assert 'risk_score' in data
        assert 'risk_level' in data
    
    def test_get_output_path_with_filename(self, reporter):
        """Test output path with custom filename."""
        path = reporter._get_output_path('html', None, 'test_report')
        assert 'test_report.html' in str(path)
    
    def test_get_output_path_auto_generated(self, reporter):
        """Test auto-generated filename."""
        path = reporter._get_output_path('pdf', None, None)
        assert 'scan_report_' in str(path)
        assert str(path).endswith('.pdf')
    
    def test_generate_html(self, reporter):
        """Test HTML report generation."""
        os.makedirs('tests/test_output', exist_ok=True)
        
        path = reporter.generate('html', filename='test_html_report')
        
        assert os.path.exists(path)
        assert path.endswith('.html')
        os.remove(path)
    
    def test_generate_json(self, reporter):
        """Test JSON report generation."""
        os.makedirs('tests/test_output', exist_ok=True)
        
        path = reporter.generate('json', filename='test_json_report')
        
        assert os.path.exists(path)
        assert path.endswith('.json')
        
        import json
        with open(path, 'r') as f:
            data = json.load(f)
            assert 'findings' in data
        os.remove(path)
    
    def test_generate_markdown(self, reporter):
        """Test Markdown report generation."""
        os.makedirs('tests/test_output', exist_ok=True)
        
        path = reporter.generate('markdown', filename='test_md_report')
        
        assert os.path.exists(path)
        assert path.endswith('.md')
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            assert len(content) > 0
        os.remove(path)
    
    def test_generate_all(self, reporter):
        """Test generating all formats at once."""
        os.makedirs('tests/test_output', exist_ok=True)
        
        paths = reporter.generate_all(filename='test_all_report')
        
        assert isinstance(paths, dict)
        assert 'html' in paths
        assert 'json' in paths
        assert 'markdown' in paths
        
        for path in paths.values():
            if path and os.path.exists(path):
                os.remove(path)
    
    def test_format_duration(self, reporter):
        """Test duration formatting."""
        assert '45.5 seconds' == reporter._format_duration(45.5)
    
    def test_filter_recommendations(self, reporter):
        """Test filtering recommendations by severity."""
        recs = reporter._filter_recommendations(
            reporter.results['findings'], 'critical'
        )
        assert isinstance(recs, str)