#!/usr/bin/env python3
"""
Unit tests for CISA KEV and GitHub Advisory database updates.
"""

import pytest
from unittest.mock import patch, MagicMock
from core.updater import DatabaseUpdater
from core.database import VulnerabilityDatabase


@pytest.fixture
def test_updater(tmp_path):
    """Create a DatabaseUpdater with a temporary database."""
    db_file = tmp_path / "test_vulns.db"
    config = {
        'database': {
            'path': str(db_file),
            'nvd_api_key': '',
            'wpscan_api_key': ''
        }
    }
    return DatabaseUpdater(config)


@patch('requests.get')
def test_update_from_cisa_kev(mock_get, test_updater):
    """Test importing web vulnerabilities from CISA KEV catalog."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        'title': 'CISA KEV Catalog',
        'vulnerabilities': [
            {
                'cveID': 'CVE-2024-4577',
                'vendorProject': 'PHP',
                'product': 'PHP CGI',
                'vulnerabilityName': 'PHP CGI Argument Injection',
                'dateAdded': '2024-06-10',
                'shortDescription': 'PHP CGI argument injection vulnerability allows remote code execution.',
                'cwes': ['CWE-78']
            },
            {
                # Non-web vendor should be ignored
                'cveID': 'CVE-2024-0001',
                'vendorProject': 'AutomotiveHardwareCorp',
                'product': 'EngineController',
                'vulnerabilityName': 'CAN Bus Overflow',
                'dateAdded': '2024-01-01',
                'shortDescription': 'Vehicle brake system issue.',
                'cwes': ['CWE-120']
            }
        ]
    }
    mock_get.return_value = mock_resp

    count = test_updater._update_from_cisa_kev()
    assert count == 1

    # Verify record in database
    vuln = test_updater.db.search_by_cve('CVE-2024-4577')
    assert vuln is not None
    assert vuln['component'] == 'PHP CGI'
    assert vuln['severity'] == 'critical'
    assert vuln['exploit_available'] == 1


@patch('requests.get')
def test_update_from_github_advisories(mock_get, test_updater):
    """Test importing vulnerabilities from GitHub Security Advisories API."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            'ghsa_id': 'GHSA-xxxx-yyyy-zzzz',
            'cve_id': 'CVE-2024-8888',
            'summary': 'Next.js Server Actions RCE',
            'description': 'Critical flaw in server action deserialization.',
            'severity': 'critical',
            'html_url': 'https://github.com/advisories/GHSA-xxxx',
            'published_at': '2024-08-15T12:00:00Z',
            'vulnerabilities': [
                {
                    'package': {
                        'name': 'next',
                        'ecosystem': 'npm'
                    },
                    'vulnerable_version_range': '< 14.2.5',
                    'first_patched_version': '14.2.5'
                }
            ],
            'cvss': {'score': 9.8},
            'cwes': [{'cwe_id': 'CWE-94'}]
        }
    ]
    mock_get.return_value = mock_resp

    count = test_updater._update_from_github_advisory()
    assert count == 1

    vuln = test_updater.db.search_by_cve('CVE-2024-8888')
    assert vuln is not None
    assert vuln['component'] == 'next'
    assert vuln['severity'] == 'critical'
    assert vuln['fixed_version'] == '14.2.5'
