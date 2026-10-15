#!/usr/bin/env python3
"""
Unit tests for the Smart Web Spider & Asset Discovery engine (core/crawler.py).
"""

import pytest
from unittest.mock import MagicMock
from core.crawler import WebCrawler


@pytest.fixture
def mock_html_homepage():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Test App</title></head>
    <body>
        <a href="/about">About Us</a>
        <a href="/contact">Contact Us</a>
        <a href="https://external-domain.com/logout">External Link</a>
        <script src="/static/app.js"></script>

        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>

        <form action="/search" method="GET">
            <input type="text" name="q" />
        </form>
    </body>
    </html>
    """


@pytest.fixture
def mock_js_file():
    return """
    const apiUsers = '/api/v1/users';
    const adminEndpoint = '/admin/dashboard/metrics';
    const imageAsset = '/assets/logo.png';
    function fetchAuth() { return fetch('/auth/token'); }
    """


def test_crawler_page_crawling_and_form_extraction(mock_html_homepage, sample_config):
    """Test crawler correctly crawls root page and extracts HTML forms and internal links."""
    mock_browser = MagicMock()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if url == 'https://example.com' or url == 'https://example.com/':
            resp.headers = {'Content-Type': 'text/html; charset=utf-8'}
            resp.text = mock_html_homepage
            return resp
        elif url in ['https://example.com/about', 'https://example.com/contact']:
            resp.headers = {'Content-Type': 'text/html; charset=utf-8'}
            resp.text = "<html><body>Subpage content</body></html>"
            return resp
        elif 'crt.sh' in url:
            resp.json.return_value = [{'name_value': 'admin.example.com\napi.example.com'}]
            return resp
        resp.status_code = 404
        return resp

    mock_browser.get.side_effect = mock_get

    config = {
        'crawler': {
            'max_depth': 1,
            'max_pages': 10,
            'extract_js_endpoints': False,
            'enumerate_subdomains': False
        }
    }

    crawler = WebCrawler(mock_browser, "https://example.com", config)
    result = crawler.run()

    # Verify discovered links
    assert 'https://example.com/about' in result['discovered_urls_list']
    assert 'https://example.com/contact' in result['discovered_urls_list']
    # External domains must be filtered out
    assert 'https://external-domain.com/logout' not in result['discovered_urls_list']

    # Verify extracted forms
    assert result['forms_discovered'] == 2
    form_actions = [f['action_url'] for f in result['forms_list']]
    assert 'https://example.com/login' in form_actions
    assert 'https://example.com/search' in form_actions


def test_crawler_js_endpoint_extraction(mock_js_file, sample_config):
    """Test parsing JavaScript files for hidden API routes."""
    mock_browser = MagicMock()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if url == 'https://example.com' or url == 'https://example.com/':
            resp.headers = {'Content-Type': 'text/html'}
            resp.text = '<html><head><script src="/static/bundle.js"></script></head><body></body></html>'
            return resp
        elif url == 'https://example.com/static/bundle.js':
            resp.headers = {'Content-Type': 'application/javascript'}
            resp.text = mock_js_file
            return resp
        resp.status_code = 404
        return resp

    mock_browser.get.side_effect = mock_get

    config = {
        'crawler': {
            'max_depth': 1,
            'max_pages': 5,
            'extract_js_endpoints': True,
            'enumerate_subdomains': False
        }
    }

    crawler = WebCrawler(mock_browser, "https://example.com", config)
    crawler.discovered_urls.add('https://example.com/static/bundle.js')
    result = crawler.run()

    # Verify extracted JS routes
    assert '/api/v1/users' in result['js_endpoints_list']
    assert '/admin/dashboard/metrics' in result['js_endpoints_list']
    assert '/auth/token' in result['js_endpoints_list']
    # Image assets should be filtered
    assert '/assets/logo.png' not in result['js_endpoints_list']


def test_crawler_subdomain_discovery(sample_config):
    """Test passive subdomain enumeration via Certificate Transparency logs."""
    mock_browser = MagicMock()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if 'crt.sh' in url:
            resp.json.return_value = [
                {'name_value': 'mail.example.com\n*.example.com'},
                {'name_value': 'vpn.example.com'},
                {'name_value': 'unrelated-domain.org'}
            ]
            return resp
        resp.headers = {'Content-Type': 'text/html'}
        resp.text = "<html><body>Hello</body></html>"
        return resp

    mock_browser.get.side_effect = mock_get

    config = {
        'crawler': {
            'max_depth': 0,
            'max_pages': 1,
            'extract_js_endpoints': False,
            'enumerate_subdomains': True
        }
    }

    crawler = WebCrawler(mock_browser, "https://example.com", config)
    result = crawler.run()

    # Subdomains should be populated and filtered
    assert 'mail.example.com' in result['subdomains_list']
    assert 'vpn.example.com' in result['subdomains_list']
    assert 'unrelated-domain.org' not in result['subdomains_list']
    assert '*.example.com' not in result['subdomains_list']
