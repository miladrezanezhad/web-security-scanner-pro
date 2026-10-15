#!/usr/bin/env python3
"""
Smart Web Spider & Asset Discovery Engine for Web Security Analyzer Pro.
Performs comprehensive web crawling, form harvesting, JavaScript endpoint extraction,
and passive subdomain discovery (crt.sh).

Features:
    - Recursive breadth-first web crawling with configurable depth and page limits
    - HTML <form> input extraction (parameters, actions, methods) for vulnerability feeding
    - Regex-based REST & GraphQL endpoint discovery inside JavaScript assets (.js files)
    - Passive subdomain enumeration via Certificate Transparency (crt.sh)
    - Deduplication and domain-boundary enforcement (stays within target scope)
"""

import re
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
from loguru import logger


class WebCrawler:
    """Smart web crawler, form parser, and asset discovery engine."""

    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize the crawler.

        Args:
            browser: StealthBrowser instance
            target_url: Root target URL to crawl
            config: Scanner configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.module_name = "Smart Web Spider & Asset Discovery"

        # Crawler configuration parameters
        crawl_cfg = config.get('crawler', {})
        self.max_depth = crawl_cfg.get('max_depth', 2)
        self.max_pages = crawl_cfg.get('max_pages', 30)
        self.extract_js_endpoints = crawl_cfg.get('extract_js_endpoints', True)
        self.enumerate_subdomains = crawl_cfg.get('enumerate_subdomains', True)

        parsed = urlparse(self.target_url)
        self.target_domain = parsed.netloc.split(':')[0]
        self.scheme = parsed.scheme

        # Internal collections
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Dict] = []
        self.js_endpoints: Set[str] = set()
        self.subdomains: Set[str] = set()
        self.findings = []

    def run(self) -> Dict:
        """
        Execute full crawling and asset discovery process.

        Returns:
            Dict containing crawled URLs, discovered forms, JS endpoints, and findings
        """
        logger.info(f"Starting {self.module_name} for {self.target_url}")

        # 1. Crawl internal web pages and harvest forms/links
        self._crawl()

        # 2. Extract API endpoints from referenced JavaScript files
        if self.extract_js_endpoints:
            self._analyze_javascript_files()

        # 3. Passive subdomain discovery via Certificate Transparency logs
        if self.enumerate_subdomains:
            self._discover_subdomains()

        # Generate findings for interesting architectural discoveries
        self._generate_findings()

        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'urls_crawled': len(self.visited_urls),
            'urls_discovered': len(self.discovered_urls),
            'forms_discovered': len(self.discovered_forms),
            'js_endpoints_discovered': len(self.js_endpoints),
            'subdomains_discovered': len(self.subdomains),
            'discovered_urls_list': sorted(list(self.discovered_urls)),
            'forms_list': self.discovered_forms,
            'js_endpoints_list': sorted(list(self.js_endpoints)),
            'subdomains_list': sorted(list(self.subdomains)),
            'findings': self.findings
        }

        logger.info(
            f"{self.module_name} complete. "
            f"Pages: {len(self.visited_urls)}, Forms: {len(self.discovered_forms)}, "
            f"JS Endpoints: {len(self.js_endpoints)}, Subdomains: {len(self.subdomains)}"
        )
        return result

    def _crawl(self):
        """Breadth-first search crawler constrained to target domain."""
        queue: List[Tuple[str, int]] = [(self.target_url, 0)]
        self.discovered_urls.add(self.target_url)

        while queue and len(self.visited_urls) < self.max_pages:
            current_url, depth = queue.pop(0)

            clean_url, _ = urldefrag(current_url)
            if clean_url in self.visited_urls:
                continue

            self.visited_urls.add(clean_url)

            # Skip non-HTML files from deep crawling
            if clean_url.endswith(('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.css', '.woff', '.woff2', '.svg')):
                continue

            try:
                resp = self.browser.get(clean_url)
                if not resp or resp.status_code != 200:
                    continue

                content_type = resp.headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                    continue

                # Parse forms and extract links
                soup = BeautifulSoup(resp.text, 'html.parser')
                self._extract_forms(soup, clean_url)

                if depth < self.max_depth:
                    links = self._extract_links(soup, clean_url)
                    for link in links:
                        if link not in self.discovered_urls:
                            self.discovered_urls.add(link)
                            queue.append((link, depth + 1))

            except Exception as e:
                logger.debug(f"Crawler error on {clean_url}: {e}")

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all valid same-domain links from HTML."""
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue

            absolute_url = urljoin(base_url, href)
            parsed = urlparse(absolute_url)

            # Restrict to target domain only
            if parsed.netloc.split(':')[0] == self.target_domain:
                clean_url, _ = urldefrag(absolute_url)
                links.append(clean_url)

        return links

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        """Extract form inputs and methods for vulnerability modules."""
        for form in soup.find_all('form'):
            action = form.get('action', '').strip()
            method = form.get('method', 'GET').upper()
            action_url = urljoin(page_url, action) if action else page_url

            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_name = inp.get('name')
                inp_type = inp.get('type', 'text').lower()
                inp_val = inp.get('value', '')
                if inp_name:
                    inputs.append({
                        'name': inp_name,
                        'type': inp_type,
                        'value': inp_val
                    })

            if inputs:
                form_entry = {
                    'page_url': page_url,
                    'action_url': action_url,
                    'method': method,
                    'inputs': inputs
                }
                # Prevent duplicate form registration
                if form_entry not in self.discovered_forms:
                    self.discovered_forms.append(form_entry)

    def _analyze_javascript_files(self):
        """Inspect JavaScript assets for hidden API routes and parameters."""
        logger.info("Inspecting JavaScript bundles for hidden API routes...")
        js_urls = [u for u in self.discovered_urls if u.endswith('.js')]

        # Regex patterns for finding REST routes inside client-side JS
        route_pattern = re.compile(
            r'["\'](/(?:api|v[1-9]|auth|admin|users|internal)/[a-zA-Z0-9_\-\./]+)["\']',
            re.IGNORECASE
        )

        for js_url in js_urls[:15]:
            try:
                resp = self.browser.get(js_url)
                if resp and resp.status_code == 200:
                    matches = route_pattern.findall(resp.text)
                    for route in matches:
                        if not route.endswith(('.png', '.svg', '.jpg', '.css', '.js')):
                            self.js_endpoints.add(route)
            except Exception as e:
                logger.debug(f"Failed to inspect JS file {js_url}: {e}")

    def _discover_subdomains(self):
        """Passive subdomain discovery using Certificate Transparency logs via crt.sh."""
        logger.info(f"Querying Certificate Transparency logs for subdomains of {self.target_domain}...")
        try:
            # Query crt.sh JSON endpoint for target domain
            crt_url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            resp = self.browser.get(crt_url, timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for sub in name_value.split('\n'):
                            sub = sub.strip().lower()
                            if sub and '*' not in sub and sub.endswith(self.target_domain):
                                self.subdomains.add(sub)
        except Exception as e:
            logger.debug(f"Certificate Transparency lookup failed: {e}")

    def _generate_findings(self):
        """Generate architectural and security findings based on crawl data."""
        # 1. Informational finding for attack surface summary
        if self.discovered_forms:
            self.findings.append({
                'title': f"Attack Surface: {len(self.discovered_forms)} interactive web forms discovered",
                'severity': 'info',
                'description': (
                    f"The web spider identified {len(self.discovered_forms)} HTML forms across {len(self.visited_urls)} pages. "
                    "These form endpoints accept user input and should be verified for CSRF, XSS, and SQL Injection."
                ),
                'recommendation': "Ensure all identified forms enforce CSRF tokens and server-side input validation.",
                'module': self.module_name,
                'evidence': f"Forms discovered on: {', '.join([f['page_url'] for f in self.discovered_forms[:5]])}",
            })

        # 2. Informational finding for hidden JavaScript endpoints
        if self.js_endpoints:
            self.findings.append({
                'title': f"API Endpoints Discovered in Client JavaScript ({len(self.js_endpoints)} routes)",
                'severity': 'low',
                'description': (
                    f"Client-side JavaScript bundles revealed {len(self.js_endpoints)} API endpoints. "
                    "Unintended route disclosure can help attackers map administrative or internal APIs."
                ),
                'recommendation': "Verify that all client-referenced API endpoints require strict server-side authorization.",
                'module': self.module_name,
                'evidence': f"Endpoints: {', '.join(sorted(list(self.js_endpoints))[:8])}",
            })

        # 3. Subdomains discovery finding
        if self.subdomains:
            self.findings.append({
                'title': f"Asset Discovery: {len(self.subdomains)} subdomains identified via CT Logs",
                'severity': 'info',
                'description': (
                    f"Certificate Transparency logs revealed {len(self.subdomains)} active subdomains for {self.target_domain}. "
                    "Expanding asset discovery helps maintain visibility over organization attack surface."
                ),
                'recommendation': "Regularly audit organization subdomains to prevent subdomain takeover and legacy exposures.",
                'module': self.module_name,
                'evidence': f"Subdomains: {', '.join(sorted(list(self.subdomains))[:10])}",
            })


class Scanner(WebCrawler):
    """Compatibility alias for module discovery."""
    pass
