#!/usr/bin/env python3
"""
Out-of-Band (OOB) Interaction & Callback Engine for Web Security Analyzer Pro.
Enables detection of blind vulnerabilities (Blind SSRF, Blind RCE, Blind XXE, Blind SQLi)
by listening for incoming DNS queries and HTTP requests triggered by the target server.

Supports:
    - Local HTTP Callback Listener (threaded daemon for local/LAN testing)
    - Public/Self-hosted Interactsh server protocols & REST API polling
    - Custom callback server webhook polling (e.g. webhook.site, custom DNS listener)
    - Unique correlation token generation per parameter & target
"""

import time
import uuid
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional
import requests
from loguru import logger


class LocalHTTPCallbackHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for local OOB callback detection."""
    engine = None

    def log_message(self, format, *args):
        # Suppress standard HTTP server console logging
        pass

    def do_GET(self):
        self._record_interaction('GET')

    def do_POST(self):
        self._record_interaction('POST')

    def do_HEAD(self):
        self._record_interaction('HEAD')

    def _record_interaction(self, method: str):
        if LocalHTTPCallbackHandler.engine:
            path_str = self.path
            headers_str = str(self.headers)
            full_raw = f"{method} {path_str}\n{headers_str}"
            LocalHTTPCallbackHandler.engine._record_local_hit(full_raw)

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OOB Callback Received OK\n")


class OOBEngine:
    """Manages Out-of-Band callback sessions, payload generation, and interaction polling."""

    def __init__(self, config: Dict):
        """
        Initialize the OOB Engine.

        Args:
            config: General scanner configuration dictionary
        """
        self.config = config
        self.oob_config = config.get('oob', {})
        self.enabled = self.oob_config.get('enabled', True)
        self.provider = self.oob_config.get('provider', 'interactsh').lower()
        self.server_host = self.oob_config.get('server_host', 'oast.pro')
        self.custom_url = self.oob_config.get('custom_url', '')

        self.use_local_listener = self.oob_config.get('local_listener', True)
        self.local_port = self.oob_config.get('local_port', 8888)
        self.local_host = self.oob_config.get('local_host', '127.0.0.1')

        self.session_id = uuid.uuid4().hex[:8]
        self.registered_tokens: Dict[str, Dict] = {}
        self.local_hits: List[str] = []
        self.poll_history: List[Dict] = []

        self._server_thread = None
        self._httpd = None

        if self.enabled and self.use_local_listener:
            self._start_local_listener()

    def _start_local_listener(self):
        """Start a background daemon thread for capturing local OOB callbacks."""
        try:
            LocalHTTPCallbackHandler.engine = self
            self._httpd = HTTPServer(('0.0.0.0', self.local_port), LocalHTTPCallbackHandler)
            self._server_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._server_thread.start()
            logger.info(f"Local OOB Callback Server listening on port {self.local_port}")
        except Exception as e:
            logger.debug(f"Could not start local OOB HTTP server on port {self.local_port}: {e}")

    def _record_local_hit(self, raw_data: str):
        """Record an incoming HTTP request raw payload."""
        self.local_hits.append(raw_data)

    def get_payload(self, vuln_type: str = "ssrf", param_name: str = "param") -> Dict[str, str]:
        """
        Generate unique DNS, HTTP, and protocol payloads tied to a correlation token.

        Args:
            vuln_type: Vulnerability type (ssrf, rce, xxe)
            param_name: Target parameter name being tested

        Returns:
            Dict containing payload strings for HTTP, DNS, and URL
        """
        token = f"{vuln_type[:4]}-{uuid.uuid4().hex[:6]}"
        unique_domain = f"{token}.{self.session_id}.{self.server_host}"
        local_callback_url = f"http://{self.local_host}:{self.local_port}/{token}"

        self.registered_tokens[token] = {
            'vuln_type': vuln_type,
            'param_name': param_name,
            'domain': unique_domain,
            'local_url': local_callback_url,
            'timestamp': time.time(),
            'triggered': False
        }

        # Select host/URL based on configuration
        target_url = local_callback_url if self.use_local_listener else f"http://{unique_domain}"

        return {
            'token': token,
            'domain': unique_domain,
            'http_url': target_url,
            'https_url': f"https://{unique_domain}",
            'dns_query': unique_domain,
            'nslookup_cmd': f"nslookup {unique_domain}",
            'curl_cmd': f"curl -m 3 {target_url}",
            'xxe_entity': f'<!ENTITY % oob SYSTEM "{target_url}">%oob;'
        }

    def poll_interactions(self, timeout: int = 2) -> List[Dict]:
        """
        Query the callback provider / local hits to check if any target has connected back.

        Args:
            timeout: Seconds to wait before checking

        Returns:
            List of confirmed interaction events
        """
        if not self.enabled:
            return []

        time.sleep(timeout)
        interactions = []

        # 1. Check local HTTP listener hits
        if self.local_hits:
            combined_hits = "\n".join(self.local_hits)
            for token, meta in self.registered_tokens.items():
                if token in combined_hits and not meta['triggered']:
                    meta['triggered'] = True
                    interactions.append({
                        'token': token,
                        'vuln_type': meta['vuln_type'],
                        'param_name': meta['param_name'],
                        'protocol': 'HTTP/Local',
                        'domain': meta['domain'],
                        'raw': f'Confirmed local HTTP callback on port {self.local_port}'
                    })

        # 2. Check custom webhook URL if configured
        if self.custom_url:
            try:
                resp = requests.get(self.custom_url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json() if 'json' in resp.headers.get('content-type', '') else resp.text
                    raw_text = str(data)
                    for token, meta in self.registered_tokens.items():
                        if token in raw_text and not meta['triggered']:
                            meta['triggered'] = True
                            interactions.append({
                                'token': token,
                                'vuln_type': meta['vuln_type'],
                                'param_name': meta['param_name'],
                                'protocol': 'HTTP/DNS',
                                'domain': meta['domain'],
                                'raw': 'Callback verified via custom endpoint'
                            })
            except Exception as e:
                logger.debug(f"Custom OOB polling error: {e}")

        # 3. Check Interactsh HTTP REST API endpoint
        if self.provider == 'interactsh' and not self.custom_url:
            try:
                poll_url = f"https://{self.server_host}/poll?id={self.session_id}"
                resp = requests.get(poll_url, timeout=4)
                if resp.status_code == 200:
                    raw_text = resp.text
                    for token, meta in self.registered_tokens.items():
                        if token in raw_text and not meta['triggered']:
                            meta['triggered'] = True
                            interactions.append({
                                'token': token,
                                'vuln_type': meta['vuln_type'],
                                'param_name': meta['param_name'],
                                'protocol': 'DNS/HTTP (Interactsh)',
                                'domain': meta['domain'],
                                'raw': 'Out-of-band correlation confirmed via Interactsh'
                            })
            except Exception as e:
                logger.debug(f"Interactsh poll note: {e}")

        # 4. Check mock / simulated hits for offline testing
        for token, meta in self.registered_tokens.items():
            if meta.get('simulated_hit') and not meta['triggered']:
                meta['triggered'] = True
                interactions.append({
                    'token': token,
                    'vuln_type': meta['vuln_type'],
                    'param_name': meta['param_name'],
                    'protocol': 'DNS/HTTP',
                    'domain': meta['domain'],
                    'raw': 'Out-of-band correlation confirmed'
                })

        return interactions

    def stop(self):
        """Stop local HTTP listener server cleanly."""
        if self._httpd:
            try:
                self._httpd.shutdown()
                logger.info("Local OOB Callback Server stopped.")
            except Exception:
                pass

