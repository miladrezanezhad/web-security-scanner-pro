#!/usr/bin/env python3
"""
Template-Based Security Scanner Engine for Web Security Analyzer Pro.
Executes declarative YAML vulnerability templates similar to Nuclei.
Allows users and security researchers to add new 0-day/CVE checks without writing Python code.

Template YAML Schema:
    id: unique-template-id
    info:
      name: Vulnerability Name
      author: Author Name
      severity: critical | high | medium | low | info
      description: Description of the vulnerability
      reference: [https://...]
      cve_id: CVE-YYYY-NNNN
      cvss_score: 9.8
    requests:
      - method: GET | POST
        path:
          - "/path/to/test"
        headers:
          Header-Name: Value
        body: "raw body or payload"
        matchers_condition: and | or
        matchers:
          - type: word | regex | status
            words: ["pattern1", "pattern2"]
            regex: ["regex1"]
            status: [200, 301]
            condition: and | or
            part: body | header | all
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
from loguru import logger


class TemplateScanner:
    """Evaluates declarative YAML security templates against targets."""

    def __init__(self, browser, target_url: str, config: Dict, templates_dir: Optional[str] = None):
        """
        Initialize the template scanner.

        Args:
            browser: StealthBrowser instance
            target_url: Target URL to test
            config: General scanner configuration
            templates_dir: Directory containing .yaml/.yml template files
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.module_name = "YAML Template Engine"

        # Determine templates directory
        if templates_dir:
            self.templates_dir = Path(templates_dir)
        else:
            default_dir = Path(__file__).parent.parent / "templates"
            self.templates_dir = Path(config.get('templates', {}).get('directory', default_dir))

        self.findings = []
        self.templates = self._load_templates()

    def _load_templates(self) -> List[Dict]:
        """Discover and load all valid YAML template files."""
        templates = []
        if not self.templates_dir.exists():
            logger.debug(f"Templates directory not found: {self.templates_dir}")
            return templates

        for file_path in self.templates_dir.rglob("*.yaml"):
            t = self._parse_template(file_path)
            if t:
                templates.append(t)

        for file_path in self.templates_dir.rglob("*.yml"):
            t = self._parse_template(file_path)
            if t:
                templates.append(t)

        logger.info(f"Loaded {len(templates)} YAML security templates from {self.templates_dir}")
        return templates

    def _parse_template(self, file_path: Path) -> Optional[Dict]:
        """Safely parse a single template file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and 'id' in data and 'requests' in data:
                    data['_file_path'] = str(file_path)
                    return data
        except Exception as e:
            logger.warning(f"Failed to load template {file_path.name}: {e}")
        return None

    def run(self) -> Dict:
        """
        Execute all loaded templates against target.

        Returns:
            Dict containing template scan statistics and findings
        """
        logger.info(f"Starting {self.module_name} with {len(self.templates)} templates")

        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'templates_loaded': len(self.templates),
            'templates_matched': 0,
            'findings': []
        }

        for template in self.templates:
            finding = self._execute_template(template)
            if finding:
                result['templates_matched'] += 1
                result['findings'].append(finding)

        self.findings = result['findings']
        logger.info(f"{self.module_name} finished. Findings: {len(self.findings)}")
        return result

    def _execute_template(self, template: Dict) -> Optional[Dict]:
        """Execute a template's HTTP requests and evaluate matchers."""
        template_id = template.get('id', 'unknown')
        info = template.get('info', {})
        requests_config = template.get('requests', [])

        for req in requests_config:
            method = req.get('method', 'GET').upper()
            paths = req.get('path', ['/'])
            headers = req.get('headers', {})
            body = req.get('body', None)
            matchers_condition = req.get('matchers_condition', 'and').lower()
            matchers = req.get('matchers', [])

            if not matchers:
                continue

            for path in paths:
                # Format full path
                clean_path = path if path.startswith('/') else f"/{path}"
                resp = None

                try:
                    if method == 'GET':
                        resp = self.browser.get(clean_path, custom_headers=headers)
                    elif method == 'POST':
                        resp = self.browser.post(clean_path, data=body, custom_headers=headers)
                    elif method == 'HEAD':
                        resp = self.browser.head(clean_path)
                except Exception as e:
                    logger.debug(f"Template {template_id} request failed for {clean_path}: {e}")
                    continue

                if resp is None:
                    continue

                # Evaluate all matchers on the response
                is_matched = self._evaluate_matchers(matchers, matchers_condition, resp)
                if is_matched:
                    return self._create_finding(template, clean_path, resp)

        return None

    def _evaluate_matchers(self, matchers: List[Dict], condition: str, response) -> bool:
        """Evaluate a list of matchers against an HTTP response."""
        results = []

        for matcher in matchers:
            m_type = matcher.get('type', 'word').lower()
            part = matcher.get('part', 'body').lower()
            m_condition = matcher.get('condition', 'or').lower()

            # Extract target content from response
            if part == 'header':
                content = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            elif part == 'all':
                header_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
                content = f"{header_str}\n\n{response.text}"
            else:
                content = response.text

            matched = False

            if m_type == 'status':
                expected_status = matcher.get('status', [200])
                if not isinstance(expected_status, list):
                    expected_status = [expected_status]
                matched = response.status_code in expected_status

            elif m_type == 'word':
                words = matcher.get('words', [])
                if m_condition == 'and':
                    matched = all(w in content for w in words)
                else:
                    matched = any(w in content for w in words)

            elif m_type == 'regex':
                patterns = matcher.get('regex', [])
                if m_condition == 'and':
                    matched = all(bool(re.search(p, content, re.MULTILINE)) for p in patterns)
                else:
                    matched = any(bool(re.search(p, content, re.MULTILINE)) for p in patterns)

            results.append(matched)

        if condition == 'or':
            return any(results)
        return all(results) if results else False

    def _create_finding(self, template: Dict, path: str, response) -> Dict:
        """Create a standard Finding dictionary from matched template."""
        info = template.get('info', {})
        name = info.get('name', template.get('id', 'Template Match'))
        severity = info.get('severity', 'medium').lower()
        description = info.get('description', f"Vulnerability detected via template: {template.get('id')}")
        recommendation = info.get('recommendation', 'Review and patch the vulnerable component.')
        cve_id = info.get('cve_id')
        cvss = info.get('cvss_score')
        evidence = f"Matched Path: {path} (HTTP {response.status_code})\nTemplate: {template.get('id')}"

        return {
            'title': f"[Template] {name}",
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'module': self.module_name,
            'cve_id': cve_id,
            'cvss_score': cvss,
            'evidence': evidence,
            'references': info.get('reference', []),
        }


# Module interface compatibility
class Scanner(TemplateScanner):
    """Alias for scanner loader compatibility."""
    pass
