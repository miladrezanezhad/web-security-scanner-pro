#!/usr/bin/env python3
"""
Main Security Scanner Orchestrator Module.
Coordinates all security testing modules and manages the scan lifecycle.

Features:
    - Dynamic module loading
    - Scan progress tracking
    - Result aggregation
    - Severity-based finding classification
    - Comprehensive reporting
"""

import os
import sys
import time
import json
import importlib
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

from core.browser import StealthBrowser
from core.evasion import EvasionEngine, EvasionConfig, ScanMode

console = Console()


@dataclass
class Finding:
    """Security finding data model."""
    title: str
    severity: str
    description: str
    recommendation: str
    module: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Optional[str] = None
    references: Optional[List[str]] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        """Convert finding to dictionary."""
        return {
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'recommendation': self.recommendation,
            'module': self.module,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'evidence': self.evidence,
            'references': self.references,
            'timestamp': self.timestamp,
        }


@dataclass
class ScanResult:
    """Container for complete scan results."""
    target_url: str
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_duration: float = 0.0
    modules_run: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    module_results: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, int] = field(default_factory=lambda: {
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0
    })
    
    def add_finding(self, finding: Finding):
        """Add a finding and update statistics."""
        self.findings.append(finding)
        severity = finding.severity.lower()
        if severity in self.statistics:
            self.statistics[severity] += 1
        self.statistics['total'] += 1
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'target_url': self.target_url,
            'scan_time': self.scan_time,
            'scan_duration': self.scan_duration,
            'modules_run': self.modules_run,
            'findings': [f.to_dict() for f in self.findings],
            'module_results': self.module_results,
            'statistics': self.statistics,
        }


class SecurityScanner:
    """
    Main security scanner orchestrator.
    
    Manages the entire scanning process including:
    - Module discovery and loading
    - Scan execution and coordination
    - Result collection and aggregation
    - Progress reporting
    """
    
    # Module registry: CLI name -> import path
    MODULE_MAP = {
        # CMS
        'wordpress': 'modules.cms.wordpress.detector',
        'wordpress_version': 'modules.cms.wordpress.version',
        'wordpress_plugins': 'modules.cms.wordpress.plugins',
        'wordpress_themes': 'modules.cms.wordpress.themes',
        'wordpress_users': 'modules.cms.wordpress.users',
        'wordpress_xmlrpc': 'modules.cms.wordpress.xmlrpc',
        'wordpress_rest': 'modules.cms.wordpress.rest_api',
        'wordpress_backups': 'modules.cms.wordpress.backups',
        'wordpress_hardening': 'modules.cms.wordpress.hardening',
        'joomla': 'modules.cms.joomla.scanner',
        'drupal': 'modules.cms.drupal.scanner',
        
        # Web Servers
        'apache': 'modules.webserver.apache',
        'nginx': 'modules.webserver.nginx',
        'litespeed': 'modules.webserver.litespeed',
        'iis': 'modules.webserver.iis',
        'tomcat': 'modules.webserver.tomcat',
        
        # PHP
        'php_version': 'modules.php.version',
        'php_config': 'modules.php.configuration',
        'php_functions': 'modules.php.dangerous_functions',
        'php_info': 'modules.php.info_disclosure',
        
        # Databases
        'mysql': 'modules.database.mysql',
        'postgresql': 'modules.database.postgresql',
        'redis': 'modules.database.redis',
        'mongodb': 'modules.database.mongodb',
        'elasticsearch': 'modules.database.elasticsearch',
        
        # Control Panels
        'cpanel': 'modules.control_panels.cpanel',
        'directadmin': 'modules.control_panels.directadmin',
        'plesk': 'modules.control_panels.plesk',
        'virtualmin': 'modules.control_panels.virtualmin',
        
        # Vulnerabilities
        'xss': 'modules.vulnerabilities.xss',
        'sqli': 'modules.vulnerabilities.sqli',
        'lfi': 'modules.vulnerabilities.lfi',
        'rfi': 'modules.vulnerabilities.rfi',
        'xxe': 'modules.vulnerabilities.xxe',
        'ssti': 'modules.vulnerabilities.ssti',
        'csrf': 'modules.vulnerabilities.csrf',
        'command_injection': 'modules.vulnerabilities.command_injection',
        'file_upload': 'modules.vulnerabilities.file_upload',
        'deserialization': 'modules.vulnerabilities.deserialization',
        'ssrf': 'modules.vulnerabilities.ssrf',
        
        # SSL/TLS
        'ssl': 'modules.ssl_tls.certificate',
        'ssl_protocols': 'modules.ssl_tls.protocols',
        'ssl_ciphers': 'modules.ssl_tls.ciphers',
        
        # Headers
        'headers': 'modules.headers.security_headers',
        'info_disclosure': 'modules.headers.information_disclosure',
        
        # API Security
        'graphql': 'modules.api_security.graphql',
        'rest_api': 'modules.api_security.rest_api',
        'jwt': 'modules.api_security.jwt',
    }
    
    def __init__(self, target_url: str, config: Dict):
        """
        Initialize the security scanner.
        
        Args:
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.target_url = target_url.rstrip('/')
        self.config = config
        
        # Initialize evasion engine
        mode_str = config.get('scan_mode', {}).get('default', 'stealth')
        mode_map = {
            'stealth': ScanMode.STEALTH,
            'normal': ScanMode.NORMAL,
            'aggressive': ScanMode.AGGRESSIVE
        }
        evasion_config = EvasionConfig(mode=mode_map.get(mode_str, ScanMode.STEALTH))
        self.evasion = EvasionEngine(evasion_config)
        
        # Initialize browser
        self.browser = StealthBrowser(target_url, evasion_config)
        
        # Initialize result container
        self.result = ScanResult(target_url=target_url)
        
        logger.info(f"SecurityScanner initialized for {target_url}")
    
    async def scan(
        self,
        modules: Optional[List[str]] = None,
        progress: Optional[Progress] = None,
        task: Optional[Any] = None
    ) -> ScanResult:
        """
        Run security scan with specified modules.
        
        Args:
            modules: List of module names to run
            progress: Rich progress bar instance
            task: Progress task ID
        
        Returns:
            ScanResult object with all findings
        """
        start_time = time.time()
        
        # Determine which modules to run
        if modules is None:
            modules = self._get_default_modules()
        else:
            modules = [m for m in modules if m in self.MODULE_MAP]
        
        logger.info(f"Starting scan with {len(modules)} modules")
        console.print(f"\n[bold cyan]Running {len(modules)} security modules...[/bold cyan]\n")
        
        total_modules = len(modules)
        
        for i, module_name in enumerate(modules):
            try:
                if progress and task:
                    progress.update(task, description=f"[cyan]Testing {module_name}...")
                
                # Run module
                module_result = await self._run_module(module_name)
                
                if module_result:
                    self.result.modules_run.append(module_name)
                    self.result.module_results[module_name] = module_result
                    
                    # Extract findings
                    findings = module_result.get('findings', [])
                    for finding_data in findings:
                        if isinstance(finding_data, dict):
                            finding = Finding(**finding_data)
                        else:
                            finding = finding_data
                        self.result.add_finding(finding)
                    
                    console.print(f"[bold green]✓[/bold green] {module_name}: Complete")
                else:
                    console.print(f"[bold yellow]⚠[/bold yellow] {module_name}: No results")
                
                # Update progress
                if progress and task:
                    progress.update(task, completed=int((i + 1) / total_modules * 100))
                
                # Small delay between modules
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Module '{module_name}' failed: {e}")
                console.print(f"[bold red]✗[/bold red] {module_name}: Failed - {e}")
        
        self.result.scan_duration = time.time() - start_time
        logger.info(f"Scan complete. Found {self.result.statistics['total']} issues in {self.result.scan_duration:.1f}s")
        
        return self.result
    
    async def _run_module(self, module_name: str) -> Optional[Dict]:
        """
        Dynamically load and execute a security module.
        
        Args:
            module_name: Name of the module to run
        
        Returns:
            Module result dictionary or None
        """
        module_path = self.MODULE_MAP.get(module_name)
        if not module_path:
            logger.error(f"No module mapping for: {module_name}")
            return None
        
        try:
            # Dynamic import
            module = importlib.import_module(module_path)
            
            # Each module should have a Scanner class
            if hasattr(module, 'Scanner'):
                scanner_class = module.Scanner
                scanner_instance = scanner_class(
                    browser=self.browser,
                    target_url=self.target_url,
                    config=self.config
                )
                
                if hasattr(scanner_instance, 'run'):
                    return scanner_instance.run()
                else:
                    logger.warning(f"Module {module_name} has no run() method")
                    return None
            else:
                logger.warning(f"Module {module_name} has no Scanner class")
                return None
                
        except ModuleNotFoundError:
            logger.error(f"Module not found: {module_path}")
            return None
        except Exception as e:
            logger.error(f"Error running module {module_name}: {e}")
            raise
    
    def _get_default_modules(self) -> List[str]:
        """Get default module list based on configuration."""
        enabled = []
        modules_config = self.config.get('modules', {})
        
        for category, category_config in modules_config.items():
            if isinstance(category_config, dict):
                for name, is_enabled in category_config.items():
                    if is_enabled and name in self.MODULE_MAP:
                        enabled.append(name)
            elif category_config and category in self.MODULE_MAP:
                enabled.append(category)
        
        return enabled[:10] if enabled else list(self.MODULE_MAP.keys())[:5]
    
    def print_summary(self):
        """Print scan summary in a beautiful format."""
        stats = self.result.statistics
        
        console.print("\n")
        console.print(Panel.fit(
            "[bold white]📊 SCAN SUMMARY[/bold white]",
            border_style="cyan"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim", width=12)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Status", justify="center", width=8)
        
        severity_config = [
            ('critical', 'red', '🔴'),
            ('high', 'orange1', '🟠'),
            ('medium', 'yellow', '🟡'),
            ('low', 'green', '🟢'),
            ('info', 'blue', '🔵'),
        ]
        
        for severity, color, icon in severity_config:
            count = stats.get(severity, 0)
            status = "⚠️" if count > 0 else "✅"
            table.add_row(
                f"[{color}]{severity.upper()}[/{color}]",
                str(count),
                status
            )
        
        table.add_section()
        table.add_row("[bold]TOTAL[/bold]", f"[bold]{stats.get('total', 0)}[/bold]", "")
        
        console.print(table)
        
        # Top findings
        if self.result.findings:
            critical_high = [
                f for f in self.result.findings
                if f.severity.lower() in ['critical', 'high']
            ]
            
            if critical_high:
                console.print("\n[bold red]🚨 CRITICAL & HIGH FINDINGS:[/bold red]\n")
                for i, finding in enumerate(critical_high[:10], 1):
                    color = 'red' if finding.severity.lower() == 'critical' else 'orange1'
                    console.print(
                        f"  {i}. [{color}]{finding.severity.upper()}[/{color}] - {finding.title}"
                    )
        
        console.print(f"\n[dim]Modules executed: {len(self.result.modules_run)}[/dim]")
        console.print(f"[dim]Scan duration: {self.result.scan_duration:.1f} seconds[/dim]")