#!/usr/bin/env python3
"""
Main Security Scanner Orchestrator Module.
Coordinates all security testing modules and manages the scan lifecycle.

Features:
    - Dynamic module loading
    - Scan progress tracking with callback support
    - Result aggregation
    - Severity-based finding classification
    - Comprehensive reporting
    - Synchronous and asynchronous scan support
"""

import os
import sys
import time
import json
import importlib
import asyncio
from typing import Dict, List, Optional, Any, Tuple, Callable
from datetime import datetime
from dataclasses import dataclass, field
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

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
    scan_mode: str = "stealth"
    timeout: int = 30
    rps: float = 1.0
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
            'scan_mode': self.scan_mode,
            'timeout': self.timeout,
            'rps': self.rps,
            'modules_run': self.modules_run,
            'findings': [f.to_dict() for f in self.findings],
            'module_results': self.module_results,
            'statistics': self.statistics,
            'urls_tested': len(self.module_results),
            'params_tested': sum(
                len(r.get('parameters_tested', [])) 
                for r in self.module_results.values() 
                if isinstance(r, dict)
            ),
            'forms_tested': sum(
                len(r.get('forms_tested', [])) 
                for r in self.module_results.values() 
                if isinstance(r, dict)
            ),
        }


class SecurityScanner:
    """
    Main security scanner orchestrator.
    
    Manages the entire scanning process including:
    - Module discovery and loading
    - Scan execution and coordination
    - Result collection and aggregation
    - Progress reporting with callback support
    
    Usage:
        scanner = SecurityScanner("https://example.com", config)
        
        # Async scan with progress bar
        results = await scanner.scan(modules=['wordpress', 'xss', 'sqli'])
        
        # Sync scan with progress callback
        results = scanner.run_with_progress(
            modules=['wordpress', 'headers'],
            progress_callback=lambda pct, msg: print(f"{pct}%: {msg}")
        )
    """
    
    # Module registry: CLI name -> import path
    MODULE_MAP = {
        # CMS - WordPress
        'wordpress': 'modules.cms.wordpress.detector',
        'wordpress_version': 'modules.cms.wordpress.version',
        'wordpress_plugins': 'modules.cms.wordpress.plugins',
        'wordpress_themes': 'modules.cms.wordpress.themes',
        'wordpress_users': 'modules.cms.wordpress.users',
        'wordpress_xmlrpc': 'modules.cms.wordpress.xmlrpc',
        'wordpress_rest': 'modules.cms.wordpress.rest_api',
        'wordpress_backups': 'modules.cms.wordpress.backups',
        'wordpress_hardening': 'modules.cms.wordpress.hardening',
        
        # CMS - Joomla & Drupal
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
            target_url: Target URL to scan (e.g., https://example.com)
            config: Configuration dictionary from config.yaml
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
        self.result = ScanResult(
            target_url=target_url,
            scan_mode=mode_str,
            timeout=config.get('scan_mode', {}).get('timeout', 30),
            rps=config.get('scan_mode', {}).get('max_requests_per_second', 1.0)
        )
        
        logger.info(f"SecurityScanner initialized for {target_url} in {mode_str} mode")
    
    # ========================================================================
    # Public Scan Methods
    # ========================================================================
    
    async def scan(
        self,
        modules: Optional[List[str]] = None,
        progress: Optional[Progress] = None,
        task: Optional[Any] = None
    ) -> ScanResult:
        """
        Run asynchronous security scan with Rich progress bar support.
        
        Args:
            modules: List of module names to run (None = default set)
            progress: Rich Progress instance for progress bar
            task: Rich Task ID for progress updates
        
        Returns:
            ScanResult object with all findings
        
        Example:
            with Progress() as progress:
                task = progress.add_task("Scanning...", total=100)
                results = await scanner.scan(['wordpress', 'xss'], progress, task)
        """
        start_time = time.time()
        
        # Determine modules to run
        modules = self._resolve_modules(modules)
        
        if not modules:
            logger.warning("No modules to run")
            console.print("[yellow]⚠️ No modules selected for scanning[/yellow]")
            return self.result
        
        logger.info(f"Starting async scan with {len(modules)} modules")
        console.print(f"\n[bold cyan]🔍 Running {len(modules)} security modules...[/bold cyan]\n")
        
        total_modules = len(modules)
        
        for i, module_name in enumerate(modules):
            try:
                # Update progress description
                if progress and task:
                    progress.update(
                        task, 
                        description=f"[cyan]🔍 Testing {module_name}..."
                    )
                
                # Execute module
                module_result = await self._run_module(module_name)
                
                # Process results
                self._process_module_result(module_name, module_result)
                
                # Update progress percentage
                if progress and task:
                    percentage = int((i + 1) / total_modules * 100)
                    progress.update(task, completed=percentage)
                    logger.debug(f"Progress: {percentage}% - {module_name} complete")
                
                # Brief pause between modules to avoid rate limiting
                await asyncio.sleep(0.3)
                
            except KeyboardInterrupt:
                logger.warning("Scan interrupted by user")
                console.print("\n[yellow]⚠️ Scan interrupted[/yellow]")
                break
            except Exception as e:
                logger.error(f"Module '{module_name}' failed: {e}")
                console.print(f"[bold red]✗[/bold red] {module_name}: Error - {str(e)[:100]}")
                
                if progress and task:
                    percentage = int((i + 1) / total_modules * 100)
                    progress.update(task, completed=percentage)
        
        # Finalize
        self.result.scan_duration = time.time() - start_time
        
        # Mark progress complete
        if progress and task:
            progress.update(task, completed=100, description="[green]✅ Scan Complete!")
        
        logger.info(
            f"Scan complete. "
            f"Found {self.result.statistics['total']} issues "
            f"in {self.result.scan_duration:.1f}s"
        )
        
        return self.result
    
    def run_with_progress(
        self,
        modules: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> Dict:
        """
        Run synchronous scan with progress callback support.
        
        This method is designed for CLI use where Rich Progress bars
        need external progress updates.
        
        Args:
            modules: List of module names to run
            progress_callback: Function(percent: float, message: str) 
                              Called after each module completes
        
        Returns:
            Dictionary with scan results (same as ScanResult.to_dict())
        
        Example:
            def update_progress(pct, msg):
                print(f"[{pct:.0f}%] {msg}")
            
            results = scanner.run_with_progress(
                modules=['wordpress', 'headers'],
                progress_callback=update_progress
            )
        """
        start_time = time.time()
        
        # Resolve modules
        modules = self._resolve_modules(modules)
        
        if not modules:
            logger.warning("No modules selected")
            return self.result.to_dict()
        
        logger.info(f"Starting sync scan with {len(modules)} modules")
        console.print(f"\n[bold cyan]🔍 Running {len(modules)} security modules...[/bold cyan]\n")
        
        total_modules = len(modules)
        
        for i, module_name in enumerate(modules):
            try:
                # Update progress via callback
                if progress_callback:
                    percentage = (i / total_modules) * 100
                    progress_callback(percentage, f"Testing {module_name}...")
                
                # Execute module synchronously
                module_result = self._run_module_sync(module_name)
                
                # Process results
                self._process_module_result(module_name, module_result)
                
                # Update progress after module completes
                if progress_callback:
                    percentage = ((i + 1) / total_modules) * 100
                    findings_count = len(module_result.get('findings', [])) if module_result else 0
                    progress_callback(
                        percentage,
                        f"✓ {module_name} ({findings_count} findings)"
                    )
                
                logger.info(
                    f"✓ {module_name}: "
                    f"{len(module_result.get('findings', [])) if module_result else 0} findings"
                )
                
            except KeyboardInterrupt:
                logger.warning("Scan interrupted by user")
                console.print("\n[yellow]⚠️ Scan interrupted[/yellow]")
                break
            except Exception as e:
                logger.error(f"Module '{module_name}' failed: {e}")
                console.print(f"[bold red]✗[/bold red] {module_name}: {e}")
                
                if progress_callback:
                    percentage = ((i + 1) / total_modules) * 100
                    progress_callback(percentage, f"✗ {module_name} failed")
        
        # Finalize
        self.result.scan_duration = time.time() - start_time
        
        if progress_callback:
            progress_callback(100.0, "✅ Scan Complete!")
        
        logger.info(
            f"Scan complete. "
            f"Found {self.result.statistics['total']} issues "
            f"in {self.result.scan_duration:.1f}s"
        )
        
        return self.result.to_dict()
    
    async def quick_scan(self, modules: Optional[List[str]] = None) -> ScanResult:
        """
        Run a quick scan with aggressive mode for speed.
        
        Args:
            modules: Modules to run (defaults to critical modules only)
        
        Returns:
            ScanResult object
        """
        # Switch to aggressive mode for speed
        original_mode = self.evasion.config.mode
        self.evasion.config.mode = ScanMode.AGGRESSIVE
        self.result.scan_mode = "aggressive"
        
        if modules is None:
            # Quick scan uses only critical modules
            modules = [
                'wordpress', 'php_version', 'headers', 
                'ssl', 'xss', 'sqli'
            ]
        
        logger.info(f"Starting quick scan with {len(modules)} modules")
        
        try:
            result = await self.scan(modules=modules)
            return result
        finally:
            # Restore original mode
            self.evasion.config.mode = original_mode
    
    # ========================================================================
    # Private Methods
    # ========================================================================
    
    def _resolve_modules(self, modules: Optional[List[str]]) -> List[str]:
        """
        Resolve which modules to run.
        
        Priority:
        1. User-specified modules list
        2. Config-enabled modules
        3. Default critical modules
        """
        if modules is None:
            modules = self._get_enabled_modules()
        
        # Filter to valid modules only
        valid_modules = [m for m in modules if m in self.MODULE_MAP]
        
        # Warn about invalid modules
        invalid = set(modules) - set(valid_modules)
        if invalid:
            logger.warning(f"Invalid module names ignored: {invalid}")
            console.print(f"[yellow]⚠️ Unknown modules: {', '.join(invalid)}[/yellow]")
        
        return valid_modules
    
    def _get_enabled_modules(self) -> List[str]:
        """Get default module list based on configuration."""
        enabled = []
        modules_config = self.config.get('modules', {})
        
        if not modules_config:
            # Return critical modules if no config
            return [
                'wordpress', 'php_version', 'headers', 
                'ssl', 'xss', 'sqli', 'cpanel'
            ]
        
        for category, category_config in modules_config.items():
            if isinstance(category_config, dict):
                # Category with sub-modules
                for name, is_enabled in category_config.items():
                    if is_enabled and name in self.MODULE_MAP:
                        enabled.append(name)
            elif category_config:
                # Simple boolean category
                if category in self.MODULE_MAP:
                    enabled.append(category)
        
        # Fallback if nothing enabled
        if not enabled:
            enabled = list(self.MODULE_MAP.keys())[:10]
        
        logger.info(f"Enabled modules: {len(enabled)}")
        return enabled
    
    async def _run_module(self, module_name: str) -> Optional[Dict]:
        """
        Dynamically load and execute a security module (async).
        
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
            
            # Look for Scanner class
            if hasattr(module, 'Scanner'):
                scanner_class = module.Scanner
                scanner_instance = scanner_class(
                    browser=self.browser,
                    target_url=self.target_url,
                    config=self.config
                )
                
                # Check for async run method
                if hasattr(scanner_instance, 'run_async'):
                    return await scanner_instance.run_async()
                elif hasattr(scanner_instance, 'run'):
                    return scanner_instance.run()
                else:
                    logger.warning(f"Module {module_name} Scanner has no run() method")
                    return None
            
            # Look for standalone run function
            elif hasattr(module, 'run'):
                result = module.run(
                    browser=self.browser,
                    target_url=self.target_url,
                    config=self.config
                )
                return result
            
            else:
                logger.warning(f"Module {module_name} has no Scanner class or run() function")
                return None
                
        except ModuleNotFoundError:
            logger.error(f"Module file not found: {module_path}")
            return None
        except Exception as e:
            logger.error(f"Error running module {module_name}: {e}")
            raise
    
    def _run_module_sync(self, module_name: str) -> Optional[Dict]:
        """
        Synchronously load and execute a security module.
        Used by run_with_progress() for CLI compatibility.
        
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
            
            # Look for Scanner class
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
                    logger.warning(f"Module {module_name} Scanner has no run() method")
                    return None
            
            # Look for standalone run function
            elif hasattr(module, 'run'):
                return module.run(
                    browser=self.browser,
                    target_url=self.target_url,
                    config=self.config
                )
            
            else:
                logger.warning(f"Module {module_name} has no Scanner class or run() function")
                return None
                
        except ModuleNotFoundError:
            logger.error(f"Module file not found: {module_path}")
            return None
        except Exception as e:
            logger.error(f"Error running module {module_name}: {e}")
            raise
    
    def _process_module_result(self, module_name: str, module_result: Optional[Dict]):
        """
        Process and store module results.
        
        Args:
            module_name: Name of the module
            module_result: Result dictionary from module
        """
        if module_result:
            self.result.modules_run.append(module_name)
            self.result.module_results[module_name] = module_result
            
            # Extract findings
            findings = module_result.get('findings', [])
            for finding_data in findings:
                if isinstance(finding_data, Finding):
                    self.result.add_finding(finding_data)
                elif isinstance(finding_data, dict):
                    # Create Finding from dict
                    finding = Finding(**finding_data)
                    self.result.add_finding(finding)
            
            findings_count = len(findings)
            if findings_count > 0:
                # Count severities in this module
                severities = {}
                for f in findings:
                    sev = (f.severity if isinstance(f, Finding) else f.get('severity', 'info')).lower()
                    severities[sev] = severities.get(sev, 0) + 1
                
                severity_str = ', '.join(f"{s}:{c}" for s, c in severities.items())
                console.print(
                    f"[bold green]✓[/bold green] {module_name}: "
                    f"{findings_count} findings ({severity_str})"
                )
            else:
                console.print(f"[bold green]✓[/bold green] {module_name}: Clean")
        else:
            console.print(f"[bold yellow]⚠[/bold yellow] {module_name}: No results returned")
    
    # ========================================================================
    # Reporting Methods
    # ========================================================================
    
    def print_summary(self):
        """Print scan summary in a beautiful formatted table."""
        stats = self.result.statistics
        
        console.print("\n")
        console.print(Panel.fit(
            "[bold white]📊 SCAN SUMMARY[/bold white]",
            border_style="cyan"
        ))
        
        # Statistics table
        table = Table(
            show_header=True,
            header_style="bold magenta",
            title=f"Target: {self.result.target_url}",
            title_style="bold"
        )
        table.add_column("Severity", style="dim", width=12)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Bar", width=30)
        table.add_column("Status", justify="center", width=8)
        
        severity_config = [
            ('critical', 'red', '🔴'),
            ('high', 'orange1', '🟠'),
            ('medium', 'yellow', '🟡'),
            ('low', 'green', '🟢'),
            ('info', 'blue', '🔵'),
        ]
        
        total = max(stats.get('total', 1), 1)  # Avoid division by zero
        
        for severity, color, icon in severity_config:
            count = stats.get(severity, 0)
            status = "⚠️" if count > 0 else "✅"
            
            # Create bar visualization
            bar_length = int((count / total) * 30) if count > 0 else 0
            bar = f"[{color}]{'█' * bar_length}[/{color}]"
            
            table.add_row(
                f"[{color}]{icon} {severity.upper()}[/{color}]",
                str(count),
                bar,
                status
            )
        
        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{stats.get('total', 0)}[/bold]",
            "",
            ""
        )
        
        console.print(table)
        
        # Top critical/high findings
        if self.result.findings:
            critical_high = [
                f for f in self.result.findings
                if f.severity.lower() in ['critical', 'high']
            ]
            
            if critical_high:
                console.print("\n[bold red]🚨 CRITICAL & HIGH PRIORITY FINDINGS:[/bold red]\n")
                for i, finding in enumerate(critical_high[:10], 1):
                    color = 'red' if finding.severity.lower() == 'critical' else 'orange1'
                    cve = f" [{finding.cve_id}]" if finding.cve_id else ""
                    cvss = f" (CVSS: {finding.cvss_score})" if finding.cvss_score else ""
                    console.print(
                        f"  {i}. [{color}]{finding.severity.upper()}[/{color}] "
                        f"- {finding.title}{cve}{cvss}"
                    )
        
        # Module execution summary
        console.print(f"\n[dim]📦 Modules executed: {len(self.result.modules_run)}[/dim]")
        console.print(f"[dim]⏱️  Scan duration: {self.result.scan_duration:.1f} seconds[/dim]")
        console.print(f"[dim]🛡️  Scan mode: {self.result.scan_mode}[/dim]")
        
        # Overall assessment
        critical = stats.get('critical', 0)
        high = stats.get('high', 0)
        
        if critical > 0:
            console.print(Panel(
                "[bold red]⚠️ CRITICAL VULNERABILITIES FOUND![/bold red]\n"
                "Immediate action is required to address critical security issues.",
                border_style="red"
            ))
        elif high > 0:
            console.print(Panel(
                "[bold yellow]⚠️ HIGH SEVERITY ISSUES DETECTED[/bold yellow]\n"
                "Remediation should be prioritized within 48 hours.",
                border_style="yellow"
            ))
        elif stats.get('total', 0) > 0:
            console.print(Panel(
                "[bold green]📋 Issues found but no critical/high severity[/bold green]\n"
                "Address findings during regular maintenance cycles.",
                border_style="green"
            ))
        else:
            console.print(Panel(
                "[bold green]✅ NO VULNERABILITIES FOUND[/bold green]\n"
                "Excellent security posture! Maintain current security practices.",
                border_style="green"
            ))
    
    def print_module_summary(self):
        """Print detailed module-by-module summary."""
        if not self.result.module_results:
            console.print("[dim]No module results to display[/dim]")
            return
        
        console.print("\n[bold cyan]📋 MODULE EXECUTION DETAILS:[/bold cyan]\n")
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Module")
        table.add_column("Status")
        table.add_column("Findings")
        table.add_column("Critical/High")
        
        for module_name, result in self.result.module_results.items():
            findings = result.get('findings', []) if isinstance(result, dict) else []
            critical_count = sum(
                1 for f in findings
                if (f.severity if isinstance(f, Finding) else f.get('severity', '')).lower() == 'critical'
            )
            high_count = sum(
                1 for f in findings
                if (f.severity if isinstance(f, Finding) else f.get('severity', '')).lower() == 'high'
            )
            
            status = "✅" if not findings else f"⚠️"
            
            table.add_row(
                module_name,
                status,
                str(len(findings)),
                f"[red]{critical_count}[/red]/[orange1]{high_count}[/orange1]"
            )
        
        console.print(table)
    
    def to_json(self, filepath: Optional[str] = None) -> str:
        """
        Export scan results to JSON.
        
        Args:
            filepath: Optional file path to save JSON
        
        Returns:
            JSON string
        """
        data = self.result.to_dict()
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(json_str)
            logger.info(f"Results saved to: {filepath}")
        
        return json_str