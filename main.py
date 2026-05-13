#!/usr/bin/env python3
"""
Web Security Analyzer Pro v3.0 - Main Entry Point
A comprehensive web application security scanner.

Usage:
    python main.py scan https://example.com
    python main.py quick https://example.com
    python main.py scan https://example.com --mode stealth
    python main.py scan https://example.com --modules wordpress,php,xss
    python main.py api --port 8000
    python main.py update --all
    python main.py report scan_results.json --format html pdf
    python main.py version

Author: Security Research Team
License: GPLv3
Version: 3.0.0
"""

import sys
import os
import yaml
import click
import asyncio
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Third-party imports
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.syntax import Syntax
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  'rich' library not installed. Install with: pip install rich")
    print("⚠️  Falling back to basic output mode.\n")

try:
    from loguru import logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False
    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

# Project imports
from core.scanner import SecurityScanner, ScanResult, Finding
from core.evasion import EvasionConfig, ScanMode

console = Console() if RICH_AVAILABLE else None

# Version info
VERSION = "3.0.0"
BUILD_DATE = "2026-05-14"
AUTHOR = "Security Research Team"

# Banner
BANNER = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗   ║
║   ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║   ║
║   ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║   ║
║   ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║   ║
║   ╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║   ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ║
║                                                                      ║
║              Web Security Analyzer Pro v{VERSION:<44}║
║              Comprehensive Security Analysis Tool                   ║
║              Build: {BUILD_DATE:<46}║
╚══════════════════════════════════════════════════════════════════════╝
"""


# ============================================================================
# Helper Functions
# ============================================================================

def load_config(config_path: str = "config.yaml") -> dict:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to configuration file
    
    Returns:
        Configuration dictionary
    """
    default_config = {
        'scan_mode': {
            'default': 'stealth',
            'max_requests_per_second': 1.0,
            'timeout': 30,
            'retry_count': 3,
        },
        'evasion': {
            'rotate_user_agent': True,
            'random_delay': True,
            'min_delay': 0.5,
            'max_delay': 3.0,
            'jitter': True,
        },
        'proxy': {
            'enabled': False,
            'tor_enabled': False,
        },
        'reporting': {
            'formats': ['html'],
            'output_directory': 'reports/output',
            'include_remediation': True,
        },
        'logging': {
            'level': 'INFO',
            'file': 'logs/scanner.log',
        },
    }
    
    if not os.path.exists(config_path):
        logger.warning(f"Config file not found: {config_path}")
        logger.info("Using default configuration")
        # Create default config
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            logger.info(f"Default config created: {config_path}")
        except Exception as e:
            logger.error(f"Could not create default config: {e}")
        return default_config
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logger.info(f"Configuration loaded from {config_path}")
        return config
    except yaml.YAMLError as e:
        logger.error(f"Error parsing config file: {e}")
        return default_config


def setup_logging(config: dict):
    """Configure logging based on settings."""
    if not LOGURU_AVAILABLE:
        return
    
    log_config = config.get('logging', {})
    logger.remove()
    
    # Console logging
    logger.add(
        sys.stderr,
        level=log_config.get('level', 'INFO'),
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        colorize=True
    )
    
    # File logging
    log_file = log_config.get('file', 'logs/scanner.log')
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        logger.add(
            log_file,
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            rotation="10 MB",
            retention=5
        )


def print_banner():
    """Print the application banner."""
    if RICH_AVAILABLE:
        console.print(BANNER, style="cyan")
    else:
        print(BANNER)


def print_scan_header(target_url: str, mode: str, modules: Optional[List[str]] = None):
    """Print scan start header."""
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]🎯 Target:[/bold cyan] {target_url}")
        console.print(f"[bold cyan]⚙️  Mode:[/bold cyan] {mode}")
        console.print(f"[bold cyan]🕐 Time:[/bold cyan] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if modules:
            console.print(f"[bold cyan]📦 Modules:[/bold cyan] {', '.join(modules[:10])}")
            if len(modules) > 10:
                console.print(f"          ... and {len(modules) - 10} more")
        console.print()
    else:
        print(f"\n🎯 Target: {target_url}")
        print(f"⚙️  Mode: {mode}")
        print(f"🕐 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if modules:
            print(f"📦 Modules: {', '.join(modules[:10])}")
        print()


def print_scan_results(results: ScanResult):
    """Print scan results summary."""
    stats = results.statistics
    
    if RICH_AVAILABLE:
        console.print("\n")
        console.print(Panel.fit(
            "[bold white]📊 SCAN RESULTS[/bold white]",
            border_style="cyan"
        ))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim", width=12)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Status", justify="center", width=8)
        
        severity_data = [
            ('CRITICAL', 'red', stats.get('critical', 0)),
            ('HIGH', 'orange1', stats.get('high', 0)),
            ('MEDIUM', 'yellow', stats.get('medium', 0)),
            ('LOW', 'green', stats.get('low', 0)),
            ('INFO', 'blue', stats.get('info', 0)),
        ]
        
        for severity, color, count in severity_data:
            status = "⚠️" if count > 0 else "✅"
            table.add_row(f"[{color}]{severity}[/{color}]", str(count), status)
        
        table.add_section()
        table.add_row("[bold]TOTAL[/bold]", f"[bold]{stats.get('total', 0)}[/bold]", "")
        
        console.print(table)
        
        # Print top findings
        critical_high = [f for f in results.findings if f.severity.lower() in ['critical', 'high']]
        if critical_high:
            console.print("\n[bold red]🚨 TOP CRITICAL/HIGH FINDINGS:[/bold red]\n")
            for i, finding in enumerate(critical_high[:5], 1):
                color = 'red' if finding.severity.lower() == 'critical' else 'orange1'
                console.print(f"  {i}. [{color}]{finding.severity.upper()}[/{color}] - {finding.title}")
        
        console.print(f"\n[dim]✅ Scan completed in {results.scan_duration:.1f} seconds[/dim]")
        console.print(f"[dim]📦 {len(results.modules_run)} modules executed[/dim]")
        console.print(f"[dim]🔍 {stats.get('total', 0)} total findings[/dim]")
    else:
        print(f"\n{'='*60}")
        print("📊 SCAN RESULTS")
        print(f"{'='*60}")
        print(f"  CRITICAL: {stats.get('critical', 0)}")
        print(f"  HIGH:     {stats.get('high', 0)}")
        print(f"  MEDIUM:   {stats.get('medium', 0)}")
        print(f"  LOW:      {stats.get('low', 0)}")
        print(f"  INFO:     {stats.get('info', 0)}")
        print(f"  {'─'*20}")
        print(f"  TOTAL:    {stats.get('total', 0)}")
        print(f"\n✅ Scan completed in {results.scan_duration:.1f} seconds")


def generate_reports(results: ScanResult, config: dict, formats: tuple, output: Optional[str]):
    """Generate scan reports."""
    try:
        from core.reporter import ReportGenerator
        
        reporter = ReportGenerator(results, config)
        formats_list = list(formats) if formats else ['html']
        
        for fmt in formats_list:
            report_path = reporter.generate(format=fmt, output_path=output)
            if RICH_AVAILABLE:
                console.print(f"[bold green]📄 Report generated:[/bold green] {report_path}")
            else:
                print(f"📄 Report generated: {report_path}")
    except ImportError:
        logger.warning("Report generator not available")
    except Exception as e:
        logger.error(f"Report generation failed: {e}")


# ============================================================================
# CLI Commands
# ============================================================================

@click.group()
@click.version_option(VERSION, prog_name="Web Security Analyzer Pro")
@click.option('--config', '-c', default='config.yaml', help='Path to config file')
@click.pass_context
def cli(ctx, config):
    """
    Web Security Analyzer Pro - Comprehensive Security Analysis Tool
    
    A powerful web application security scanner with 50+ security testing modules.
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    setup_logging(ctx.obj['config'])


@cli.command()
@click.argument('target_url')
@click.option('--mode', '-m', type=click.Choice(['stealth', 'normal', 'aggressive']),
              default='stealth', help='Scan mode (default: stealth)')
@click.option('--modules', '-M', help='Comma-separated list of modules to run')
@click.option('--output', '-o', help='Output file path (without extension)')
@click.option('--format', '-f', 'output_format', multiple=True,
              type=click.Choice(['html', 'pdf', 'json', 'markdown']),
              help='Report format(s)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def scan(ctx, target_url: str, mode: str, modules: Optional[str],
         output: Optional[str], output_format: tuple, verbose: bool):
    """
    Run a comprehensive security scan against a target URL.
    
    Example:
        python main.py scan https://example.com
        python main.py scan https://example.com --mode stealth
        python main.py scan https://example.com --modules wordpress,php,xss
        python main.py scan https://example.com --format html pdf
    """
    print_banner()
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
        logger.info(f"Added https:// prefix: {target_url}")
    
    # Parse modules
    selected_modules = None
    if modules:
        selected_modules = [m.strip() for m in modules.split(',')]
    
    # Update config with CLI options
    config = ctx.obj['config']
    config['scan_mode']['default'] = mode
    
    if verbose:
        config['logging']['level'] = 'DEBUG'
        setup_logging(config)
    
    print_scan_header(target_url, mode, selected_modules)
    
    # Initialize scanner
    scanner = SecurityScanner(target_url, config)
    
    # Run scan with progress bar
    try:
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Scanning...", total=100)
                results = asyncio.run(scanner.scan(selected_modules, progress, task))
                progress.update(task, completed=100)
        else:
            print("Scanning... (install 'rich' for progress bar)")
            results = asyncio.run(scanner.scan(selected_modules))
        
        # Print results
        print_scan_results(results)
        
        # Generate reports if requested
        if output_format or output:
            generate_reports(results, config, output_format, output)
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        print("\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"\n❌ Error: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument('target_url')
@click.option('--modules', '-M', help='Comma-separated list of modules')
@click.pass_context
def quick(ctx, target_url: str, modules: Optional[str]):
    """
    Run a quick scan with minimal settings.
    
    Example:
        python main.py quick https://example.com
        python main.py quick https://example.com --modules wordpress,headers
    """
    print_banner()
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    config = ctx.obj['config']
    config['scan_mode']['default'] = 'normal'
    
    selected_modules = None
    if modules:
        selected_modules = [m.strip() for m in modules.split(',')]
    
    print_scan_header(target_url, 'quick', selected_modules)
    
    scanner = SecurityScanner(target_url, config)
    
    try:
        print("⚡ Running quick scan...\n")
        results = asyncio.run(scanner.scan(selected_modules))
        print_scan_results(results)
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Quick scan failed: {e}")
        print(f"\n❌ Error: {e}")
        sys.exit(1)


@cli.command()
@click.option('--port', '-p', default=8000, help='API server port (default: 8000)')
@click.option('--host', '-h', default='127.0.0.1', help='API server host (default: 127.0.0.1)')
@click.pass_context
def api(ctx, port: int, host: str):
    """
    Start the REST API server for remote scanning.
    
    Example:
        python main.py api
        python main.py api --port 8080
        python main.py api --host 0.0.0.0 --port 8000
    """
    print_banner()
    
    try:
        from core.api import APIServer
    except ImportError:
        print("❌ API server dependencies not installed.")
        print("   Install with: pip install fastapi uvicorn")
        sys.exit(1)
    
    config = ctx.obj['config']
    
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]🚀 Starting API Server...[/bold cyan]")
        console.print(f"[bold green]📍 Host:[/bold green] {host}")
        console.print(f"[bold green]🔌 Port:[/bold green] {port}")
        console.print(f"[bold green]📚 Docs:[/bold green] http://{host}:{port}/docs")
        console.print(f"[bold green]🔍 Redoc:[/bold green] http://{host}:{port}/redoc\n")
    else:
        print(f"\n🚀 Starting API Server...")
        print(f"📍 Host: {host}")
        print(f"🔌 Port: {port}")
        print(f"📚 Docs: http://{host}:{port}/docs\n")
    
    server = APIServer(config)
    server.run(host=host, port=port)


@cli.command()
@click.option('--db', is_flag=True, help='Update vulnerability database')
@click.option('--signatures', is_flag=True, help='Update technology signatures')
@click.option('--all', 'update_all', is_flag=True, help='Update everything')
@click.pass_context
def update(ctx, db: bool, signatures: bool, update_all: bool):
    """
    Update vulnerability database and technology signatures.
    
    Example:
        python main.py update --db
        python main.py update --all
    """
    print_banner()
    
    try:
        from core.updater import DatabaseUpdater
    except ImportError:
        print("❌ Database updater not available.")
        sys.exit(1)
    
    config = ctx.obj['config']
    updater = DatabaseUpdater(config)
    
    if update_all:
        db = True
        signatures = True
    
    if not db and not signatures:
        print("⚠️  Please specify what to update:")
        print("   --db          Update vulnerability database")
        print("   --signatures  Update technology signatures")
        print("   --all         Update everything")
        return
    
    if db:
        print("\n📥 Updating vulnerability database...")
        count = updater.update_vulnerability_database()
        print(f"✅ Database updated: {count} vulnerabilities")
    
    if signatures:
        print("\n📥 Updating technology signatures...")
        count = updater.update_signatures()
        print(f"✅ Signatures updated: {count} entries")
    
    print("\n✅ Update complete!")


@cli.command()
@click.argument('input_file')
@click.option('--format', '-f', 'output_format', multiple=True,
              type=click.Choice(['html', 'pdf', 'json', 'markdown']),
              help='Output format(s)')
@click.option('--output', '-o', help='Output file path (without extension)')
@click.pass_context
def report(ctx, input_file: str, output_format: tuple, output: Optional[str]):
    """
    Generate report from existing scan results.
    
    Example:
        python main.py report scan_results.json
        python main.py report scan_results.json --format html pdf
    """
    print_banner()
    
    if not os.path.exists(input_file):
        print(f"❌ File not found: {input_file}")
        sys.exit(1)
    
    try:
        import json
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        from core.reporter import ReportGenerator
        
        config = ctx.obj['config']
        reporter = ReportGenerator(data, config)
        
        formats_list = list(output_format) if output_format else ['html']
        
        for fmt in formats_list:
            report_path = reporter.generate(format=fmt, output_path=output)
            print(f"📄 Report generated: {report_path}")
        
        print("\n✅ Report generation complete!")
        
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        sys.exit(1)


@cli.command()
def version():
    """Display version information."""
    print_banner()
    print(f"  Version:    {VERSION}")
    print(f"  Build Date: {BUILD_DATE}")
    print(f"  Author:     {AUTHOR}")
    print(f"  Python:     {sys.version}")
    print(f"  Platform:   {sys.platform}")
    print(f"  Rich:       {'✅ Available' if RICH_AVAILABLE else '❌ Not installed'}")
    print(f"  Loguru:     {'✅ Available' if LOGURU_AVAILABLE else '❌ Not installed'}")
    print()


@cli.command()
def modules():
    """List all available scan modules."""
    print_banner()
    print("\n📦 Available Modules:\n")
    
    from core.scanner import SecurityScanner
    
    categories = {
        'CMS': ['wordpress', 'wordpress_version', 'wordpress_plugins', 'wordpress_themes',
                'wordpress_users', 'wordpress_xmlrpc', 'wordpress_backups', 'wordpress_hardening',
                'joomla', 'drupal'],
        'Web Servers': ['apache', 'nginx', 'litespeed', 'iis', 'tomcat'],
        'PHP': ['php_version', 'php_config', 'php_functions', 'php_info'],
        'Databases': ['mysql', 'postgresql', 'redis', 'mongodb', 'elasticsearch'],
        'Control Panels': ['cpanel', 'directadmin', 'plesk', 'virtualmin'],
        'Vulnerabilities': ['xss', 'sqli', 'lfi', 'rfi', 'xxe', 'ssti', 'csrf',
                           'command_injection', 'file_upload', 'deserialization', 'ssrf'],
        'SSL/TLS': ['ssl', 'ssl_protocols', 'ssl_ciphers'],
        'Headers': ['headers', 'info_disclosure'],
        'API Security': ['graphql', 'rest_api', 'jwt'],
    }
    
    for category, module_list in categories.items():
        print(f"  📁 {category}:")
        for mod in module_list:
            status = "✅" if mod in SecurityScanner.MODULE_MAP else "❌"
            print(f"      {status} {mod}")
        print()


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports/output', exist_ok=True)
    os.makedirs('database', exist_ok=True)
    
    # Run CLI
    cli(obj={})