#!/usr/bin/env python3
"""
Web Security Analyzer Pro v3.0 - Interactive CLI
A comprehensive web application security scanner with interactive menu.

Usage:
    python main.py
"""

import sys
import os
import yaml
import asyncio
import time
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
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.syntax import Syntax
    from rich import print as rprint
    from rich.layout import Layout
    from rich.live import Live
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  'rich' library not installed. Install with: pip install rich")
    sys.exit(1)

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

console = Console()

# Version info
VERSION = "3.0.0"
BUILD_DATE = "2026-05-14"

# Banner
BANNER = f"""
[bold cyan]
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗   ║
║   ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║   ║
║   ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║   ║
║   ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║   ║
║   ╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║   ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ║
║                                                                      ║
║              Web Security Analyzer Pro v{VERSION}                    ║
║              Comprehensive Security Analysis Tool                   ║
╚══════════════════════════════════════════════════════════════════════╝
[/bold cyan]
"""

# Module categories with their modules
MODULE_CATEGORIES = {
    "🔍 CMS & Platforms": [
        ("1", "wordpress", "WordPress Security Scanner", "WordPress detection, version, plugins, themes, users, backups"),
        ("2", "joomla", "Joomla Security Scanner", "Joomla detection and vulnerability assessment"),
        ("3", "drupal", "Drupal Security Scanner", "Drupal detection and security analysis"),
    ],
    "🌐 Web Servers": [
        ("4", "apache", "Apache HTTP Server", "Apache version, server-status, server-info, misconfigurations"),
        ("5", "nginx", "Nginx Web Server", "Nginx version, stub_status, configuration issues"),
        ("6", "litespeed", "LiteSpeed Web Server", "LiteSpeed detection, admin interface, cache plugin"),
        ("7", "iis", "Microsoft IIS", "IIS version, web.config, trace.axd, Exchange detection"),
        ("8", "tomcat", "Apache Tomcat", "Tomcat manager, default credentials, examples"),
    ],
    "🐘 PHP Security": [
        ("9", "php_version", "PHP Version Detection", "PHP version enumeration and vulnerability matching"),
        ("10", "php_config", "PHP Configuration", "php.ini settings, phpinfo detection, session security"),
        ("11", "php_functions", "Dangerous PHP Functions", "Detection of exec, system, eval and other dangerous functions"),
        ("12", "php_info", "PHP Information Disclosure", "Error logs, config files, composer, .env exposure"),
    ],
    "🗄️ Database Security": [
        ("13", "mysql", "MySQL Security", "MySQL port scanning, error disclosure, phpMyAdmin detection"),
        ("14", "postgresql", "PostgreSQL Security", "PostgreSQL port scanning, authentication check"),
        ("15", "redis", "Redis Security", "Redis unauthorized access, dangerous commands"),
        ("16", "mongodb", "MongoDB Security", "MongoDB unauthorized access, version disclosure"),
        ("17", "elasticsearch", "Elasticsearch Security", "ES indices enumeration, authentication check"),
    ],
    "🖥️ Control Panels": [
        ("18", "cpanel", "cPanel/WHM Security", "cPanel ports, WHM access, version disclosure"),
        ("19", "directadmin", "DirectAdmin Security", "DirectAdmin port, interface access, version check"),
        ("20", "plesk", "Plesk Security", "Plesk ports, API exposure, backup detection"),
        ("21", "virtualmin", "Virtualmin/Webmin", "Webmin detection, unauthenticated access, default creds"),
    ],
    "🛡️ Vulnerability Scanners": [
        ("22", "xss", "Cross-Site Scripting (XSS)", "Reflected, stored, and DOM-based XSS detection"),
        ("23", "sqli", "SQL Injection (SQLi)", "Error-based, boolean, time-based, and UNION SQLi"),
        ("24", "lfi", "Local File Inclusion (LFI)", "Path traversal and local file inclusion detection"),
        ("25", "rfi", "Remote File Inclusion (RFI)", "Remote file inclusion vulnerability detection"),
        ("26", "xxe", "XML External Entity (XXE)", "XXE injection in XML parsers"),
        ("27", "ssti", "Server-Side Template Injection", "Template injection in various engines"),
        ("28", "csrf", "Cross-Site Request Forgery", "CSRF token validation and protection analysis"),
        ("29", "command_injection", "Command Injection", "OS command injection vulnerability detection"),
        ("30", "file_upload", "Unrestricted File Upload", "File upload vulnerability testing"),
        ("31", "deserialization", "Insecure Deserialization", "PHP, Python, Java, .NET deserialization"),
        ("32", "ssrf", "Server-Side Request Forgery", "SSRF to internal services and cloud metadata"),
    ],
    "🔒 SSL/TLS Security": [
        ("33", "ssl", "SSL/TLS Certificate", "Certificate validation, expiry, self-signed detection"),
        ("34", "ssl_protocols", "SSL/TLS Protocols", "Supported protocol versions and vulnerabilities"),
        ("35", "ssl_ciphers", "SSL/TLS Ciphers", "Cipher suite analysis and weak cipher detection"),
    ],
    "📋 HTTP Headers": [
        ("36", "headers", "Security Headers", "HSTS, CSP, X-Frame-Options, and other security headers"),
        ("37", "info_disclosure", "Information Disclosure", "Server, X-Powered-By, and technology headers"),
    ],
    "🔌 API Security": [
        ("38", "graphql", "GraphQL Security", "GraphQL introspection, query depth, mutations"),
        ("39", "rest_api", "REST API Security", "API endpoints, methods, CORS, authentication"),
        ("40", "jwt", "JWT Token Analysis", "JWT algorithm, weak secrets, sensitive data in payload"),
    ],
}


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    default_config = {
        'scan_mode': {'default': 'stealth', 'max_requests_per_second': 1.0, 'timeout': 30},
        'evasion': {'rotate_user_agent': True, 'random_delay': True, 'jitter': True},
        'proxy': {'enabled': False, 'tor_enabled': False},
        'reporting': {'formats': ['html'], 'output_directory': 'reports/output', 'include_remediation': True},
        'logging': {'level': 'INFO', 'file': 'logs/scanner.log'},
    }
    
    if not os.path.exists(config_path):
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        return default_config
    
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def setup_logging(config: dict):
    """Configure logging."""
    if not LOGURU_AVAILABLE:
        return
    
    log_config = config.get('logging', {})
    logger.remove()
    logger.add(
        sys.stderr,
        level="WARNING",  # Only show warnings and errors in console
        format="<red>{time:HH:mm:ss}</red> | <level>{level: <8}</level> | <level>{message}</level>",
        colorize=True
    )
    
    log_file = log_config.get('file', 'logs/scanner.log')
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        logger.add(log_file, level="DEBUG", rotation="10 MB", retention=5)


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print the application banner."""
    clear_screen()
    console.print(BANNER)


def get_target_url() -> str:
    """Get target URL from user with validation."""
    console.print("\n[bold yellow]📋 STEP 1: Enter Target URL[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    while True:
        url = Prompt.ask(
            "[bold cyan]🔗 Enter the target URL to scan[/bold cyan]",
            default="https://example.com"
        ).strip()
        
        if not url:
            console.print("[red]❌ URL cannot be empty![/red]")
            continue
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            console.print(f"[yellow]⚠️  Added https:// prefix: {url}[/yellow]")
        
        # Basic URL validation
        if '.' in url and len(url) > 10:
            console.print(f"\n[green]✅ Target URL: {url}[/green]")
            return url
        
        console.print("[red]❌ Invalid URL format! Please enter a valid URL.[/red]")


def select_scan_mode() -> str:
    """Let user select scan mode."""
    console.print("\n[bold yellow]📋 STEP 2: Select Scan Mode[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    modes = [
        ("1", "stealth", "🥷 Stealth Mode", "Maximum evasion, 2-5s delays, user-agent rotation", "Recommended for sensitive sites"),
        ("2", "normal", "⚖️ Normal Mode", "Balanced speed and evasion, 0.5-2s delays", "Good for most sites"),
        ("3", "aggressive", "⚡ Aggressive Mode", "Maximum speed, minimal evasion, 0.1-0.5s delays", "Only for your own sites"),
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", width=4)
    table.add_column("Mode", width=20)
    table.add_column("Description", width=45)
    table.add_column("Best For", width=30)
    
    for num, mode, name, desc, best in modes:
        table.add_row(num, name, desc, best)
    
    console.print(table)
    
    while True:
        choice = Prompt.ask("\n[bold cyan]Select mode[/bold cyan]", choices=["1", "2", "3"], default="1")
        
        for num, mode, name, _, _ in modes:
            if choice == num:
                console.print(f"\n[green]✅ Selected: {name}[/green]")
                return mode


def show_basic_info(target_url: str, config: dict):
    """Show basic information about the target before scanning."""
    console.print("\n[bold yellow]📋 STEP 3: Target Analysis[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]Analyzing target...", total=None)
        
        try:
            from core.browser import StealthBrowser
            from core.evasion import EvasionConfig, ScanMode
            
            evasion_config = EvasionConfig(mode=ScanMode.STEALTH)
            browser = StealthBrowser(target_url, evasion_config)
            
            # Get basic info
            resp = browser.get('/')
            progress.update(task, description="[cyan]Checking server headers...")
            
            info_table = Table(title="📊 Target Information", show_header=True)
            info_table.add_column("Property", style="cyan", width=20)
            info_table.add_column("Value", style="green", width=50)
            
            if resp:
                server = resp.headers.get('Server', 'Not disclosed')
                powered_by = resp.headers.get('X-Powered-By', 'Not disclosed')
                content_type = resp.headers.get('Content-Type', 'Unknown')
                status = resp.status_code
                size = len(resp.content)
                response_time = browser.stats.get('requests_successful', 0)
                
                info_table.add_row("URL", target_url)
                info_table.add_row("Status Code", str(status))
                info_table.add_row("Server", server)
                info_table.add_row("Powered By", powered_by)
                info_table.add_row("Content Type", content_type)
                info_table.add_row("Page Size", f"{size:,} bytes")
                info_table.add_row("HTTPS", "✅ Yes" if target_url.startswith('https') else "❌ No")
                
                # Quick CMS detection
                if 'wp-content' in resp.text.lower() or 'wordpress' in resp.text.lower():
                    info_table.add_row("CMS Detected", "🔍 WordPress (likely)")
                elif 'joomla' in resp.text.lower():
                    info_table.add_row("CMS Detected", "🔍 Joomla (likely)")
                elif 'drupal' in resp.text.lower():
                    info_table.add_row("CMS Detected", "🔍 Drupal (likely)")
                
                # Security headers quick check
                security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
                missing = [h for h in security_headers if h not in resp.headers]
                if missing:
                    info_table.add_row("⚠️ Missing Headers", f"[yellow]{', '.join(missing)}[/yellow]")
                else:
                    info_table.add_row("Security Headers", "[green]✅ All basic headers present[/green]")
            
            console.print(info_table)
            
        except Exception as e:
            console.print(f"[red]❌ Could not analyze target: {e}[/red]")


def select_modules() -> List[str]:
    """Interactive module selection menu."""
    console.print("\n[bold yellow]📋 STEP 4: Select Security Modules[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    all_modules = {}
    for category, modules in MODULE_CATEGORIES.items():
        console.print(f"\n[bold magenta]{category}[/bold magenta]")
        console.print("[dim]" + "─" * 60 + "[/dim]")
        
        for num, name, title, desc in modules:
            all_modules[num] = name
            console.print(f"  [bold cyan]{num:>2}[/bold cyan]. [bold]{title}[/bold]")
            console.print(f"      [dim]{desc}[/dim]")
    
    console.print("\n[bold yellow]Quick Options:[/bold yellow]")
    console.print("  [bold cyan] 0[/bold cyan]. [bold green]ALL modules[/bold green] - Run all 40 modules")
    console.print("  [bold cyan]41[/bold cyan]. [bold yellow]WordPress Suite[/bold yellow] - All WordPress modules (1)")
    console.print("  [bold cyan]42[/bold cyan]. [bold yellow]Vulnerability Suite[/bold yellow] - All vulnerability scanners (22-32)")
    console.print("  [bold cyan]43[/bold cyan]. [bold red]Top 10 Critical[/bold red] - Most important security checks")
    
    console.print("\n[dim]Enter module numbers separated by commas (e.g., 1,4,9,22,23)[/dim]")
    
    while True:
        choice = Prompt.ask("[bold cyan]Select modules[/bold cyan]", default="0").strip()
        
        if choice == "0":
            console.print("[green]✅ All 40 modules selected![/green]")
            return list(all_modules.values())
        
        elif choice == "41":
            console.print("[green]✅ WordPress Suite selected![/green]")
            return ["wordpress", "wordpress_version", "wordpress_plugins", "wordpress_themes", 
                    "wordpress_users", "wordpress_xmlrpc", "wordpress_backups", "wordpress_hardening"]
        
        elif choice == "42":
            console.print("[green]✅ Vulnerability Suite selected![/green]")
            return ["xss", "sqli", "lfi", "rfi", "xxe", "ssti", "csrf", 
                    "command_injection", "file_upload", "deserialization", "ssrf"]
        
        elif choice == "43":
            console.print("[green]✅ Top 10 Critical selected![/green]")
            return ["wordpress", "php_version", "xss", "sqli", "ssl", "headers", 
                    "cpanel", "mysql", "redis", "mongodb"]
        
        # Parse custom selection
        selected = []
        parts = [p.strip() for p in choice.split(',')]
        invalid = []
        
        for part in parts:
            if '-' in part:
                # Range selection
                try:
                    start, end = part.split('-')
                    for i in range(int(start), int(end) + 1):
                        num_str = str(i)
                        if num_str in all_modules:
                            selected.append(all_modules[num_str])
                        else:
                            invalid.append(num_str)
                except:
                    invalid.append(part)
            elif part in all_modules:
                selected.append(all_modules[part])
            else:
                invalid.append(part)
        
        if invalid:
            console.print(f"[red]❌ Invalid selections: {', '.join(invalid)}[/red]")
            console.print("[yellow]Please try again.[/yellow]")
            continue
        
        if selected:
            console.print(f"[green]✅ {len(selected)} module(s) selected![/green]")
            return selected
        
        console.print("[red]❌ No modules selected! Please try again.[/red]")


async def run_scan(target_url: str, mode: str, modules: List[str], config: dict) -> ScanResult:
    """Run the security scan with progress tracking."""
    console.print("\n[bold yellow]📋 STEP 5: Running Security Scan[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    # Update config
    config['scan_mode']['default'] = mode
    
    # Initialize scanner
    scanner = SecurityScanner(target_url, config)
    
    results = None
    scan_logs = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        
        task = progress.add_task("[cyan]Initializing scanner...", total=100)
        
        try:
            results = await scanner.scan(modules, progress, task)
            progress.update(task, completed=100, description="[green]✅ Scan complete!")
        except Exception as e:
            progress.update(task, description=f"[red]❌ Scan failed: {e}")
            raise
    
    return results


def show_results(results: ScanResult):
    """Display scan results in a beautiful format."""
    console.print("\n[bold yellow]📋 STEP 6: Scan Results[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    stats = results.statistics
    
    # Summary panel
    severity_colors = {
        'critical': 'red', 'high': 'orange1', 'medium': 'yellow',
        'low': 'green', 'info': 'blue'
    }
    
    summary_table = Table(title="📊 Security Scan Summary", show_header=True, header_style="bold")
    summary_table.add_column("Severity", width=12)
    summary_table.add_column("Count", justify="center", width=8)
    summary_table.add_column("Status", justify="center", width=8)
    summary_table.add_column("Bar", width=30)
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        count = stats.get(severity, 0)
        color = severity_colors.get(severity, 'white')
        status = "⚠️" if count > 0 else "✅"
        bar = "█" * min(count * 3, 30)
        
        summary_table.add_row(
            f"[{color}]{severity.upper()}[/{color}]",
            str(count),
            status,
            f"[{color}]{bar}[/{color}]"
        )
    
    summary_table.add_section()
    summary_table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{stats.get('total', 0)}[/bold]",
        "",
        ""
    )
    
    console.print(summary_table)
    
    # Show findings by severity
    if results.findings:
        console.print("\n[bold]🔍 Detailed Findings:[/bold]\n")
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = [f for f in results.findings if f.severity.lower() == severity]
            
            if severity_findings:
                color = severity_colors.get(severity, 'white')
                console.print(f"\n[bold {color}]━━━ {severity.upper()} ({len(severity_findings)}) ━━━[/bold {color}]")
                
                for i, finding in enumerate(severity_findings[:10], 1):
                    console.print(f"\n  [{color}]{i}.[/] [bold]{finding.title}[/bold]")
                    console.print(f"  [dim]Module: {finding.module}[/dim]")
                    
                    if finding.description:
                        desc = finding.description[:200]
                        console.print(f"  [dim]{desc}...[/dim]" if len(finding.description) > 200 else f"  [dim]{finding.description}[/dim]")
                    
                    if finding.cvss_score:
                        console.print(f"  [yellow]CVSS: {finding.cvss_score}[/yellow]", end="")
                    if finding.cve_id:
                        console.print(f"  [red]{finding.cve_id}[/red]", end="")
                    if finding.cvss_score or finding.cve_id:
                        console.print()
    
    # Module execution summary
    console.print(f"\n[dim]✅ Scan completed in {results.scan_duration:.1f} seconds[/dim]")
    console.print(f"[dim]📦 {len(results.modules_run)} modules executed[/dim]")


def save_report(results: ScanResult, config: dict):
    """Ask user if they want to save the report."""
    console.print("\n[bold yellow]📋 STEP 7: Save Report[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    save = Confirm.ask("[bold cyan]💾 Do you want to save the scan report?[/bold cyan]", default=True)
    
    if not save:
        console.print("[yellow]Report not saved.[/yellow]")
        return
    
    # Select format
    console.print("\n[bold]Available formats:[/bold]")
    console.print("  1. [green]HTML[/green] - Interactive report with charts (Recommended)")
    console.print("  2. [yellow]PDF[/yellow] - Printable report (requires wkhtmltopdf)")
    console.print("  3. [cyan]JSON[/cyan] - Machine-readable format")
    console.print("  4. [magenta]Markdown[/magenta] - Documentation format")
    console.print("  5. [bold]ALL[/bold] - Generate all formats")
    
    format_choice = Prompt.ask("[bold cyan]Select format[/bold cyan]", choices=["1", "2", "3", "4", "5"], default="1")
    
    format_map = {"1": "html", "2": "pdf", "3": "json", "4": "markdown", "5": "all"}
    selected_format = format_map[format_choice]
    
    # Output filename
    default_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_name = Prompt.ask("[bold cyan]Output filename (without extension)[/bold cyan]", default=default_name)
    
    try:
        from core.reporter import ReportGenerator
        reporter = ReportGenerator(results, config)
        
        formats_to_generate = ['html', 'json', 'markdown'] if selected_format == 'all' else [selected_format]
        
        # Remove PDF if 'all' is selected (to avoid errors)
        if selected_format == 'all':
            formats_to_generate = ['html', 'json', 'markdown']
            console.print("[yellow]⚠️  PDF skipped (requires wkhtmltopdf). HTML, JSON, and Markdown will be generated.[/yellow]")
        
        console.print("\n[bold]Generating reports...[/bold]")
        
        for fmt in formats_to_generate:
            try:
                with Progress(SpinnerColumn(), TextColumn(f"[progress.description]Generating {fmt.upper()}..."), transient=True) as progress:
                    task = progress.add_task("", total=None)
                    report_path = reporter.generate(format=fmt, output_path=output_name)
                    progress.update(task, completed=True)
                
                console.print(f"  [green]✅ {fmt.upper()}: {report_path}[/green]")
            except Exception as fmt_error:
                console.print(f"  [yellow]⚠️  {fmt.upper()}: Failed - {str(fmt_error)[:100]}[/yellow]")
        
        console.print(f"\n[bold green]✅ Report saved successfully![/bold green]")
        console.print(f"[dim]📁 Location: reports/output/[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Failed to generate report: {e}[/red]")
        console.print("[yellow]💡 Tip: Try HTML format which works on all platforms.[/yellow]")

        
    """Ask user if they want to save the report."""
    console.print("\n[bold yellow]📋 STEP 7: Save Report[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    save = Confirm.ask("[bold cyan]💾 Do you want to save the scan report?[/bold cyan]", default=True)
    
    if not save:
        console.print("[yellow]Report not saved.[/yellow]")
        return
    
    # Select format
    console.print("\n[bold]Available formats:[/bold]")
    console.print("  1. [green]HTML[/green] - Interactive report with charts")
    console.print("  2. [yellow]PDF[/yellow] - Printable report")
    console.print("  3. [cyan]JSON[/cyan] - Machine-readable format")
    console.print("  4. [magenta]Markdown[/magenta] - Documentation format")
    console.print("  5. [bold]ALL[/bold] - Generate all formats")
    
    format_choice = Prompt.ask("[bold cyan]Select format[/bold cyan]", choices=["1", "2", "3", "4", "5"], default="1")
    
    format_map = {"1": "html", "2": "pdf", "3": "json", "4": "markdown", "5": "all"}
    selected_format = format_map[format_choice]
    
    # Output filename
    default_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_name = Prompt.ask("[bold cyan]Output filename (without extension)[/bold cyan]", default=default_name)
    
    try:
        from core.reporter import ReportGenerator
        reporter = ReportGenerator(results, config)
        
        formats_to_generate = ['html', 'pdf', 'json', 'markdown'] if selected_format == 'all' else [selected_format]
        
        console.print("\n[bold]Generating reports...[/bold]")
        
        for fmt in formats_to_generate:
            with Progress(SpinnerColumn(), TextColumn(f"[progress.description]Generating {fmt.upper()}..."), transient=True) as progress:
                task = progress.add_task("", total=None)
                report_path = reporter.generate(format=fmt, output_path=output_name)
                progress.update(task, completed=True)
            
            console.print(f"  [green]✅ {fmt.upper()}: {report_path}[/green]")
        
        console.print(f"\n[bold green]✅ Report saved successfully![/bold green]")
        
    except Exception as e:
        console.print(f"[red]❌ Failed to generate report: {e}[/red]")


def show_final_summary(results: ScanResult):
    """Show final summary with next steps."""
    console.print("\n[bold yellow]📋 Final Summary[/bold yellow]")
    console.print("[dim]──────────────────────────────────────────────────────────────[/dim]\n")
    
    stats = results.statistics
    
    if stats.get('critical', 0) > 0 or stats.get('high', 0) > 0:
        console.print(Panel(
            "[bold red]🚨 CRITICAL/HIGH SEVERITY ISSUES FOUND![/bold red]\n\n"
            "[bold]Immediate Actions Required:[/bold]\n"
            "1. Review all critical and high findings\n"
            "2. Patch vulnerable software immediately\n"
            "3. Close exposed ports and services\n"
            "4. Implement missing security headers\n"
            "5. Run a follow-up scan to verify fixes\n\n"
            "[dim]Consider hiring a security professional for detailed analysis.[/dim]",
            title="⚠️ Action Required",
            border_style="red"
        ))
    elif stats.get('medium', 0) > 0:
        console.print(Panel(
            "[bold yellow]⚠️ MEDIUM SEVERITY ISSUES FOUND[/bold yellow]\n\n"
            "Review and address medium severity findings to improve security posture.",
            title="📋 Recommendations",
            border_style="yellow"
        ))
    else:
        console.print(Panel(
            "[bold green]✅ GOOD SECURITY POSTURE![/bold green]\n\n"
            "No critical or high severity issues found.\n"
            "Continue monitoring and regular scanning.",
            title="✅ Status",
            border_style="green"
        ))
    
    console.print(f"\n[dim]Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print(f"[dim]Tool version: {VERSION}[/dim]")


async def main():
    """Main interactive menu."""
    try:
        # Load config
        config = load_config()
        setup_logging(config)
        
        # Display banner
        print_banner()
        
        # Welcome message
        console.print("\n[bold green]Welcome to Web Security Analyzer Pro![/bold green]")
        console.print("[dim]This tool will guide you through a comprehensive security assessment.[/dim]\n")
        
        # Step 1: Get target URL
        target_url = get_target_url()
        
        # Step 2: Select scan mode
        mode = select_scan_mode()
        
        # Step 3: Show basic info
        show_basic_info(target_url, config)
        
        # Step 4: Select modules
        modules = select_modules()
        
        # Step 5: Run scan
        results = await run_scan(target_url, mode, modules, config)
        
        # Step 6: Show results
        show_results(results)
        
        # Step 7: Save report
        save_report(results, config)
        
        # Final summary
        show_final_summary(results)
        
        console.print("\n[bold green]Thank you for using Web Security Analyzer Pro! 🛡️[/bold green]\n")
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️ Scan interrupted by user.[/yellow]")
        console.print("[dim]Partial results may not be saved.[/dim]\n")
    except Exception as e:
        console.print(f"\n[red]❌ An error occurred: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports/output', exist_ok=True)
    os.makedirs('database', exist_ok=True)
    
    # Run the interactive menu
    asyncio.run(main())