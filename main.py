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
from typing import Optional, List, Dict, Tuple
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

# Module categories with their modules - each category is a page
MODULE_CATEGORIES = {
    "🔍 CMS & Platforms": {
        "modules": [
            ("1", "wordpress", "WordPress Security", "Detection, version, plugins, themes, users, backups, hardening"),
            ("2", "joomla", "Joomla Security", "Joomla detection and vulnerability assessment"),
            ("3", "drupal", "Drupal Security", "Drupal detection and security analysis"),
        ]
    },
    "🌐 Web Servers": {
        "modules": [
            ("1", "apache", "Apache HTTP Server", "Version, server-status, server-info, misconfigurations"),
            ("2", "nginx", "Nginx Web Server", "Version, stub_status, configuration issues"),
            ("3", "litespeed", "LiteSpeed Web Server", "Detection, admin interface, cache plugin"),
            ("4", "iis", "Microsoft IIS", "Version, web.config, trace.axd, Exchange detection"),
            ("5", "tomcat", "Apache Tomcat", "Manager, default credentials, examples"),
        ]
    },
    "🐘 PHP Security": {
        "modules": [
            ("1", "php_version", "PHP Version Detection", "PHP version enumeration and vulnerability matching"),
            ("2", "php_config", "PHP Configuration", "php.ini settings, phpinfo, session security"),
            ("3", "php_functions", "Dangerous PHP Functions", "Detection of exec, system, eval, dangerous functions"),
            ("4", "php_info", "PHP Information Disclosure", "Error logs, config files, composer, .env exposure"),
        ]
    },
    "🗄️ Database Security": {
        "modules": [
            ("1", "mysql", "MySQL Security", "Port scanning, error disclosure, phpMyAdmin detection"),
            ("2", "postgresql", "PostgreSQL Security", "Port scanning, authentication check, version disclosure"),
            ("3", "redis", "Redis Security", "Unauthorized access, dangerous commands"),
            ("4", "mongodb", "MongoDB Security", "Unauthorized access, version disclosure"),
            ("5", "elasticsearch", "Elasticsearch Security", "Indices enumeration, authentication check"),
        ]
    },
    "🖥️ Control Panels": {
        "modules": [
            ("1", "cpanel", "cPanel/WHM Security", "cPanel ports, WHM access, version disclosure"),
            ("2", "directadmin", "DirectAdmin Security", "Port scanning, interface access, version check"),
            ("3", "plesk", "Plesk Security", "Ports, API exposure, backup detection"),
            ("4", "virtualmin", "Virtualmin/Webmin", "Webmin detection, unauthenticated access, default creds"),
        ]
    },
    "🛡️ Vulnerability Scanners": {
        "modules": [
            ("1", "xss", "Cross-Site Scripting (XSS)", "Reflected, stored, and DOM-based XSS"),
            ("2", "sqli", "SQL Injection (SQLi)", "Error, boolean, time, and UNION-based SQLi"),
            ("3", "lfi", "Local File Inclusion (LFI)", "Path traversal and local file inclusion"),
            ("4", "rfi", "Remote File Inclusion (RFI)", "Remote file inclusion detection"),
            ("5", "xxe", "XML External Entity (XXE)", "XXE injection in XML parsers"),
            ("6", "ssti", "Server-Side Template Injection", "Template injection in various engines"),
            ("7", "csrf", "Cross-Site Request Forgery", "CSRF token and protection analysis"),
            ("8", "command_injection", "Command Injection", "OS command injection detection"),
            ("9", "file_upload", "Unrestricted File Upload", "File upload vulnerability testing"),
            ("10", "deserialization", "Insecure Deserialization", "PHP, Python, Java, .NET deserialization"),
            ("11", "ssrf", "Server-Side Request Forgery", "SSRF to internal services and cloud metadata"),
        ]
    },
    "🔒 SSL/TLS Security": {
        "modules": [
            ("1", "ssl", "SSL/TLS Certificate", "Certificate validation, expiry, self-signed detection"),
            ("2", "ssl_protocols", "SSL/TLS Protocols", "Supported protocols and vulnerabilities"),
            ("3", "ssl_ciphers", "SSL/TLS Ciphers", "Cipher suite analysis, weak cipher detection"),
        ]
    },
    "📋 HTTP Headers": {
        "modules": [
            ("1", "headers", "Security Headers", "HSTS, CSP, X-Frame-Options, and other security headers"),
            ("2", "info_disclosure", "Information Disclosure", "Server, X-Powered-By, technology headers"),
        ]
    },
    "🔌 API Security": {
        "modules": [
            ("1", "graphql", "GraphQL Security", "GraphQL introspection, query depth, mutations"),
            ("2", "rest_api", "REST API Security", "API endpoints, methods, CORS, authentication"),
            ("3", "jwt", "JWT Token Analysis", "JWT algorithm, weak secrets, sensitive data in payload"),
        ]
    },
}

# Quick select options
QUICK_OPTIONS = {
    "ALL": ("ALL", "Run ALL 40 modules", "Complete security assessment"),
    "WORDPRESS": ("WP", "WordPress Suite", "All WordPress modules"),
    "VULN": ("VULN", "Vulnerability Suite", "All vulnerability scanners (XSS, SQLi, etc.)"),
    "TOP10": ("TOP10", "Top 10 Critical", "Most important security checks"),
    "SERVER": ("SRV", "Server Security", "Web server + PHP + SSL/TLS + Headers"),
    "DB": ("DB", "Database Security", "All database modules"),
}


# ============================================================================
# Utility Functions
# ============================================================================

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
    logger.add(sys.stderr, level="WARNING", format="<red>{time:HH:mm:ss}</red> | <level>{message}</level>", colorize=True)
    log_file = log_config.get('file', 'logs/scanner.log')
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        logger.add(log_file, level="DEBUG", rotation="10 MB", retention=5)


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(title: str, step: int = 0):
    """Print a formatted section header."""
    clear_screen()
    console.print(BANNER)
    if step > 0:
        console.print(f"\n[bold yellow]📋 STEP {step}: {title}[/bold yellow]")
    else:
        console.print(f"\n[bold yellow]📋 {title}[/bold yellow]")
    console.print("[dim]" + "─" * 70 + "[/dim]\n")


def get_target_url() -> str:
    """Get target URL from user with validation."""
    print_header("Enter Target URL", 1)
    
    while True:
        url = Prompt.ask("[bold cyan]🔗 Enter the target URL to scan[/bold cyan]", default="https://example.com").strip()
        
        if not url:
            console.print("[red]❌ URL cannot be empty![/red]")
            continue
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            console.print(f"[yellow]⚠️  Added https:// prefix: {url}[/yellow]")
        
        if '.' in url and len(url) > 10:
            console.print(f"\n[green]✅ Target URL: {url}[/green]")
            return url
        
        console.print("[red]❌ Invalid URL format![/red]")


def select_scan_mode() -> str:
    """Let user select scan mode."""
    print_header("Select Scan Mode", 2)
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", width=4, style="cyan")
    table.add_column("Mode", width=22, style="bold")
    table.add_column("Speed", width=15)
    table.add_column("Evasion", width=15)
    table.add_column("Best For", width=30)
    
    table.add_row("1", "🥷 Stealth", "🐢 Slow", "🛡️ Maximum", "[green]Sensitive sites[/green]")
    table.add_row("2", "⚖️ Normal", "🐇 Medium", "🛡️ Balanced", "[yellow]Most sites[/yellow]")
    table.add_row("3", "⚡ Aggressive", "🚀 Fast", "⚠️ Minimal", "[red]Your own sites[/red]")
    
    console.print(table)
    console.print()
    
    while True:
        choice = Prompt.ask("[bold cyan]Select mode[/bold cyan]", choices=["1", "2", "3"], default="1")
        modes = {"1": "stealth", "2": "normal", "3": "aggressive"}
        names = {"1": "🥷 Stealth Mode", "2": "⚖️ Normal Mode", "3": "⚡ Aggressive Mode"}
        console.print(f"\n[green]✅ Selected: {names[choice]}[/green]")
        return modes[choice]


def show_basic_info(target_url: str, config: dict):
    """Show basic information about the target."""
    print_header("Target Analysis", 3)
    
    with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing target...[/cyan]"), transient=True) as progress:
        task = progress.add_task("", total=None)
        
        try:
            from core.browser import StealthBrowser
            from core.evasion import EvasionConfig, ScanMode
            
            evasion_config = EvasionConfig(mode=ScanMode.STEALTH)
            browser = StealthBrowser(target_url, evasion_config)
            resp = browser.get('/')
            
            table = Table(title="📊 Target Information", show_header=True)
            table.add_column("Property", style="cyan", width=22)
            table.add_column("Value", style="green", width=50)
            
            if resp:
                table.add_row("URL", target_url)
                table.add_row("Status Code", f"{resp.status_code} {'✅' if resp.status_code == 200 else '⚠️'}")
                table.add_row("Server", resp.headers.get('Server', '[dim]Not disclosed[/dim]'))
                table.add_row("Powered By", resp.headers.get('X-Powered-By', '[dim]Not disclosed[/dim]'))
                table.add_row("Content Type", resp.headers.get('Content-Type', 'Unknown'))
                table.add_row("Page Size", f"{len(resp.content):,} bytes")
                table.add_row("HTTPS", "✅ Yes" if target_url.startswith('https') else "❌ No")
                
                # CMS Detection
                text_lower = resp.text.lower()
                if 'wp-content' in text_lower or 'wordpress' in text_lower:
                    table.add_row("CMS Detected", "[bold cyan]🔍 WordPress[/bold cyan]")
                elif 'joomla' in text_lower:
                    table.add_row("CMS Detected", "[bold cyan]🔍 Joomla[/bold cyan]")
                elif 'drupal' in text_lower:
                    table.add_row("CMS Detected", "[bold cyan]🔍 Drupal[/bold cyan]")
                else:
                    table.add_row("CMS Detected", "[dim]Not identified[/dim]")
                
                # Quick security check
                security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
                missing = [h for h in security_headers if h not in resp.headers]
                if missing:
                    table.add_row("⚠️ Missing Headers", f"[yellow]{', '.join(missing)}[/yellow]")
                else:
                    table.add_row("Security Headers", "[green]✅ All basic headers present[/green]")
                
                # WAF Detection
                waf_indicators = {
                    'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
                    'Sucuri': ['x-sucuri-id', 'sucuri'],
                    'Wordfence': ['wordfence'],
                    'AWS WAF': ['x-amzn-requestid'],
                }
                detected_waf = None
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                for waf_name, indicators in waf_indicators.items():
                    if any(i.lower() in headers_lower or i.lower() in text_lower for i in indicators):
                        detected_waf = waf_name
                        break
                if detected_waf:
                    table.add_row("WAF Detected", f"[yellow]🛡️ {detected_waf}[/yellow]")
            
            console.print(table)
            console.print()
            
        except Exception as e:
            console.print(f"[red]❌ Could not analyze target: {e}[/red]")


# ============================================================================
# Category Page System
# ============================================================================

def show_category_page(category_name: str, category_data: dict) -> List[str]:
    """
    Display a category page and let user select modules.
    
    Returns:
        List of selected module names
    """
    selected_in_category = []
    
    while True:
        print_header(f"Select Modules - {category_name}")
        
        modules = category_data["modules"]
        
        # Display modules in a nice table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", width=4, style="cyan")
        table.add_column("Module", width=30, style="bold")
        table.add_column("Description", width=45, style="dim")
        table.add_column("Selected", width=10)
        
        for num, name, title, desc in modules:
            is_selected = name in selected_in_category
            status = "[green]✅ YES[/green]" if is_selected else "[dim]❌ NO[/dim]"
            table.add_row(num, title, desc, status)
        
        console.print(table)
        
        # Show summary
        if selected_in_category:
            console.print(f"\n[green]📦 {len(selected_in_category)} module(s) selected in this category[/green]")
            console.print(f"[dim]Currently selected: {', '.join(selected_in_category)}[/dim]")
        
        # Options
        console.print("\n[bold yellow]Options:[/bold yellow]")
        console.print("  [cyan]1-N[/cyan]    - Toggle individual module")
        console.print("  [cyan]A[/cyan]      - [green]Select ALL[/green] modules in this category")
        console.print("  [cyan]N[/cyan]      - [red]Deselect ALL[/red] modules in this category")
        console.print("  [cyan]D[/cyan]      - [bold]Done[/bold] - Save and return to main menu")
        console.print("  [cyan]B[/cyan]      - [yellow]Back[/yellow] - Return without saving")
        console.print("  [cyan]?[/cyan]      - Show this help")
        
        choice = Prompt.ask("\n[bold cyan]Enter your choice[/bold cyan]").strip().upper()
        
        if choice == 'D':
            console.print(f"\n[green]✅ {len(selected_in_category)} module(s) saved from {category_name}[/green]")
            return selected_in_category
        
        elif choice == 'B':
            console.print(f"\n[yellow]↩️ Returning to main menu...[/yellow]")
            return []
        
        elif choice == 'A':
            selected_in_category = [m[1] for m in modules]
            console.print(f"\n[green]✅ ALL {len(selected_in_category)} modules selected![/green]")
            time.sleep(0.5)
        
        elif choice == 'N':
            selected_in_category = []
            console.print(f"\n[red]❌ All modules deselected![/red]")
            time.sleep(0.5)
        
        elif choice == '?':
            continue
        
        else:
            # Check if it's a valid module number
            for num, name, title, desc in modules:
                if choice == num:
                    if name in selected_in_category:
                        selected_in_category.remove(name)
                        console.print(f"\n[red]❌ Deselected: {title}[/red]")
                    else:
                        selected_in_category.append(name)
                        console.print(f"\n[green]✅ Selected: {title}[/green]")
                    time.sleep(0.3)
                    break
            else:
                console.print(f"\n[red]❌ Invalid choice: {choice}[/red]")
                time.sleep(0.5)


def show_main_module_menu() -> Tuple[List[str], List[str]]:
    """
    Show main category menu with page-based navigation.
    
    Returns:
        Tuple of (selected_module_names, selected_category_names)
    """
    all_selected_modules = {}
    category_names = list(MODULE_CATEGORIES.keys())
    quick_options = list(QUICK_OPTIONS.keys())
    
    while True:
        print_header("Select Security Modules", 4)
        
        # Display categories as a menu
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", width=4, style="cyan")
        table.add_column("Category", width=35, style="bold")
        table.add_column("Modules", width=10, justify="center")
        table.add_column("Selected", width=15)
        
        for i, cat_name in enumerate(category_names, 1):
            cat_data = MODULE_CATEGORIES[cat_name]
            total = len(cat_data["modules"])
            selected = len(all_selected_modules.get(cat_name, []))
            status = f"[green]{selected}/{total}[/green]" if selected > 0 else f"[dim]0/{total}[/dim]"
            table.add_row(str(i), cat_name, str(total), status)
        
        console.print(table)
        
        # Quick options
        console.print("\n[bold yellow]🚀 Quick Options:[/bold yellow]")
        quick_table = Table(show_header=False)
        quick_table.add_column("Key", width=8, style="cyan")
        quick_table.add_column("Name", width=20, style="bold")
        quick_table.add_column("Description", width=45, style="dim")
        
        quick_keys = {
            "ALL": ("Q0", "ALL Modules", "Run all 40 security modules"),
            "WORDPRESS": ("QW", "WordPress Suite", "All WordPress detection and analysis modules"),
            "VULN": ("QV", "Vulnerability Suite", "XSS, SQLi, LFI, RFI, XXE, SSTI, CSRF, etc."),
            "TOP10": ("QT", "Top 10 Critical", "Most important security checks"),
            "SERVER": ("QS", "Server Security", "Web server + PHP + SSL/TLS + Headers"),
            "DB": ("QD", "Database Security", "MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch"),
        }
        
        for key, (qk, qn, qd) in quick_keys.items():
            quick_table.add_row(f"[bold]{qk}[/bold]", qn, qd)
        
        console.print(quick_table)
        
        # Total selected
        total_selected = sum(len(v) for v in all_selected_modules.values())
        if total_selected > 0:
            console.print(f"\n[bold green]📦 Total selected: {total_selected} module(s)[/bold green]")
        
        # Navigation
        console.print("\n[bold yellow]Navigation:[/bold yellow]")
        console.print("  [cyan]1-9[/cyan]    - Open category page")
        console.print("  [cyan]Q0[/cyan]     - [green]Select ALL modules[/green]")
        console.print("  [cyan]QW[/cyan]     - WordPress Suite")
        console.print("  [cyan]QV[/cyan]     - Vulnerability Suite")
        console.print("  [cyan]QT[/cyan]     - Top 10 Critical")
        console.print("  [cyan]QS[/cyan]     - Server Security")
        console.print("  [cyan]QD[/cyan]     - Database Security")
        console.print("  [cyan]R[/cyan]      - [red]Reset ALL selections[/red]")
        console.print("  [cyan]D[/cyan]      - [bold green]DONE - Start Scan[/bold green]")
        console.print("  [cyan]?[/cyan]      - Show this help")
        
        choice = Prompt.ask("\n[bold cyan]Enter your choice[/bold cyan]").strip().upper()
        
        # Process choice
        if choice == 'D':
            if total_selected == 0:
                console.print("\n[red]❌ No modules selected! Please select at least one module.[/red]")
                time.sleep(1)
                continue
            
            # Flatten all selected modules
            final_modules = []
            final_categories = []
            for cat_name, mods in all_selected_modules.items():
                if mods:
                    final_modules.extend(mods)
                    final_categories.append(cat_name)
            
            console.print(f"\n[bold green]✅ {len(final_modules)} module(s) from {len(final_categories)} category(ies) selected![/bold green]")
            console.print(f"[dim]Categories: {', '.join(final_categories)}[/dim]")
            time.sleep(1)
            return final_modules, final_categories
        
        elif choice == 'R':
            all_selected_modules = {}
            console.print("\n[red]🔄 All selections cleared![/red]")
            time.sleep(0.5)
        
        elif choice == '?':
            continue
        
        elif choice.startswith('Q'):
            # Quick select options
            quick_map = {
                "Q0": "ALL",
                "QW": "WORDPRESS",
                "QV": "VULN",
                "QT": "TOP10",
                "QS": "SERVER",
                "QD": "DB",
            }
            
            if choice in quick_map:
                key = quick_map[choice]
                
                if key == "ALL":
                    for cat_name in category_names:
                        all_selected_modules[cat_name] = [m[1] for m in MODULE_CATEGORIES[cat_name]["modules"]]
                    console.print(f"\n[green]✅ ALL 40 modules selected![/green]")
                
                elif key == "WORDPRESS":
                    all_selected_modules[category_names[0]] = [m[1] for m in MODULE_CATEGORIES[category_names[0]]["modules"]]
                    console.print(f"\n[green]✅ WordPress Suite selected![/green]")
                
                elif key == "VULN":
                    vuln_cat = category_names[5]  # Vulnerability Scanners
                    all_selected_modules[vuln_cat] = [m[1] for m in MODULE_CATEGORIES[vuln_cat]["modules"]]
                    console.print(f"\n[green]✅ Vulnerability Suite selected![/green]")
                
                elif key == "TOP10":
                    top_modules = ["wordpress", "php_version", "xss", "sqli", "ssl", "headers", "cpanel", "mysql", "redis", "mongodb"]
                    for cat_name in category_names:
                        cat_mods = [m[1] for m in MODULE_CATEGORIES[cat_name]["modules"] if m[1] in top_modules]
                        if cat_mods:
                            all_selected_modules[cat_name] = cat_mods
                    console.print(f"\n[green]✅ Top 10 Critical selected![/green]")
                
                elif key == "SERVER":
                    server_cats = [category_names[1], category_names[2], category_names[6], category_names[7]]  # Web, PHP, SSL, Headers
                    for cat_name in server_cats:
                        all_selected_modules[cat_name] = [m[1] for m in MODULE_CATEGORIES[cat_name]["modules"]]
                    console.print(f"\n[green]✅ Server Security selected![/green]")
                
                elif key == "DB":
                    db_cat = category_names[3]  # Database Security
                    all_selected_modules[db_cat] = [m[1] for m in MODULE_CATEGORIES[db_cat]["modules"]]
                    console.print(f"\n[green]✅ Database Security selected![/green]")
                
                time.sleep(0.5)
        
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(category_names):
                cat_name = category_names[idx]
                cat_data = MODULE_CATEGORIES[cat_name]
                
                # Show category page
                selected = show_category_page(cat_name, cat_data)
                if selected:
                    all_selected_modules[cat_name] = selected
                elif cat_name in all_selected_modules:
                    # If user went Back, keep previous selection
                    pass
        
        else:
            console.print(f"\n[red]❌ Invalid choice: {choice}[/red]")
            time.sleep(0.5)


# ============================================================================
# Scan Execution
# ============================================================================

async def run_scan(target_url: str, mode: str, modules: List[str], config: dict) -> Optional[ScanResult]:
    """Run the security scan with progress tracking."""
    print_header("Running Security Scan", 5)
    
    # Update config
    config['scan_mode']['default'] = mode
    
    # Show scan info
    console.print(f"[bold cyan]Target:[/bold cyan] {target_url}")
    console.print(f"[bold cyan]Mode:[/bold cyan] {mode}")
    console.print(f"[bold cyan]Modules:[/bold cyan] {len(modules)}")
    console.print()
    
    # Initialize scanner
    scanner = SecurityScanner(target_url, config)
    
    results = None
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        
        task = progress.add_task(f"[cyan]Scanning {len(modules)} module(s)...", total=len(modules))
        
        try:
            results = await scanner.scan(modules, progress, task)
            progress.update(task, completed=len(modules), description="[green]✅ Scan complete![/green]")
        except Exception as e:
            progress.update(task, description=f"[red]❌ Error: {e}[/red]")
            console.print(f"\n[red]❌ Scan failed: {e}[/red]")
            return None
    
    return results


def show_results(results: ScanResult):
    """Display scan results."""
    print_header("Scan Results", 6)
    
    stats = results.statistics
    
    severity_colors = {
        'critical': 'red', 'high': 'orange1', 'medium': 'yellow',
        'low': 'green', 'info': 'blue'
    }
    
    # Summary table
    summary_table = Table(title="📊 Security Scan Summary", show_header=True, header_style="bold")
    summary_table.add_column("Severity", width=12)
    summary_table.add_column("Count", justify="center", width=8)
    summary_table.add_column("Status", justify="center", width=8)
    summary_table.add_column("Bar", width=35)
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        count = stats.get(severity, 0)
        color = severity_colors.get(severity, 'white')
        status = "⚠️" if count > 0 else "✅"
        bar_len = min(count * 3, 35)
        bar = "█" * bar_len if bar_len > 0 else ""
        
        summary_table.add_row(
            f"[{color}]{severity.upper()}[/{color}]",
            str(count),
            status,
            f"[{color}]{bar}[/{color}]"
        )
    
    summary_table.add_section()
    summary_table.add_row("[bold]TOTAL[/bold]", f"[bold]{stats.get('total', 0)}[/bold]", "", "")
    
    console.print(summary_table)
    
    # Detailed findings
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
                        if len(finding.description) > 200:
                            desc += "..."
                        console.print(f"  [dim]{desc}[/dim]")
                    
                    if finding.cvss_score:
                        console.print(f"  [yellow]CVSS: {finding.cvss_score}[/yellow]", end="")
                    if finding.cve_id:
                        console.print(f"  [red]  {finding.cve_id}[/red]", end="")
                    if finding.cvss_score or finding.cve_id:
                        console.print()
    
    console.print(f"\n[dim]✅ Scan completed in {results.scan_duration:.1f} seconds[/dim]")
    console.print(f"[dim]📦 {len(results.modules_run)} modules executed[/dim]")


def save_report(results: ScanResult, config: dict):
    """Ask user if they want to save the report."""
    print_header("Save Report", 7)
    
    save = Confirm.ask("[bold cyan]💾 Do you want to save the scan report?[/bold cyan]", default=True)
    
    if not save:
        console.print("[yellow]Report not saved.[/yellow]")
        return
    
    console.print("\n[bold]Available formats:[/bold]")
    console.print("  1. [green]HTML[/green] - Interactive report with charts (Recommended)")
    console.print("  2. [cyan]JSON[/cyan] - Machine-readable format")
    console.print("  3. [magenta]Markdown[/magenta] - Documentation format")
    console.print("  4. [yellow]PDF[/yellow] - Printable report (requires wkhtmltopdf)")
    console.print("  5. [bold]ALL[/bold] - Generate all formats")
    
    format_choice = Prompt.ask("[bold cyan]Select format[/bold cyan]", choices=["1", "2", "3", "4", "5"], default="1")
    
    format_map = {"1": "html", "2": "json", "3": "markdown", "4": "pdf", "5": "all"}
    selected_format = format_map[format_choice]
    
    default_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_name = Prompt.ask("[bold cyan]Output filename (without extension)[/bold cyan]", default=default_name)
    
    try:
        from core.reporter import ReportGenerator
        reporter = ReportGenerator(results, config)
        
        if selected_format == 'all':
            formats_to_generate = ['html', 'json', 'markdown']
            console.print("[yellow]⚠️  PDF skipped (requires wkhtmltopdf). Generating HTML, JSON, and Markdown...[/yellow]")
        elif selected_format == 'pdf':
            formats_to_generate = ['html', 'pdf']  # Try both
        else:
            formats_to_generate = [selected_format]
        
        console.print("\n[bold]Generating reports...[/bold]")
        
        for fmt in formats_to_generate:
            try:
                with Progress(SpinnerColumn(), TextColumn(f"[cyan]{fmt.upper()}...[/cyan]"), transient=True) as progress:
                    task = progress.add_task("", total=None)
                    report_path = reporter.generate(format=fmt, output_path=output_name)
                    progress.update(task, completed=True)
                console.print(f"  [green]✅ {fmt.upper()}: {report_path}[/green]")
            except Exception as fmt_error:
                if fmt == 'pdf':
                    console.print(f"  [yellow]⚠️  PDF: wkhtmltopdf not found. HTML report generated instead.[/yellow]")
                else:
                    console.print(f"  [red]❌ {fmt.upper()}: {str(fmt_error)[:80]}[/red]")
        
        console.print(f"\n[bold green]✅ Report saved successfully![/bold green]")
        console.print(f"[dim]📁 Location: reports/output/[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Failed to generate report: {e}[/red]")


def show_final_summary(results: ScanResult):
    """Show final summary with recommendations."""
    print_header("Final Summary")
    
    stats = results.statistics
    critical = stats.get('critical', 0)
    high = stats.get('high', 0)
    medium = stats.get('medium', 0)
    
    if critical > 0:
        console.print(Panel(
            f"[bold red]🚨 {critical} CRITICAL ISSUE(S) FOUND![/bold red]\n\n"
            "[bold]Immediate Actions Required:[/bold]\n"
            "1. Review all critical findings immediately\n"
            "2. Close exposed ports and services NOW\n"
            "3. Patch vulnerable software\n"
            "4. Change exposed credentials\n"
            "5. Run a follow-up scan to verify fixes\n\n"
            "[dim]Consider hiring a security professional for urgent remediation.[/dim]",
            title="🔴 CRITICAL - Immediate Action Required",
            border_style="red"
        ))
    elif high > 0:
        console.print(Panel(
            f"[bold orange1]⚠️ {high + critical} HIGH-PRIORITY ISSUE(S)[/bold orange1]\n\n"
            "[bold]Recommended Actions:[/bold]\n"
            "1. Review all high-severity findings\n"
            "2. Implement missing security headers\n"
            "3. Update vulnerable software\n"
            "4. Restrict access to admin interfaces\n"
            "5. Schedule a follow-up scan\n\n"
            "[dim]Address these issues within the next 7 days.[/dim]",
            title="🟠 Action Required",
            border_style="orange1"
        ))
    elif medium > 0:
        console.print(Panel(
            f"[bold yellow]📋 {medium} MEDIUM SEVERITY ISSUE(S)[/bold yellow]\n\n"
            "Review and address medium severity findings to improve security posture.",
            title="📋 Recommendations",
            border_style="yellow"
        ))
    else:
        console.print(Panel(
            "[bold green]✅ GOOD SECURITY POSTURE![/bold green]\n\n"
            "No critical, high, or medium severity issues found.\n"
            "Continue monitoring and regular scanning to maintain security.",
            title="✅ Status",
            border_style="green"
        ))
    
    console.print(f"\n[dim]Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print(f"[dim]Tool version: {VERSION}[/dim]")


# ============================================================================
# Main Function
# ============================================================================

async def main():
    """Main interactive menu."""
    try:
        # Load config
        config = load_config()
        setup_logging(config)
        
        # Welcome
        clear_screen()
        console.print(BANNER)
        console.print("\n[bold green]Welcome to Web Security Analyzer Pro![/bold green]")
        console.print("[dim]This interactive tool will guide you through a comprehensive security assessment.[/dim]")
        console.print("[dim]Follow the steps below to configure and run your scan.[/dim]\n")
        
        Prompt.ask("[dim]Press Enter to continue...[/dim]", default="")
        
        # Step 1: Get target URL
        target_url = get_target_url()
        
        # Step 2: Select scan mode
        mode = select_scan_mode()
        
        # Step 3: Show basic info
        show_basic_info(target_url, config)
        Prompt.ask("[dim]Press Enter to continue to module selection...[/dim]", default="")
        
        # Step 4: Select modules (page-based)
        modules, categories = show_main_module_menu()
        
        # Show summary before scan
        print_header("Ready to Scan")
        console.print(f"[bold cyan]Target:[/bold cyan] {target_url}")
        console.print(f"[bold cyan]Mode:[/bold cyan] {mode}")
        console.print(f"[bold cyan]Modules:[/bold cyan] {len(modules)}")
        console.print(f"[bold cyan]Categories:[/bold cyan] {', '.join(categories)}")
        console.print()
        
        if not Confirm.ask("[bold green]Start scan now?[/bold green]", default=True):
            console.print("[yellow]Scan cancelled.[/yellow]")
            return
        
        # Step 5: Run scan
        results = await run_scan(target_url, mode, modules, config)
        
        if results is None:
            console.print("[red]Scan failed. Exiting.[/red]")
            return
        
        # Step 6: Show results
        show_results(results)
        
        # Step 7: Save report
        save_report(results, config)
        
        # Final summary
        show_final_summary(results)
        
        console.print("\n[bold green]Thank you for using Web Security Analyzer Pro! 🛡️[/bold green]\n")
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️ Program interrupted by user.[/yellow]")
        console.print("[dim]Goodbye![/dim]\n")
    except Exception as e:
        console.print(f"\n[red]❌ An unexpected error occurred: {e}[/red]")
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