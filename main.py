#!/usr/bin/env python3
"""
Web Security Analyzer Pro v3.0
Simple CLI tool for web security testing.
"""

import os
import sys
import time
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import SecurityScanner
from core.reporter import ReportGenerator


def load_config():
    """Load config or return defaults."""
    try:
        import yaml
        with open('config.yaml', 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except:
        return {}


def print_banner():
    """Print application banner."""
    print(f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════╗
║     Web Security Analyzer Pro v3.0                  ║
║     Comprehensive Web Security Testing Tool         ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def get_target_url():
    """Get target URL from user."""
    while True:
        url = input(f"{Fore.CYAN}🔗 Enter target URL: {Style.RESET_ALL}").strip()
        if not url:
            print(f"{Fore.RED}⚠ URL cannot be empty{Style.RESET_ALL}")
            continue
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url


def show_modules_menu():
    """Display available test modules."""
    print(f"""
{Fore.YELLOW}{'='*60}{Style.RESET_ALL}
{Fore.CYAN}📋 AVAILABLE TEST MODULES{Style.RESET_ALL}
{Fore.YELLOW}{'='*60}{Style.RESET_ALL}

{Fore.GREEN}🔹 CMS & Platforms:{Style.RESET_ALL}
   1. WordPress          8. Joomla
   2. WordPress Plugins   9. Drupal
   3. WordPress Themes
   4. WordPress Users
   5. WordPress XML-RPC
   6. WordPress REST API
   7. WordPress Backups

{Fore.GREEN}🔹 Web Servers:{Style.RESET_ALL}
  10. Apache             13. IIS
  11. Nginx              14. Tomcat
  12. LiteSpeed

{Fore.GREEN}🔹 PHP Security:{Style.RESET_ALL}
  15. PHP Version        17. Dangerous Functions
  16. PHP Configuration  18. PHP Info Disclosure

{Fore.GREEN}🔹 Databases:{Style.RESET_ALL}
  19. MySQL              21. Redis
  20. PostgreSQL          22. MongoDB

{Fore.GREEN}🔹 Control Panels:{Style.RESET_ALL}
  23. cPanel             25. Plesk
  24. DirectAdmin

{Fore.GREEN}🔹 Vulnerabilities:{Style.RESET_ALL}
  26. XSS (Cross-Site Scripting)
  27. SQL Injection
  28. LFI (Local File Inclusion)
  29. XXE (XML External Entity)
  30. SSTI (Server-Side Template Injection)
  31. CSRF
  32. Command Injection
  33. File Upload
  34. SSRF (Server-Side Request Forgery)

{Fore.GREEN}🔹 SSL & Security:{Style.RESET_ALL}
  35. SSL/TLS Certificate
  36. SSL Protocols
  37. Security Headers

{Fore.GREEN}🔹 API Security:{Style.RESET_ALL}
  38. GraphQL
  39. REST API
  40. JWT Tokens

{Fore.YELLOW}{'='*60}{Style.RESET_ALL}
{Fore.CYAN}Enter numbers separated by commas (e.g., 1,15,26,37){Style.RESET_ALL}
{Fore.CYAN}Or type 'all' to run all modules{Style.RESET_ALL}
{Fore.CYAN}Or type 0 to go back{Style.RESET_ALL}
""")


def get_module_selection():
    """Get user's module selection."""
    module_map = {
        '1': 'wordpress', '2': 'wordpress_plugins', '3': 'wordpress_themes',
        '4': 'wordpress_users', '5': 'wordpress_xmlrpc', '6': 'wordpress_rest',
        '7': 'wordpress_backups', '8': 'joomla', '9': 'drupal',
        '10': 'apache', '11': 'nginx', '12': 'litespeed',
        '13': 'iis', '14': 'tomcat',
        '15': 'php_version', '16': 'php_config', '17': 'php_functions', '18': 'php_info',
        '19': 'mysql', '20': 'postgresql', '21': 'redis', '22': 'mongodb',
        '23': 'cpanel', '24': 'directadmin', '25': 'plesk',
        '26': 'xss', '27': 'sqli', '28': 'lfi', '29': 'xxe',
        '30': 'ssti', '31': 'csrf', '32': 'command_injection',
        '33': 'file_upload', '34': 'ssrf',
        '35': 'ssl', '36': 'ssl_protocols', '37': 'headers',
        '38': 'graphql', '39': 'rest_api', '40': 'jwt',
    }
    
    while True:
        show_modules_menu()
        choice = input(f"{Fore.CYAN}🎯 Your selection: {Style.RESET_ALL}").strip()
        
        if choice == '0':
            return None
        
        if choice.lower() == 'all':
            return list(module_map.values())
        
        try:
            selected = []
            parts = choice.split(',')
            
            for part in parts:
                part = part.strip()
                if '-' in part:
                    start, end = part.split('-')
                    for i in range(int(start), int(end) + 1):
                        if str(i) in module_map:
                            selected.append(module_map[str(i)])
                elif part in module_map:
                    selected.append(module_map[part])
                else:
                    print(f"{Fore.RED}⚠ Invalid number: {part}{Style.RESET_ALL}")
            
            if selected:
                print(f"\n{Fore.GREEN}✅ Selected {len(selected)} modules:{Style.RESET_ALL}")
                for mod in selected:
                    print(f"   • {mod}")
                
                confirm = input(f"\n{Fore.CYAN}Start scan? (y/n): {Style.RESET_ALL}").strip().lower()
                if confirm in ['y', 'yes', '']:
                    return selected
                else:
                    continue
            else:
                print(f"{Fore.RED}⚠ No valid modules selected{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}⚠ Error: {e}{Style.RESET_ALL}")


def run_scan(target_url, selected_modules, config):
    """Execute the security scan."""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🔍 SCANNING: {target_url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"   Modules: {len(selected_modules)}")
    print(f"   Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Initialize scanner
    scanner = SecurityScanner(target_url, config)
    
    # Track time
    start_time = time.time()
    
    # Run each module
    for i, module_name in enumerate(selected_modules, 1):
        try:
            print(f"{Fore.YELLOW}[{i}/{len(selected_modules)}]{Style.RESET_ALL} Testing {module_name}...", end=' ')
            
            # Run module
            module_result = scanner._run_module_sync(module_name)
            
            # Process result
            if module_result:
                scanner.result.modules_run.append(module_name)
                scanner.result.module_results[module_name] = module_result
                
                findings = module_result.get('findings', [])
                scanner.result.findings.extend(findings)
                
                # Count severities
                for finding in findings:
                    sev = finding.get('severity', 'info').lower() if isinstance(finding, dict) else finding.severity.lower()
                    if sev in scanner.result.statistics:
                        scanner.result.statistics[sev] += 1
                    scanner.result.statistics['total'] += 1
                
                if findings:
                    print(f"{Fore.RED}⚠ {len(findings)} issues found{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}✅ Clean{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}⚠ No results{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}✗ Failed: {str(e)[:80]}{Style.RESET_ALL}")
    
    # Finalize
    scan_duration = time.time() - start_time
    scanner.result.scan_duration = scan_duration
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}✅ Scan Complete!{Style.RESET_ALL}")
    print(f"   Duration: {scan_duration:.1f} seconds")
    print(f"   Total findings: {scanner.result.statistics.get('total', 0)}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    return scanner.result


def save_report_dialog(result, config):
    """Dialog for saving scan report."""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}💾 SAVE REPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}1.{Style.RESET_ALL} 📄 HTML Report")
    print(f"{Fore.GREEN}2.{Style.RESET_ALL} 📝 Markdown Report")
    print(f"{Fore.GREEN}3.{Style.RESET_ALL} 📋 JSON Report")
    print(f"{Fore.GREEN}4.{Style.RESET_ALL} 📕 PDF Report")
    print(f"{Fore.GREEN}5.{Style.RESET_ALL} 📦 All Formats")
    print(f"{Fore.RED}0.{Style.RESET_ALL} 🔙 Skip - Don't Save\n")
    
    choice = input(f"{Fore.CYAN}Select format: {Style.RESET_ALL}").strip()
    
    if choice == '0' or not choice:
        print(f"{Fore.YELLOW}⚠ Report not saved{Style.RESET_ALL}")
        return
    
    format_map = {
        '1': 'html',
        '2': 'markdown',
        '3': 'json',
        '4': 'pdf',
        '5': 'all'
    }
    
    selected_format = format_map.get(choice)
    if not selected_format:
        print(f"{Fore.RED}⚠ Invalid choice{Style.RESET_ALL}")
        return
    
    # Get filename
    filename = input(f"{Fore.CYAN}Enter filename (without extension): {Style.RESET_ALL}").strip()
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_{timestamp}"
    
    # Convert result to dict if needed
    if hasattr(result, 'to_dict'):
        result_data = result.to_dict()
    else:
        result_data = result
    
    # Initialize reporter
    reporter = ReportGenerator(result_data, config)
    
    try:
        if selected_format == 'all':
            paths = reporter.generate_all(filename=filename)
            print(f"\n{Fore.GREEN}✅ Reports saved:{Style.RESET_ALL}")
            for fmt, path in paths.items():
                if path:
                    print(f"   📄 {fmt.upper()}: {path}")
        else:
            path = reporter.generate(format=selected_format, filename=filename)
            print(f"\n{Fore.GREEN}✅ Report saved:{Style.RESET_ALL}")
            print(f"   📄 {path}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Failed to save report: {e}{Style.RESET_ALL}")


def show_scan_results(result):
    """Display scan results summary."""
    if not result:
        return
    
    stats = result.statistics if hasattr(result, 'statistics') else result.get('statistics', {})
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📊 RESULTS SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"""
{Fore.RED}🔴 Critical: {stats.get('critical', 0)}{Style.RESET_ALL}
{Fore.YELLOW}🟠 High:     {stats.get('high', 0)}{Style.RESET_ALL}
{Fore.YELLOW}🟡 Medium:   {stats.get('medium', 0)}{Style.RESET_ALL}
{Fore.GREEN}🟢 Low:      {stats.get('low', 0)}{Style.RESET_ALL}
{Fore.BLUE}🔵 Info:     {stats.get('info', 0)}{Style.RESET_ALL}
{Fore.WHITE}📊 Total:    {stats.get('total', 0)}{Style.RESET_ALL}
""")
    
    # Show critical/high findings
    findings = result.findings if hasattr(result, 'findings') else result.get('findings', [])
    if findings:
        critical_high = [
            f for f in findings
            if (f.severity if hasattr(f, 'severity') else f.get('severity', '')).lower() in ['critical', 'high']
        ]
        
        if critical_high:
            print(f"{Fore.RED}🚨 TOP ISSUES:{Style.RESET_ALL}")
            for i, finding in enumerate(critical_high[:5], 1):
                title = finding.title if hasattr(finding, 'title') else finding.get('title', 'Unknown')
                severity = finding.severity if hasattr(finding, 'severity') else finding.get('severity', 'info')
                print(f"   {i}. [{severity.upper()}] {title}")


def main():
    """Main program loop."""
    config = load_config()
    last_result = None
    target_url = ""
    
    while True:
        print_banner()
        
        print(f"{Fore.GREEN}1.{Style.RESET_ALL} 🔍 Start New Scan")
        print(f"{Fore.GREEN}2.{Style.RESET_ALL} 📊 Save Report from Last Scan")
        print(f"{Fore.GREEN}3.{Style.RESET_ALL} 📋 Show Last Results")
        print(f"{Fore.RED}0.{Style.RESET_ALL} 🚪 Exit\n")
        
        choice = input(f"{Fore.CYAN}🎯 Select option: {Style.RESET_ALL}").strip()
        
        if choice == '0':
            print(f"\n{Fore.YELLOW}👋 Goodbye!{Style.RESET_ALL}\n")
            break
        
        elif choice == '1':
            # Get target URL
            target_url = get_target_url()
            if not target_url:
                continue
            
            # Get module selection
            selected_modules = get_module_selection()
            if not selected_modules:
                print(f"{Fore.YELLOW}⚠ Scan cancelled{Style.RESET_ALL}")
                continue
            
            # Run scan
            last_result = run_scan(target_url, selected_modules, config)
            
            # Show results
            show_scan_results(last_result)
            
            # Ask to save report
            save = input(f"\n{Fore.CYAN}💾 Save report? (y/n): {Style.RESET_ALL}").strip().lower()
            if save in ['y', 'yes', '']:
                save_report_dialog(last_result, config)
            
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        
        elif choice == '2':
            if last_result:
                save_report_dialog(last_result, config)
            else:
                print(f"{Fore.YELLOW}⚠ No scan results available. Run a scan first.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        
        elif choice == '3':
            if last_result:
                show_scan_results(last_result)
            else:
                print(f"{Fore.YELLOW}⚠ No scan results available.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        
        else:
            print(f"{Fore.RED}⚠ Invalid option{Style.RESET_ALL}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}👋 Program terminated by user{Style.RESET_ALL}\n")
        sys.exit(0)