#!/usr/bin/env python3
"""
Master test runner - runs all tests in order.
Usage:
    python tests/test_runner.py              # Run all tests
    python tests/test_runner.py --quick      # Quick test (core only)
    python tests/test_runner.py --modules    # Module tests only
    python tests/test_runner.py --core       # Core tests only
"""

import sys
import os
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def print_header(title):
    """Print a formatted header."""
    width = 70
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)
    print()


def print_result(name, passed, total, duration):
    """Print a test result line."""
    status = "✅ PASS" if passed == total else "❌ FAIL"
    print(f"  {status}  {name:<40} {passed}/{total}  ({duration:.1f}s)")


def run_pytest(test_path, verbose=False):
    """Run pytest on a specific path and return results."""
    import pytest
    
    args = [str(test_path), "--tb=short", "--color=yes", "-p", "no:warnings"]
    
    if verbose:
        args.append("-v")
    
    start = time.time()
    exit_code = pytest.main(args)
    duration = time.time() - start
    
    return exit_code, duration


def run_simple_module_test():
    """Run the simple module test without pytest dependency."""
    print_header("🧪 SIMPLE MODULE IMPORT TEST")
    print("  Testing that all 40+ modules can be imported...")
    print()
    
    sys.path.insert(0, str(PROJECT_ROOT))
    
    # Create dummy objects for testing
    class DummyBrowser:
        def get(self, path='/'): return None
        def post(self, path='/', data=None): return None
        def head(self, path='/'): return None

    dummy_browser = DummyBrowser()
    dummy_target = "https://example.com"
    dummy_config = {'scan_mode': {'default': 'stealth'}, 'modules': {}}
    
    # Module list: (name, import_path)
    MODULES = [
        # CMS - WordPress
        ("WordPress Detector", "modules.cms.wordpress.detector"),
        ("WordPress Version", "modules.cms.wordpress.version"),
        ("WordPress Plugins", "modules.cms.wordpress.plugins"),
        ("WordPress Themes", "modules.cms.wordpress.themes"),
        ("WordPress Users", "modules.cms.wordpress.users"),
        ("WordPress XML-RPC", "modules.cms.wordpress.xmlrpc"),
        ("WordPress REST API", "modules.cms.wordpress.rest_api"),
        ("WordPress Backups", "modules.cms.wordpress.backups"),
        ("WordPress Hardening", "modules.cms.wordpress.hardening"),
        
        # CMS - Other
        ("Joomla", "modules.cms.joomla.scanner"),
        ("Drupal", "modules.cms.drupal.scanner"),
        
        # Web Servers
        ("Apache", "modules.webserver.apache"),
        ("Nginx", "modules.webserver.nginx"),
        ("LiteSpeed", "modules.webserver.litespeed"),
        ("IIS", "modules.webserver.iis"),
        ("Tomcat", "modules.webserver.tomcat"),
        
        # PHP
        ("PHP Version", "modules.php.version"),
        ("PHP Configuration", "modules.php.configuration"),
        ("PHP Dangerous Functions", "modules.php.dangerous_functions"),
        ("PHP Info Disclosure", "modules.php.info_disclosure"),
        
        # Databases
        ("MySQL", "modules.database.mysql"),
        ("PostgreSQL", "modules.database.postgresql"),
        ("Redis", "modules.database.redis"),
        ("MongoDB", "modules.database.mongodb"),
        ("Elasticsearch", "modules.database.elasticsearch"),
        
        # Control Panels
        ("cPanel", "modules.control_panels.cpanel"),
        ("DirectAdmin", "modules.control_panels.directadmin"),
        ("Plesk", "modules.control_panels.plesk"),
        ("Virtualmin", "modules.control_panels.virtualmin"),
        
        # Vulnerabilities
        ("XSS", "modules.vulnerabilities.xss"),
        ("SQL Injection", "modules.vulnerabilities.sqli"),
        ("LFI", "modules.vulnerabilities.lfi"),
        ("RFI", "modules.vulnerabilities.rfi"),
        ("XXE", "modules.vulnerabilities.xxe"),
        ("SSTI", "modules.vulnerabilities.ssti"),
        ("CSRF", "modules.vulnerabilities.csrf"),
        ("Command Injection", "modules.vulnerabilities.command_injection"),
        ("File Upload", "modules.vulnerabilities.file_upload"),
        ("Deserialization", "modules.vulnerabilities.deserialization"),
        ("SSRF", "modules.vulnerabilities.ssrf"),
        
        # SSL/TLS
        ("SSL Certificate", "modules.ssl_tls.certificate"),
        ("SSL Protocols", "modules.ssl_tls.protocols"),
        ("SSL Ciphers", "modules.ssl_tls.ciphers"),
        
        # Headers
        ("Security Headers", "modules.headers.security_headers"),
        ("Info Disclosure", "modules.headers.information_disclosure"),
        
        # API Security
        ("GraphQL", "modules.api_security.graphql"),
        ("REST API", "modules.api_security.rest_api"),
        ("JWT Tokens", "modules.api_security.jwt"),
    ]
    
    passed = 0
    failed = 0
    
    for display_name, import_path in MODULES:
        try:
            module = __import__(import_path, fromlist=['Scanner'])
            
            if hasattr(module, 'Scanner'):
                scanner = module.Scanner(
                    browser=dummy_browser,
                    target_url=dummy_target,
                    config=dummy_config
                )
                print(f"  ✅ {display_name:<40} Imported + Initialized")
                passed += 1
            elif hasattr(module, 'run'):
                print(f"  ✅ {display_name:<40} Imported (has run function)")
                passed += 1
            else:
                print(f"  ⚠️  {display_name:<40} Imported (no Scanner class)")
                failed += 1
                
        except ModuleNotFoundError as e:
            print(f"  ❌ {display_name:<40} Module not found")
            failed += 1
        except Exception as e:
            print(f"  ❌ {display_name:<40} Error: {str(e)[:50]}")
            failed += 1
    
    print()
    print(f"  Results: {passed} passed, {failed} failed, {len(MODULES)} total")
    
    return passed, failed


def run_all_tests():
    """Main test runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Web Security Analyzer Pro Test Runner")
    parser.add_argument("--quick", action="store_true", help="Quick test (simple import check only)")
    parser.add_argument("--modules", action="store_true", help="Module tests only")
    parser.add_argument("--core", action="store_true", help="Core tests only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    print_header("🧪 Web Security Analyzer Pro - Test Suite")
    print(f"  Project Root: {PROJECT_ROOT}")
    print(f"  Python: {sys.version}")
    
    total_start = time.time()
    all_passed = True
    
    if args.quick:
        # Simple import test - no pytest needed
        passed, failed = run_simple_module_test()
        all_passed = (failed == 0)
        
    elif args.modules:
        # Run module tests with pytest
        print_header("📦 MODULE TESTS")
        module_test_dir = PROJECT_ROOT / "tests" / "modules"
        
        if module_test_dir.exists():
            exit_code, duration = run_pytest(module_test_dir, args.verbose)
            print_result("Module Tests", 0, 0, duration)
            all_passed = (exit_code == 0)
        else:
            print(f"  ⚠️  Module test directory not found: {module_test_dir}")
            
    elif args.core:
        # Run core tests with pytest
        print_header("⚙️ CORE TESTS")
        core_test_dir = PROJECT_ROOT / "tests" / "core"
        
        if core_test_dir.exists():
            exit_code, duration = run_pytest(core_test_dir, args.verbose)
            print_result("Core Tests", 0, 0, duration)
            all_passed = (exit_code == 0)
        else:
            print(f"  ⚠️  Core test directory not found: {core_test_dir}")
            
    else:
        # Run all tests
        
        # 1. Simple import test
        print_header("📦 MODULE IMPORT TEST")
        passed, failed = run_simple_module_test()
        if failed > 0:
            all_passed = False
        
        # 2. Core tests
        print_header("⚙️ CORE TESTS (pytest)")
        core_test_dir = PROJECT_ROOT / "tests" / "core"
        if core_test_dir.exists():
            exit_code, duration = run_pytest(core_test_dir, args.verbose)
            print_result("Core Tests", 0, 0, duration)
            if exit_code != 0:
                all_passed = False
        
        # 3. Module tests
        print_header("📦 MODULE TESTS (pytest)")
        module_test_dir = PROJECT_ROOT / "tests" / "modules"
        if module_test_dir.exists():
            exit_code, duration = run_pytest(module_test_dir, args.verbose)
            print_result("Module Tests", 0, 0, duration)
            if exit_code != 0:
                all_passed = False
    
    # Final summary
    total_duration = time.time() - total_start
    
    print_header("📊 FINAL SUMMARY")
    if all_passed:
        print("  ✅ ALL TESTS PASSED!")
    else:
        print("  ❌ SOME TESTS FAILED!")
    print(f"  Total time: {total_duration:.1f}s")
    print()
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(run_all_tests())