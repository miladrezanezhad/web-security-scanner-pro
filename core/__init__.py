"""
Web Security Analyzer Pro - Core Module
Version: 3.0.0

This package contains the core engine components for the security scanner.

Modules:
    scanner: Main scanner orchestrator
    browser: Stealth HTTP client with evasion
    evasion: Anti-detection and WAF bypass engine
    database: Vulnerability database management
    updater: Automatic database and signature updates
    reporter: Report generation in multiple formats
    api: REST API server for remote scanning
"""

__version__ = "3.0.0"
__author__ = "Security Research Team"
__license__ = "GPLv3"

from core.scanner import SecurityScanner, ScanResult, Finding
from core.browser import StealthBrowser
from core.evasion import EvasionEngine, EvasionConfig, ScanMode
from core.database import VulnerabilityDatabase
from core.reporter import ReportGenerator
from core.updater import DatabaseUpdater
from core.api import APIServer

__all__ = [
    "SecurityScanner",
    "ScanResult",
    "Finding",
    "StealthBrowser",
    "EvasionEngine",
    "EvasionConfig",
    "ScanMode",
    "VulnerabilityDatabase",
    "ReportGenerator",
    "DatabaseUpdater",
    "APIServer",
]