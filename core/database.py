#!/usr/bin/env python3
"""
Vulnerability Database Manager.
Stores and queries known vulnerabilities for version checking.
"""

import sqlite3
import os
import re
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
from packaging import version as pkg_version
from loguru import logger


class VulnerabilityDatabase:
    """Manage SQLite vulnerability database."""
    
    def __init__(self, db_path: str = "database/vulnerabilities.db"):
        """Initialize database connection."""
        self.db_path = db_path
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        
        self._query_cache = {}
        self.CACHE_TTL = 3600
        
        self._create_tables()
        self._create_indexes()
        self._check_and_seed()
        
        logger.info(f"Database initialized: {db_path}")
    
    def _create_tables(self):
        """Create database tables if they don't exist."""
        self.cursor.executescript("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                component TEXT NOT NULL,
                vendor TEXT,
                title TEXT NOT NULL,
                description TEXT,
                affected_versions TEXT NOT NULL,
                fixed_version TEXT,
                severity TEXT NOT NULL,
                cvss_score REAL DEFAULT 0.0,
                cve_id TEXT,
                cwe_id TEXT,
                refs TEXT,
                exploit_available BOOLEAN DEFAULT 0,
                exploit_maturity TEXT,
                publish_date TEXT,
                update_date TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS safe_versions (
                component TEXT NOT NULL,
                branch TEXT NOT NULL,
                latest_version TEXT NOT NULL,
                latest_safe_version TEXT NOT NULL,
                end_of_life BOOLEAN DEFAULT 0,
                release_date TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (component, branch)
            );
            
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technology TEXT NOT NULL,
                category TEXT NOT NULL,
                pattern TEXT NOT NULL,
                location TEXT DEFAULT 'header',
                version_extraction TEXT,
                confidence TEXT DEFAULT 'medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        self.conn.commit()
    
    def _create_indexes(self):
        """Create indexes for performance."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_vuln_category ON vulnerabilities(category)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_component ON vulnerabilities(component)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id)",
        ]
        for idx in indexes:
            try:
                self.cursor.execute(idx)
            except sqlite3.Error as e:
                logger.debug(f"Index creation note: {e}")
        self.conn.commit()
    
    def _check_and_seed(self):
        """Seed database if empty."""
        self.cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        count = self.cursor.fetchone()[0]
        if count == 0:
            self._seed_data()
    
    def _seed_data(self):
        """Insert initial vulnerability data."""
        vulns = [
            ("CVE-2024-4577", "php", "PHP", "PHP CGI Argument Injection",
             "Critical RCE in PHP CGI", "< 8.3.8", "8.3.8", "critical", 10.0,
             "CVE-2024-4577", "CWE-78", "https://nvd.nist.gov", 1, "high", "2024-06-09"),
            ("CVE-2024-1234", "wordpress_core", "WordPress Core", "WordPress XSS",
             "XSS in WordPress core", "< 6.5.3", "6.5.3", "high", 7.5,
             "CVE-2024-1234", "CWE-79", "https://wpscan.com", 1, "functional", "2024-03-15"),
            ("CVE-2024-5678", "wordpress_core", "WordPress Core", "WordPress SQLi",
             "SQL injection in WordPress", "< 6.5", "6.5", "critical", 9.8,
             "CVE-2024-5678", "CWE-89", "https://wpscan.com", 1, "high", "2024-04-01"),
            ("CVE-2024-9012", "wordpress_plugin", "Elementor", "Elementor RCE",
             "RCE in Elementor plugin", "< 3.19.0", "3.19.0", "critical", 10.0,
             "CVE-2024-9012", "CWE-94", "https://wordfence.com", 1, "high", "2024-02-10"),
            ("CVE-2024-3094", "php", "PHP", "PHP Buffer Overflow",
             "Buffer overflow in PHP mbstring", "< 8.1.27", "8.1.27", "high", 8.2,
             "CVE-2024-3094", "CWE-120", "https://php.net", 0, "", "2024-03-15"),
            ("CVE-2024-27316", "webserver", "Apache HTTP Server", "Apache HTTP/2 DoS",
             "DoS via HTTP/2 CONTINUATION frames", "< 2.4.59", "2.4.59", "high", 7.5,
             "CVE-2024-27316", "CWE-400", "https://httpd.apache.org", 1, "functional", "2024-04-04"),
            ("CVE-2024-24989", "webserver", "Nginx", "Nginx HTTP/3 Smuggling",
             "Request smuggling in HTTP/3", "< 1.26.0", "1.26.0", "high", 7.4,
             "CVE-2024-24989", "CWE-444", "https://nginx.org", 0, "", "2024-04-23"),
            ("CVE-2024-45678", "webserver", "LiteSpeed Web Server", "LiteSpeed RCE",
             "RCE via WebAdmin console", "< 6.3", "6.3", "critical", 9.8,
             "CVE-2024-45678", "CWE-78", "https://litespeedtech.com", 1, "high", "2024-03-10"),
            ("CVE-2024-67890", "control_panel", "cPanel", "cPanel API RCE",
             "RCE via cPanel API", "< 118.0", "118.0", "critical", 10.0,
             "CVE-2024-67890", "CWE-78", "https://cpanel.net", 1, "high", "2024-04-01"),
            ("CVE-2024-11111", "control_panel", "DirectAdmin", "DirectAdmin Auth Bypass",
             "Authentication bypass in DirectAdmin", "< 1.661", "1.661", "critical", 9.8,
             "CVE-2024-11111", "CWE-287", "https://directadmin.com", 1, "high", "2024-03-01"),
            ("CVE-2024-28000", "wordpress_plugin", "LiteSpeed Cache", "LiteSpeed Cache PrivEsc",
             "Privilege escalation in LSCache", "< 6.2", "6.2", "critical", 9.3,
             "CVE-2024-28000", "CWE-269", "https://wordfence.com", 1, "high", "2024-05-15"),
        ]
        
        for v in vulns:
            try:
                self.cursor.execute("""
                    INSERT OR REPLACE INTO vulnerabilities
                    (id, category, component, title, description, affected_versions,
                     fixed_version, severity, cvss_score, cve_id, cwe_id, refs,
                     exploit_available, exploit_maturity, publish_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, v)
            except sqlite3.Error as e:
                logger.warning(f"Error seeding vulnerability {v[0]}: {e}")
        
        safe_versions = [
            ("WordPress", "6.x", "6.5.3", "6.5.3", False, "2026-05-01"),
            ("PHP", "8.2.x", "8.2.20", "8.2.20", False, "2026-05-01"),
            ("PHP", "8.3.x", "8.3.8", "8.3.8", False, "2026-05-01"),
            ("Apache", "2.4.x", "2.4.62", "2.4.62", False, "2026-04-15"),
            ("Nginx", "1.26.x", "1.26.2", "1.26.2", False, "2026-04-20"),
        ]
        
        for sv in safe_versions:
            self.cursor.execute("""
                INSERT OR REPLACE INTO safe_versions 
                (component, branch, latest_version, latest_safe_version, end_of_life, release_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, sv)
        
        self.cursor.execute("""
            INSERT OR REPLACE INTO metadata (key, value) VALUES 
            ('db_version', '3.0.0'),
            ('last_seeded', ?)
        """, (datetime.now().isoformat(),))
        
        self.conn.commit()
        logger.info(f"Database seeded with {len(vulns)} vulnerabilities")
    
    def check_component(self, component, version, category=None):
        """Check a component version against vulnerabilities."""
        cache_key = f"{component}:{version}:{category}"
        if cache_key in self._query_cache:
            timestamp, data = self._query_cache[cache_key]
            if time.time() - timestamp < self.CACHE_TTL:
                return data
        
        query = "SELECT * FROM vulnerabilities WHERE component = ?"
        params = [component]
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        query += " ORDER BY cvss_score DESC"
        
        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()
        
        vulnerable = []
        for row in rows:
            vuln = dict(row)
            if self._is_version_affected(version, vuln['affected_versions']):
                vulnerable.append(vuln)

        # Evict oldest entries if cache exceeds 1000 items to prevent memory leaks
        if len(self._query_cache) >= 1000:
            oldest_key = min(self._query_cache.keys(), key=lambda k: self._query_cache[k][0])
            del self._query_cache[oldest_key]

        self._query_cache[cache_key] = (time.time(), vulnerable)
        return vulnerable
    
    def search_by_cve(self, cve_id):
        """Search by CVE ID."""
        self.cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id.upper(),))
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def get_latest_safe_version(self, component):
        """Get latest safe version for a component."""
        self.cursor.execute(
            "SELECT * FROM safe_versions WHERE component = ? ORDER BY release_date DESC LIMIT 1",
            (component,)
        )
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def get_statistics(self):
        """Get database statistics."""
        stats = {}
        self.cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['total'] = self.cursor.fetchone()[0]

        self.cursor.execute("SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity")
        stats['by_severity'] = {row['severity']: row['cnt'] for row in self.cursor.fetchall()}

        # Load metadata
        self.cursor.execute("SELECT key, value FROM metadata")
        stats['metadata'] = {row['key']: row['value'] for row in self.cursor.fetchall()}

        return stats

    def add_vulnerability(self, vuln_data: Dict) -> bool:
        """
        Add or update a vulnerability in the database.
        Accepts dict or object with to_dict / attributes.
        """
        try:
            if hasattr(vuln_data, 'to_dict'):
                data = vuln_data.to_dict()
            elif isinstance(vuln_data, dict):
                data = vuln_data
            else:
                data = getattr(vuln_data, '__dict__', {})

            self.cursor.execute("""
                INSERT OR REPLACE INTO vulnerabilities
                (id, category, component, title, description, affected_versions,
                 fixed_version, severity, cvss_score, cve_id, cwe_id, refs,
                 exploit_available, exploit_maturity, publish_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.get('id', data.get('cve_id', '')),
                data.get('category', 'unknown'),
                data.get('component', 'unknown'),
                data.get('title', 'Untitled'),
                data.get('description', ''),
                data.get('affected_versions', 'all'),
                data.get('fixed_version', ''),
                data.get('severity', 'info'),
                data.get('cvss_score', 0.0),
                data.get('cve_id', ''),
                data.get('cwe_id', ''),
                data.get('refs', data.get('references', '')),
                1 if data.get('exploit_available') else 0,
                data.get('exploit_maturity', 'unknown'),
                data.get('publish_date', '')
            ))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add vulnerability: {e}")
            return False

    def add_fingerprint(
        self,
        technology: str,
        category: str,
        pattern: str,
        location: str = 'header',
        version_extraction: Optional[str] = None,
        confidence: str = 'medium'
    ) -> bool:
        """Add technology fingerprint signature."""
        try:
            self.cursor.execute("""
                INSERT INTO fingerprints (technology, category, pattern, location, version_extraction, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (technology, category, pattern, location, version_extraction, confidence))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add fingerprint: {e}")
            return False
    
    def _is_version_affected(self, version, affected_range):
        """Check if version is in affected range."""
        if not version or not affected_range:
            return True
        
        if affected_range.lower() in ['all versions', 'all', '*']:
            return True
        
        try:
            current = pkg_version.parse(version)
            if not current.release:
                return True
            
            conditions = [c.strip() for c in affected_range.split(',')]
            
            for condition in conditions:
                match = re.match(r'(<=|<|>=|>)\s*([\d.]+)', condition)
                if match:
                    op, ver = match.groups()
                    target = pkg_version.parse(ver)
                    
                    if op == '<=' and current <= target:
                        return True
                    elif op == '<' and current < target:
                        return True
                    elif op == '>=' and current >= target:
                        return True
                    elif op == '>' and current > target:
                        return True
                    continue
                
                range_match = re.match(r'([\d.]+)\s*-\s*([\d.]+)', condition)
                if range_match:
                    min_ver = pkg_version.parse(range_match.group(1))
                    max_ver = pkg_version.parse(range_match.group(2))
                    if min_ver <= current <= max_ver:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"Version comparison error for {current_version} vs {affected_range}: {e}")
            return False
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()