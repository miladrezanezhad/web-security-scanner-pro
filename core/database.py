#!/usr/bin/env python3
"""
Vulnerability database management system.
Handles SQLite database operations for storing and querying vulnerabilities.

Features:
- SQLite database with optimized indexes
- Version comparison with semantic versioning
- Bulk import from JSON/API sources
- Automatic database seeding with latest CVEs
- Query caching for performance
- Database statistics and health checks
"""

import sqlite3
import os
import re
import json
import hashlib
import time
from typing import Dict, List, Optional, Tuple, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from packaging import version as pkg_version
from loguru import logger


@dataclass
class Vulnerability:
    """Vulnerability data model."""
    id: str
    category: str
    component: str
    title: str
    description: str
    affected_versions: str
    fixed_version: str
    severity: str
    cvss_score: float
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    references: Optional[str] = None
    exploit_available: bool = False
    exploit_maturity: Optional[str] = None
    publish_date: Optional[str] = None
    update_date: Optional[str] = None
    vendor: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'category': self.category,
            'component': self.component,
            'title': self.title,
            'description': self.description,
            'affected_versions': self.affected_versions,
            'fixed_version': self.fixed_version,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'references': self.references,
            'exploit_available': self.exploit_available,
            'exploit_maturity': self.exploit_maturity,
            'publish_date': self.publish_date,
            'vendor': self.vendor,
        }


@dataclass
class SafeVersion:
    """Safe version information for a component."""
    component: str
    branch: str
    latest_version: str
    latest_safe_version: str
    end_of_life: bool = False
    release_date: Optional[str] = None


class VulnerabilityDatabase:
    """
    Vulnerability database manager.
    
    Handles storage, retrieval, and querying of security vulnerabilities.
    Uses SQLite for portability and performance.
    """
    
    # Database schema version
    SCHEMA_VERSION = "3.0.0"
    
    # Cache TTL in seconds (1 hour)
    CACHE_TTL = 3600
    
    def __init__(self, db_path: str = "database/vulnerabilities.db"):
        """
        Initialize the vulnerability database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._query_cache: Dict[str, Tuple[float, Any]] = {}
        
        # Create directory if needed
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._connect()
        self._create_tables()
        self._create_indexes()
        self._check_and_seed()
        
        logger.info(f"Database initialized: {db_path}")
        logger.info(f"Schema version: {self.SCHEMA_VERSION}")
    
    def _connect(self):
        """Establish database connection."""
        self.conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-20000")  # 20MB cache
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.cursor = self.conn.cursor()
    
    def _create_tables(self):
        """Create database tables if they don't exist."""
        self.cursor.executescript("""
            -- Main vulnerabilities table
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                component TEXT NOT NULL,
                vendor TEXT,
                title TEXT NOT NULL,
                description TEXT,
                affected_versions TEXT NOT NULL,
                fixed_version TEXT,
                severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
                cvss_score REAL DEFAULT 0.0,
                cve_id TEXT,
                cwe_id TEXT,
                references TEXT,
                exploit_available BOOLEAN DEFAULT 0,
                exploit_maturity TEXT,
                publish_date TEXT,
                update_date TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Safe versions table
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
            
            -- Technology fingerprints table
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
            
            -- Scan history table
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                modules_run TEXT,
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                scan_duration REAL,
                scan_mode TEXT
            );
            
            -- Metadata table
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Trigger to update timestamps
            CREATE TRIGGER IF NOT EXISTS update_vulnerabilities_timestamp 
            AFTER UPDATE ON vulnerabilities
            BEGIN
                UPDATE vulnerabilities SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;
        """)
        
        self.conn.commit()
    
    def _create_indexes(self):
        """Create optimized indexes for common queries."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_vuln_category ON vulnerabilities(category)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_component ON vulnerabilities(component)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_cvss ON vulnerabilities(cvss_score DESC)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_exploit ON vulnerabilities(exploit_available)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_publish_date ON vulnerabilities(publish_date)",
            "CREATE INDEX IF NOT EXISTS idx_fingerprints_tech ON fingerprints(technology)",
            "CREATE INDEX IF NOT EXISTS idx_fingerprints_category ON fingerprints(category)",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_url ON scan_history(target_url)",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_time ON scan_history(scan_time)",
        ]
        
        for index_sql in indexes:
            try:
                self.cursor.execute(index_sql)
            except sqlite3.OperationalError as e:
                logger.warning(f"Index creation warning: {e}")
        
        self.conn.commit()
    
    def _check_and_seed(self):
        """Check if database needs seeding and seed if empty."""
        self.cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        count = self.cursor.fetchone()[0]
        
        if count == 0:
            logger.info("Empty database detected. Seeding with initial data...")
            self._seed_database()
        else:
            logger.info(f"Database contains {count} vulnerabilities")
    
    def _seed_database(self):
        """Seed database with comprehensive vulnerability data."""
        from database.vulnerabilities_2024 import VULNERABILITIES_2024
        from database.vulnerabilities_2025 import VULNERABILITIES_2025
        from database.vulnerabilities_2026 import VULNERABILITIES_2026
        
        all_vulns = {}
        
        # Merge all vulnerability databases
        for vuln_db in [VULNERABILITIES_2024, VULNERABILITIES_2025, VULNERABILITIES_2026]:
            for category, vulns in vuln_db.items():
                if category not in all_vulns:
                    all_vulns[category] = []
                all_vulns[category].extend(vulns)
        
        total_count = 0
        
        for category, vulns in all_vulns.items():
            for vuln in vulns:
                try:
                    self.cursor.execute("""
                        INSERT OR REPLACE INTO vulnerabilities 
                        (id, category, component, vendor, title, description, 
                         affected_versions, fixed_version, severity, cvss_score, 
                         cve_id, cwe_id, references, exploit_available, 
                         exploit_maturity, publish_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        vuln.get('id'),
                        vuln.get('category'),
                        vuln.get('component'),
                        vuln.get('vendor'),
                        vuln.get('title'),
                        vuln.get('description'),
                        vuln.get('affected_versions'),
                        vuln.get('fixed_version'),
                        vuln.get('severity'),
                        vuln.get('cvss_score', 0.0),
                        vuln.get('cve_id'),
                        vuln.get('cwe_id'),
                        vuln.get('references'),
                        vuln.get('exploit_available', False),
                        vuln.get('exploit_maturity'),
                        vuln.get('publish_date')
                    ))
                    total_count += 1
                except sqlite3.Error as e:
                    logger.error(f"Error inserting vulnerability {vuln.get('id')}: {e}")
        
        # Seed safe versions
        safe_versions = [
            ("WordPress", "6.x", "6.5.3", "6.5.3", False, "2026-05-01"),
            ("PHP", "8.2.x", "8.2.20", "8.2.20", False, "2026-05-01"),
            ("PHP", "8.3.x", "8.3.8", "8.3.8", False, "2026-05-01"),
            ("Apache", "2.4.x", "2.4.62", "2.4.62", False, "2026-04-15"),
            ("Nginx", "1.26.x", "1.26.2", "1.26.2", False, "2026-04-20"),
            ("MySQL", "8.0.x", "8.0.37", "8.0.37", False, "2026-04-10"),
            ("PostgreSQL", "16.x", "16.3", "16.3", False, "2026-05-01"),
            ("Redis", "7.2.x", "7.2.5", "7.2.5", False, "2026-04-01"),
            ("cPanel", "122.x", "122.0.15", "122.0.15", False, "2026-05-01"),
            ("LiteSpeed", "6.x", "6.4.2", "6.4.2", False, "2026-03-15"),
        ]
        
        for sv in safe_versions:
            self.cursor.execute("""
                INSERT OR REPLACE INTO safe_versions 
                (component, branch, latest_version, latest_safe_version, end_of_life, release_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, sv)
        
        # Set metadata
        self.cursor.execute("""
            INSERT OR REPLACE INTO metadata (key, value) VALUES 
            ('db_version', ?),
            ('schema_version', ?),
            ('last_seeded', ?),
            ('total_vulnerabilities', ?),
            ('vulnerability_coverage', '2024-2026')
        """, (
            '3.0.0',
            self.SCHEMA_VERSION,
            datetime.now().isoformat(),
            str(total_count)
        ))
        
        self.conn.commit()
        logger.info(f"Database seeded with {total_count} vulnerabilities")
    
    def add_vulnerability(self, vuln: Vulnerability) -> bool:
        """
        Add a single vulnerability to the database.
        
        Args:
            vuln: Vulnerability object
        
        Returns:
            True if successful
        """
        try:
            self.cursor.execute("""
                INSERT OR REPLACE INTO vulnerabilities 
                (id, category, component, vendor, title, description, 
                 affected_versions, fixed_version, severity, cvss_score, 
                 cve_id, cwe_id, references, exploit_available, 
                 exploit_maturity, publish_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln.id, vuln.category, vuln.component, vuln.vendor,
                vuln.title, vuln.description, vuln.affected_versions,
                vuln.fixed_version, vuln.severity, vuln.cvss_score,
                vuln.cve_id, vuln.cwe_id, vuln.references,
                vuln.exploit_available, vuln.exploit_maturity, vuln.publish_date
            ))
            self.conn.commit()
            
            # Invalidate cache
            self._query_cache = {}
            
            logger.debug(f"Added vulnerability: {vuln.id}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to add vulnerability {vuln.id}: {e}")
            return False
    
    def get_vulnerability(self, vuln_id: str) -> Optional[Dict]:
        """
        Get a vulnerability by ID.
        
        Args:
            vuln_id: Vulnerability ID (e.g., CVE-2026-xxxxx)
        
        Returns:
            Dict with vulnerability details or None
        """
        self.cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def check_component_version(
        self, 
        component: str, 
        version: str, 
        category: Optional[str] = None
    ) -> List[Dict]:
        """
        Check a component version against known vulnerabilities.
        
        Args:
            component: Component name (e.g., 'WordPress', 'PHP', 'Apache')
            version: Version string to check (e.g., '6.4.2')
            category: Optional category filter
        
        Returns:
            List of matching vulnerabilities sorted by CVSS score
        """
        # Check cache first
        cache_key = f"check:{component}:{version}:{category}"
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached
        
        # Build query
        query = "SELECT * FROM vulnerabilities WHERE component = ?"
        params = [component]
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        query += " ORDER BY cvss_score DESC"
        
        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()
        
        # Filter by version
        vulnerable = []
        for row in rows:
            vuln_dict = dict(row)
            if self._is_version_affected(version, vuln_dict['affected_versions']):
                vulnerable.append(vuln_dict)
        
        # Cache results
        self._add_to_cache(cache_key, vulnerable)
        
        return vulnerable
    
    def search_by_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Search for a vulnerability by CVE ID.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2026-1234')
        
        Returns:
            Vulnerability dict or None
        """
        self.cursor.execute(
            "SELECT * FROM vulnerabilities WHERE cve_id = ?", 
            (cve_id.upper(),)
        )
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def get_vulnerabilities_by_severity(
        self, 
        severity: str, 
        limit: int = 100
    ) -> List[Dict]:
        """
        Get vulnerabilities filtered by severity.
        
        Args:
            severity: Severity level (critical, high, medium, low)
            limit: Maximum number of results
        
        Returns:
            List of vulnerability dicts
        """
        self.cursor.execute("""
            SELECT * FROM vulnerabilities 
            WHERE severity = ? 
            ORDER BY cvss_score DESC 
            LIMIT ?
        """, (severity, limit))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_exploitable_vulnerabilities(self, limit: int = 100) -> List[Dict]:
        """
        Get vulnerabilities with known exploits.
        
        Args:
            limit: Maximum number of results
        
        Returns:
            List of vulnerability dicts with exploits available
        """
        self.cursor.execute("""
            SELECT * FROM vulnerabilities 
            WHERE exploit_available = 1 
            ORDER BY cvss_score DESC 
            LIMIT ?
        """, (limit,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_recent_vulnerabilities(self, days: int = 30) -> List[Dict]:
        """
        Get vulnerabilities published in the last N days.
        
        Args:
            days: Number of days to look back
        
        Returns:
            List of recent vulnerability dicts
        """
        cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        
        self.cursor.execute("""
            SELECT * FROM vulnerabilities 
            WHERE publish_date >= ? 
            ORDER BY publish_date DESC
        """, (cutoff_date,))
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_safe_version(self, component: str) -> Optional[Dict]:
        """
        Get the latest safe version for a component.
        
        Args:
            component: Component name
        
        Returns:
            Dict with safe version info or None
        """
        self.cursor.execute("""
            SELECT * FROM safe_versions 
            WHERE component = ? 
            ORDER BY release_date DESC 
            LIMIT 1
        """, (component,))
        
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def get_all_safe_versions(self) -> List[Dict]:
        """Get all safe version recommendations."""
        self.cursor.execute("""
            SELECT * FROM safe_versions 
            ORDER BY component, branch
        """)
        return [dict(row) for row in self.cursor.fetchall()]
    
    def add_fingerprint(
        self, 
        technology: str, 
        category: str, 
        pattern: str, 
        location: str = 'header',
        version_extraction: Optional[str] = None,
        confidence: str = 'medium'
    ):
        """Add a technology fingerprint."""
        self.cursor.execute("""
            INSERT OR REPLACE INTO fingerprints 
            (technology, category, pattern, location, version_extraction, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (technology, category, pattern, location, version_extraction, confidence))
        self.conn.commit()
    
    def get_fingerprints(self, category: Optional[str] = None) -> List[Dict]:
        """Get technology fingerprints."""
        if category:
            self.cursor.execute(
                "SELECT * FROM fingerprints WHERE category = ?", 
                (category,)
            )
        else:
            self.cursor.execute("SELECT * FROM fingerprints")
        
        return [dict(row) for row in self.cursor.fetchall()]
    
    def save_scan_result(self, scan_data: Dict):
        """Save scan results to history."""
        self.cursor.execute("""
            INSERT INTO scan_history 
            (target_url, scan_time, modules_run, findings_count, 
             critical_count, high_count, medium_count, low_count,
             scan_duration, scan_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data.get('target_url'),
            scan_data.get('scan_time', datetime.now().isoformat()),
            json.dumps(scan_data.get('modules_run', [])),
            scan_data.get('total_findings', 0),
            scan_data.get('critical_count', 0),
            scan_data.get('high_count', 0),
            scan_data.get('medium_count', 0),
            scan_data.get('low_count', 0),
            scan_data.get('scan_duration'),
            scan_data.get('scan_mode', 'normal')
        ))
        self.conn.commit()
    
    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        """Get recent scan history."""
        self.cursor.execute("""
            SELECT * FROM scan_history 
            ORDER BY scan_time DESC 
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def _is_version_affected(self, version: str, affected_range: str) -> bool:
        """
        Check if a version falls within an affected version range.
        
        Supports formats:
        - '< 1.2.3'
        - '<= 1.2.3'
        - '>= 1.0, < 2.0'
        - '1.0 - 2.0'
        - 'All versions'
        
        Args:
            version: Version string to check
            affected_range: Version range specification
        
        Returns:
            True if version is affected
        """
        if not version or not affected_range:
            return True  # If we can't determine, assume vulnerable
        
        # Handle 'All versions'
        if affected_range.lower() in ['all versions', 'all', '*']:
            return True
        
        try:
            current = pkg_version.parse(version)
            
            # If version can't be parsed, assume vulnerable
            if not current.release:
                return True
            
            # Parse conditions
            conditions = [c.strip() for c in affected_range.split(',')]
            
            for condition in conditions:
                # Match operators: <, <=, >=, >
                match = re.match(r'(<=|<|>=|>)\s*([\d.]+)', condition)
                if match:
                    operator, ver = match.groups()
                    target = pkg_version.parse(ver)
                    
                    if operator == '<=' and current <= target:
                        return True
                    elif operator == '<' and current < target:
                        return True
                    elif operator == '>=' and current >= target:
                        return True
                    elif operator == '>' and current > target:
                        return True
                    continue
                
                # Match range: X - Y
                range_match = re.match(r'([\d.]+)\s*-\s*([\d.]+)', condition)
                if range_match:
                    min_ver = pkg_version.parse(range_match.group(1))
                    max_ver = pkg_version.parse(range_match.group(2))
                    if min_ver <= current <= max_ver:
                        return True
                    continue
            
            return False
            
        except Exception as e:
            logger.warning(f"Version comparison error: {version} vs {affected_range} - {e}")
            return True  # Assume vulnerable on error
    
    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get item from query cache if not expired."""
        if key in self._query_cache:
            timestamp, data = self._query_cache[key]
            if time.time() - timestamp < self.CACHE_TTL:
                return data
            del self._query_cache[key]
        return None
    
    def _add_to_cache(self, key: str, data: Any):
        """Add item to query cache."""
        # Limit cache size
        if len(self._query_cache) > 1000:
            # Remove oldest 10%
            sorted_keys = sorted(
                self._query_cache.keys(),
                key=lambda k: self._query_cache[k][0]
            )
            for old_key in sorted_keys[:100]:
                del self._query_cache[old_key]
        
        self._query_cache[key] = (time.time(), data)
    
    def get_statistics(self) -> Dict:
        """Get comprehensive database statistics."""
        stats = {}
        
        # Total vulnerabilities
        self.cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['total_vulnerabilities'] = self.cursor.fetchone()[0]
        
        # By severity
        self.cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY severity 
            ORDER BY count DESC
        """)
        stats['by_severity'] = {row['severity']: row['count'] for row in self.cursor.fetchall()}
        
        # By category
        self.cursor.execute("""
            SELECT category, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY category 
            ORDER BY count DESC
        """)
        stats['by_category'] = {row['category']: row['count'] for row in self.cursor.fetchall()}
        
        # Exploitable count
        self.cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE exploit_available = 1")
        stats['exploitable'] = self.cursor.fetchone()[0]
        
        # Latest CVE
        self.cursor.execute("""
            SELECT cve_id, publish_date 
            FROM vulnerabilities 
            WHERE cve_id IS NOT NULL 
            ORDER BY publish_date DESC 
            LIMIT 1
        """)
        latest = self.cursor.fetchone()
        stats['latest_cve'] = dict(latest) if latest else None
        
        # Safe versions count
        self.cursor.execute("SELECT COUNT(*) FROM safe_versions")
        stats['safe_versions_count'] = self.cursor.fetchone()[0]
        
        # Fingerprints count
        self.cursor.execute("SELECT COUNT(*) FROM fingerprints")
        stats['fingerprints_count'] = self.cursor.fetchone()[0]
        
        # Scan history count
        self.cursor.execute("SELECT COUNT(*) FROM scan_history")
        stats['total_scans'] = self.cursor.fetchone()[0]
        
        # Database size
        stats['database_size'] = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        
        # Metadata
        self.cursor.execute("SELECT * FROM metadata")
        stats['metadata'] = {row['key']: row['value'] for row in self.cursor.fetchall()}
        
        return stats
    
    def bulk_import(self, vulnerabilities: List[Dict]) -> int:
        """
        Bulk import vulnerabilities from a list of dicts.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        
        Returns:
            Number of vulnerabilities imported
        """
        count = 0
        self.cursor.execute("BEGIN TRANSACTION")
        
        try:
            for vuln in vulnerabilities:
                self.cursor.execute("""
                    INSERT OR REPLACE INTO vulnerabilities 
                    (id, category, component, vendor, title, description, 
                     affected_versions, fixed_version, severity, cvss_score, 
                     cve_id, cwe_id, references, exploit_available, 
                     exploit_maturity, publish_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vuln.get('id'),
                    vuln.get('category'),
                    vuln.get('component'),
                    vuln.get('vendor'),
                    vuln.get('title'),
                    vuln.get('description'),
                    vuln.get('affected_versions'),
                    vuln.get('fixed_version'),
                    vuln.get('severity'),
                    vuln.get('cvss_score', 0.0),
                    vuln.get('cve_id'),
                    vuln.get('cwe_id'),
                    vuln.get('references'),
                    vuln.get('exploit_available', False),
                    vuln.get('exploit_maturity'),
                    vuln.get('publish_date')
                ))
                count += 1
            
            self.conn.commit()
            logger.info(f"Bulk imported {count} vulnerabilities")
        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Bulk import failed: {e}")
            return 0
        
        # Invalidate cache
        self._query_cache = {}
        
        return count
    
    def export_to_json(self, output_path: str) -> bool:
        """
        Export entire database to JSON file.
        
        Args:
            output_path: Path for output JSON file
        
        Returns:
            True if successful
        """
        try:
            self.cursor.execute("SELECT * FROM vulnerabilities")
            vulnerabilities = [dict(row) for row in self.cursor.fetchall()]
            
            self.cursor.execute("SELECT * FROM safe_versions")
            safe_versions = [dict(row) for row in self.cursor.fetchall()]
            
            export_data = {
                'export_date': datetime.now().isoformat(),
                'schema_version': self.SCHEMA_VERSION,
                'statistics': self.get_statistics(),
                'vulnerabilities': vulnerabilities,
                'safe_versions': safe_versions
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Database exported to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False
    
    def vacuum(self):
        """Optimize database by running VACUUM."""
        logger.info("Running database VACUUM...")
        self.cursor.execute("VACUUM")
        self.conn.commit()
        logger.info("VACUUM complete")
    
    def close(self):
        """Close database connection safely."""
        if self.conn:
            self.conn.commit()
            self.conn.close()
            logger.info("Database connection closed")


# Module-level convenience functions
_default_db = None


def get_default_db(db_path: str = "database/vulnerabilities.db") -> VulnerabilityDatabase:
    """Get or create the default database instance."""
    global _default_db
    if _default_db is None:
        _default_db = VulnerabilityDatabase(db_path)
    return _default_db