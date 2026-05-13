#!/usr/bin/env python3
"""
Database and signature update manager.
Handles automatic updates of vulnerability database and technology signatures.

Features:
- Automatic vulnerability database updates
- Technology fingerprint updates
- NVD API integration (with API key)
- WPScan API integration
- Scheduled updates
- Version tracking
- Rollback capability
"""

import os
import json
import time
import hashlib
import requests
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from loguru import logger

from core.database import VulnerabilityDatabase


class DatabaseUpdater:
    """
    Update manager for vulnerability database and signatures.
    Supports multiple data sources and automatic scheduling.
    """
    
    # Default update sources
    UPDATE_SOURCES = {
        'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        'wpscan': 'https://wpscan.com/api/v3',
        'github_advisories': 'https://api.github.com/advisories',
        'local': 'database/',
    }
    
    def __init__(self, config: Dict):
        """
        Initialize the updater.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.db_config = config.get('database', {})
        self.db_path = self.db_config.get('path', 'database/vulnerabilities.db')
        self.db = VulnerabilityDatabase(self.db_path)
        
        # API keys
        self.nvd_api_key = self.db_config.get('nvd_api_key', '')
        self.wpscan_api_key = self.db_config.get('wpscan_api_key', '')
        
        # Update tracking
        self.update_history: List[Dict] = []
        self.last_update: Optional[datetime] = None
        
        # Load update history
        self._load_history()
        
        logger.info("Database updater initialized")
    
    def _load_history(self):
        """Load update history from metadata."""
        stats = self.db.get_statistics()
        metadata = stats.get('metadata', {})
        
        last_update_str = metadata.get('last_update')
        if last_update_str:
            try:
                self.last_update = datetime.fromisoformat(last_update_str)
            except ValueError:
                self.last_update = None
    
    def _save_history(self):
        """Save update history to database."""
        self.db.cursor.execute("""
            INSERT OR REPLACE INTO metadata (key, value) VALUES 
            ('last_update', ?),
            ('last_update_source', ?),
            ('update_count', ?)
        """, (
            datetime.now().isoformat(),
            self.update_history[-1].get('source', 'unknown') if self.update_history else 'unknown',
            str(len(self.update_history))
        ))
        self.db.conn.commit()
    
    def update_vulnerability_database(self) -> int:
        """
        Update vulnerability database from all configured sources.
        
        Returns:
            Number of vulnerabilities added/updated
        """
        total_count = 0
        
        logger.info("Starting vulnerability database update...")
        
        # Update from NVD
        if self.nvd_api_key:
            try:
                count = self._update_from_nvd()
                total_count += count
                logger.info(f"NVD update: {count} vulnerabilities")
            except Exception as e:
                logger.error(f"NVD update failed: {e}")
        else:
            logger.warning("NVD API key not configured. Skipping NVD updates.")
        
        # Update from WPScan
        if self.wpscan_api_key:
            try:
                count = self._update_from_wpscan()
                total_count += count
                logger.info(f"WPScan update: {count} vulnerabilities")
            except Exception as e:
                logger.error(f"WPScan update failed: {e}")
        
        # Update from local files
        try:
            count = self._update_from_local()
            total_count += count
            logger.info(f"Local update: {count} vulnerabilities")
        except Exception as e:
            logger.error(f"Local update failed: {e}")
        
        # Save update history
        self.update_history.append({
            'timestamp': datetime.now().isoformat(),
            'source': 'combined',
            'count': total_count
        })
        self._save_history()
        
        logger.info(f"Database update complete. Total: {total_count} vulnerabilities")
        return total_count
    
    def _update_from_nvd(self) -> int:
        """
        Update vulnerabilities from NVD API.
        
        Returns:
            Number of vulnerabilities added
        """
        count = 0
        
        # Calculate date range (last 30 days or since last update)
        if self.last_update:
            start_date = self.last_update.strftime('%Y-%m-%dT%H:%M:%S.000')
        else:
            start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S.000')
        
        end_date = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
        
        headers = {
            'apiKey': self.nvd_api_key,
            'User-Agent': 'WebSecurityAnalyzerPro/3.0'
        }
        
        params = {
            'pubStartDate': start_date,
            'pubEndDate': end_date,
            'resultsPerPage': 100,
        }
        
        try:
            response = requests.get(
                self.UPDATE_SOURCES['nvd'],
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                for item in vulnerabilities:
                    cve = item.get('cve', {})
                    
                    # Extract CVSS score
                    cvss_score = 0.0
                    metrics = cve.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in metrics:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    
                    # Map severity
                    severity = self._cvss_to_severity(cvss_score)
                    
                    # Extract affected versions
                    affected_versions = 'Unknown'
                    configurations = cve.get('configurations', [])
                    if configurations:
                        # Simplified version extraction
                        for config in configurations:
                            nodes = config.get('nodes', [])
                            for node in nodes:
                                cpe_matches = node.get('cpeMatch', [])
                                for match in cpe_matches:
                                    version_start = match.get('versionStartIncluding', '')
                                    version_end = match.get('versionEndExcluding', '')
                                    if version_start and version_end:
                                        affected_versions = f">= {version_start}, < {version_end}"
                                        break
                    
                    # Build references string
                    references_list = []
                    for ref in cve.get('references', []):
                        references_list.append(ref.get('url', ''))
                    
                    # Create vulnerability entry
                    cve_id = cve.get('id', '')
                    vuln_data = {
                        'id': cve_id,
                        'category': self._determine_category(cve),
                        'component': self._extract_component(cve),
                        'vendor': self._extract_vendor(cve),
                        'title': self._extract_title(cve),
                        'description': self._extract_description(cve),
                        'affected_versions': affected_versions,
                        'fixed_version': self._extract_fixed_version(cve),
                        'severity': severity,
                        'cvss_score': cvss_score,
                        'cve_id': cve_id,
                        'cwe_id': self._extract_cwe(cve),
                        'references': ', '.join(references_list[:5]),
                        'exploit_available': self._check_exploit_available(cve),
                        'exploit_maturity': 'unknown',
                        'publish_date': cve.get('published', '')[:10],
                    }
                    
                    # Add to database
                    from core.database import Vulnerability
                    vuln = Vulnerability(**vuln_data)
                    if self.db.add_vulnerability(vuln):
                        count += 1
                
                logger.info(f"Processed {len(vulnerabilities)} CVEs from NVD, added {count}")
            
            elif response.status_code == 403:
                logger.warning("NVD API rate limit exceeded. Try again later.")
            else:
                logger.error(f"NVD API error: {response.status_code}")
        
        except requests.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
        
        return count
    
    def _update_from_wpscan(self) -> int:
        """
        Update WordPress vulnerabilities from WPScan API.
        
        Returns:
            Number of vulnerabilities added
        """
        count = 0
        
        headers = {
            'Authorization': f'Token token={self.wpscan_api_key}',
            'User-Agent': 'WebSecurityAnalyzerPro/3.0'
        }
        
        try:
            # Get WordPress core vulnerabilities
            response = requests.get(
                f"{self.UPDATE_SOURCES['wpscan']}/core/vulnerabilities",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get('data', []):
                    vuln_data = {
                        'id': f"WPS-{item.get('id', '')}",
                        'category': 'wordpress_core',
                        'component': 'WordPress Core',
                        'vendor': 'WordPress',
                        'title': item.get('title', 'WordPress Vulnerability'),
                        'description': item.get('description', ''),
                        'affected_versions': item.get('affected_versions', ''),
                        'fixed_version': item.get('fixed_in', ''),
                        'severity': self._cvss_to_severity(
                            item.get('cvss', {}).get('score', 0)
                        ),
                        'cvss_score': item.get('cvss', {}).get('score', 0),
                        'cve_id': item.get('cve', ''),
                        'references': ', '.join(item.get('references', [])),
                        'exploit_available': item.get('exploit_available', False),
                        'publish_date': item.get('published_date', ''),
                    }
                    
                    from core.database import Vulnerability
                    vuln = Vulnerability(**vuln_data)
                    if self.db.add_vulnerability(vuln):
                        count += 1
            
            # Get plugin vulnerabilities
            response = requests.get(
                f"{self.UPDATE_SOURCES['wpscan']}/plugins/vulnerabilities",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get('data', []):
                    vuln_data = {
                        'id': f"WPS-PLUGIN-{item.get('id', '')}",
                        'category': 'wordpress_plugin',
                        'component': item.get('plugin_name', 'Unknown Plugin'),
                        'vendor': item.get('plugin_author', 'Unknown'),
                        'title': item.get('title', 'WordPress Plugin Vulnerability'),
                        'description': item.get('description', ''),
                        'affected_versions': item.get('affected_versions', ''),
                        'fixed_version': item.get('fixed_in', ''),
                        'severity': self._cvss_to_severity(
                            item.get('cvss', {}).get('score', 0)
                        ),
                        'cvss_score': item.get('cvss', {}).get('score', 0),
                        'cve_id': item.get('cve', ''),
                        'references': ', '.join(item.get('references', [])),
                        'exploit_available': item.get('exploit_available', False),
                        'publish_date': item.get('published_date', ''),
                    }
                    
                    from core.database import Vulnerability
                    vuln = Vulnerability(**vuln_data)
                    if self.db.add_vulnerability(vuln):
                        count += 1
            
            logger.info(f"Processed WPScan data, added {count} vulnerabilities")
            
        except requests.RequestException as e:
            logger.error(f"WPScan API request failed: {e}")
        
        return count
    
    def _update_from_local(self) -> int:
        """
        Update vulnerabilities from local JSON/YAML files.
        
        Returns:
            Number of vulnerabilities added
        """
        count = 0
        
        # Check for local update files
        local_dir = Path(self.UPDATE_SOURCES['local'])
        if not local_dir.exists():
            return 0
        
        # Look for vulnerability JSON files
        for file_path in local_dir.glob('vulnerabilities_*.py'):
            try:
                # Import the module dynamically
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    file_path.stem, file_path
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Get vulnerabilities dict
                vuln_dict = getattr(module, 'VULNERABILITIES', None)
                if vuln_dict:
                    for category, vulns in vuln_dict.items():
                        for vuln in vulns:
                            from core.database import Vulnerability
                            try:
                                vuln_obj = Vulnerability(**vuln)
                                if self.db.add_vulnerability(vuln_obj):
                                    count += 1
                            except Exception as e:
                                logger.warning(f"Failed to add vulnerability: {e}")
                
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
        
        return count
    
    def update_signatures(self) -> int:
        """
        Update technology fingerprints/signatures.
        
        Returns:
            Number of signatures updated
        """
        count = 0
        
        # Default fingerprints for common technologies
        default_fingerprints = {
            'webserver': [
                {
                    'technology': 'Apache',
                    'category': 'webserver',
                    'pattern': 'Apache',
                    'location': 'header',
                    'version_extraction': r'Apache/([\d.]+)',
                    'confidence': 'high'
                },
                {
                    'technology': 'Nginx',
                    'category': 'webserver',
                    'pattern': 'nginx',
                    'location': 'header',
                    'version_extraction': r'nginx/([\d.]+)',
                    'confidence': 'high'
                },
                {
                    'technology': 'LiteSpeed',
                    'category': 'webserver',
                    'pattern': 'LiteSpeed',
                    'location': 'header',
                    'version_extraction': r'LiteSpeed/([\d.]+)',
                    'confidence': 'high'
                },
                {
                    'technology': 'IIS',
                    'category': 'webserver',
                    'pattern': 'Microsoft-IIS',
                    'location': 'header',
                    'version_extraction': r'Microsoft-IIS/([\d.]+)',
                    'confidence': 'high'
                },
                {
                    'technology': 'Cloudflare',
                    'category': 'cdn',
                    'pattern': 'cloudflare',
                    'location': 'header',
                    'confidence': 'high'
                },
            ],
            'cms': [
                {
                    'technology': 'WordPress',
                    'category': 'cms',
                    'pattern': 'wp-content',
                    'location': 'body',
                    'version_extraction': r'WordPress ([\d.]+)',
                    'confidence': 'high'
                },
                {
                    'technology': 'Joomla',
                    'category': 'cms',
                    'pattern': 'joomla',
                    'location': 'body',
                    'confidence': 'medium'
                },
                {
                    'technology': 'Drupal',
                    'category': 'cms',
                    'pattern': 'drupal',
                    'location': 'body',
                    'confidence': 'medium'
                },
            ],
            'language': [
                {
                    'technology': 'PHP',
                    'category': 'language',
                    'pattern': 'X-Powered-By: PHP',
                    'location': 'header',
                    'version_extraction': r'PHP/([\d.]+)',
                    'confidence': 'high'
                },
                {
                    'technology': 'Python',
                    'category': 'language',
                    'pattern': 'python',
                    'location': 'header',
                    'confidence': 'low'
                },
            ],
            'javascript': [
                {
                    'technology': 'jQuery',
                    'category': 'javascript',
                    'pattern': 'jquery',
                    'location': 'body',
                    'version_extraction': r'jQuery v([\d.]+)',
                    'confidence': 'high'
                },
                {
                    'technology': 'React',
                    'category': 'javascript',
                    'pattern': 'react',
                    'location': 'body',
                    'confidence': 'medium'
                },
                {
                    'technology': 'Vue.js',
                    'category': 'javascript',
                    'pattern': 'vue',
                    'location': 'body',
                    'confidence': 'medium'
                },
                {
                    'technology': 'Angular',
                    'category': 'javascript',
                    'pattern': 'ng-version',
                    'location': 'body',
                    'confidence': 'high'
                },
            ],
        }
        
        for category, fingerprints in default_fingerprints.items():
            for fp in fingerprints:
                self.db.add_fingerprint(
                    technology=fp['technology'],
                    category=fp['category'],
                    pattern=fp['pattern'],
                    location=fp.get('location', 'header'),
                    version_extraction=fp.get('version_extraction'),
                    confidence=fp.get('confidence', 'medium')
                )
                count += 1
        
        self._save_history()
        
        logger.info(f"Updated {count} technology signatures")
        return count
    
    def check_for_updates(self) -> bool:
        """
        Check if updates are available.
        
        Returns:
            True if updates are needed
        """
        if not self.last_update:
            return True
        
        update_interval = self.db_config.get('update_interval', 86400)  # 24 hours
        elapsed = (datetime.now() - self.last_update).total_seconds()
        
        return elapsed > update_interval
    
    def auto_update_if_needed(self) -> int:
        """
        Automatically update if needed based on configured interval.
        
        Returns:
            Number of items updated, or 0 if no update needed
        """
        if self.check_for_updates():
            logger.info("Updates available. Starting automatic update...")
            return self.update_vulnerability_database()
        
        logger.info("Database is up to date")
        return 0
    
    def rollback(self, backup_path: str) -> bool:
        """
        Rollback database to a previous backup.
        
        Args:
            backup_path: Path to backup file
        
        Returns:
            True if rollback successful
        """
        try:
            import shutil
            
            # Create backup of current database
            current_backup = f"{self.db_path}.backup.{int(time.time())}"
            shutil.copy2(self.db_path, current_backup)
            
            # Restore from backup
            shutil.copy2(backup_path, self.db_path)
            
            # Reinitialize database connection
            self.db.close()
            self.db = VulnerabilityDatabase(self.db_path)
            
            logger.info(f"Database rolled back from {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    # Helper methods
    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity string."""
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        elif score > 0:
            return 'low'
        return 'info'
    
    def _determine_category(self, cve: Dict) -> str:
        """Determine vulnerability category from CVE data."""
        descriptions = cve.get('descriptions', [])
        desc_text = ' '.join([d.get('value', '') for d in descriptions]).lower()
        
        if any(word in desc_text for word in ['wordpress', 'wp-', 'plugin']):
            return 'wordpress_plugin'
        if any(word in desc_text for word in ['apache', 'nginx', 'iis', 'litespeed']):
            return 'webserver'
        if any(word in desc_text for word in ['php', 'python', 'ruby', 'java']):
            return 'language'
        if any(word in desc_text for word in ['mysql', 'postgresql', 'redis', 'mongodb']):
            return 'database'
        if any(word in desc_text for word in ['xss', 'cross-site scripting']):
            return 'xss'
        if any(word in desc_text for word in ['sql injection', 'sqli']):
            return 'sqli'
        
        return 'general'
    
    def _extract_component(self, cve: Dict) -> str:
        """Extract affected component name from CVE."""
        descriptions = cve.get('descriptions', [])
        desc_text = ' '.join([d.get('value', '') for d in descriptions])
        
        # Try to extract product name
        import re
        patterns = [
            r'in ([A-Za-z ]+) before',
            r'in ([A-Za-z ]+) through',
            r'([A-Za-z ]+) version',
            r'([A-Za-z ]+) ([0-9.]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, desc_text)
            if match:
                return match.group(1).strip()
        
        return 'Unknown'
    
    def _extract_vendor(self, cve: Dict) -> Optional[str]:
        """Extract vendor name from CVE."""
        configurations = cve.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for match in cpe_matches:
                    criteria = match.get('criteria', '')
                    # CPE format: cpe:2.3:a:vendor:product:version
                    parts = criteria.split(':')
                    if len(parts) >= 4:
                        return parts[3]
        return None
    
    def _extract_title(self, cve: Dict) -> str:
        """Extract title from CVE description."""
        descriptions = cve.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                # Truncate to reasonable length
                value = desc.get('value', '')
                return value[:200] + ('...' if len(value) > 200 else '')
        return 'No description available'
    
    def _extract_description(self, cve: Dict) -> str:
        """Extract full description from CVE."""
        descriptions = cve.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return 'No description available'
    
    def _extract_fixed_version(self, cve: Dict) -> Optional[str]:
        """Extract fixed version from CVE."""
        references = cve.get('references', [])
        for ref in references:
            tags = ref.get('tags', [])
            if 'Patch' in tags or 'Vendor Advisory' in tags:
                # Could parse more details from the advisory
                return 'See advisory'
        return None
    
    def _extract_cwe(self, cve: Dict) -> Optional[str]:
        """Extract CWE ID from CVE."""
        weaknesses = cve.get('weaknesses', [])
        for weakness in weaknesses:
            description = weakness.get('description', [])
            for desc in description:
                value = desc.get('value', '')
                if value.startswith('CWE-'):
                    return value
        return None
    
    def _check_exploit_available(self, cve: Dict) -> bool:
        """Check if exploit is known to be available."""
        references = cve.get('references', [])
        for ref in references:
            url = ref.get('url', '').lower()
            tags = ref.get('tags', [])
            if 'Exploit' in tags:
                return True
            if any(domain in url for domain in ['exploit-db.com', 'github.com/rapid7', 'metasploit.com']):
                return True
        
        # Check description for exploit mentions
        descriptions = cve.get('descriptions', [])
        for desc in descriptions:
            if 'exploit' in desc.get('value', '').lower():
                return True
        
        return False
    
    def get_update_status(self) -> Dict:
        """Get current update status."""
        return {
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'updates_available': self.check_for_updates(),
            'update_history': self.update_history[-5:] if self.update_history else [],
            'database_stats': self.db.get_statistics(),
            'config': {
                'nvd_enabled': bool(self.nvd_api_key),
                'wpscan_enabled': bool(self.wpscan_api_key),
                'auto_update': self.db_config.get('auto_update', False),
                'update_interval': self.db_config.get('update_interval', 86400),
            }
        }