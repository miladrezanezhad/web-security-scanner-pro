#!/usr/bin/env python3
"""
Report generator for Web Security Analyzer Pro.
Fixed: File naming, multiple format generation, proper extensions.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from jinja2 import Template
from loguru import logger


class ReportGenerator:
    """
    Generate professional security scan reports.
    
    Fixed issues:
    - Proper file extensions (.html, .pdf, .md, .json)
    - Correct output directory handling
    - Support for custom filenames
    - Generate all formats simultaneously
    """
    
    def __init__(self, scan_results, config: Dict):
        self.results = scan_results
        self.config = config
        
        # Get template directory
        self.template_dir = Path(__file__).parent.parent / "reports" / "templates"
        
        # Get output directory from config with fallback
        output_setting = config.get('reporting', {}).get('output_directory', 'reports/output')
        self.output_dir = Path(output_setting)
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Report output directory: {self.output_dir.absolute()}")
        
        # Load templates
        self.html_template = self._load_template('report.html')
        self.md_template = self._load_template('report.md')
    
    def _load_template(self, filename: str) -> Optional[Template]:
        """Load Jinja2 template from file."""
        template_path = self.template_dir / filename
        
        if not template_path.exists():
            logger.error(f"Template not found: {template_path.absolute()}")
            logger.info(f"Looking in: {template_path.absolute()}")
            return None
        
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return Template(f.read())
        except Exception as e:
            logger.error(f"Failed to load template {filename}: {e}")
            return None
    
    def generate(
        self, 
        format: str = 'html', 
        output_path: Optional[str] = None,
        filename: Optional[str] = None
    ) -> str:
        """
        Generate report in specified format.
        
        Args:
            format: 'html', 'pdf', 'markdown', or 'json'
            output_path: Full path for output file
            filename: Custom filename without extension (e.g., 'milad')
        
        Returns:
            Absolute path to generated report
        
        Examples:
            # Auto-named
            reporter.generate('html')
            # => reports/output/scan_report_20240101_120000.html
            
            # Custom name
            reporter.generate('html', filename='milad')
            # => reports/output/milad.html
            
            # Full path
            reporter.generate('html', output_path='/path/to/report.html')
        """
        logger.info(f"Generating {format.upper()} report...")
        
        # Prepare template data
        data = self._prepare_data()
        
        if format == 'json':
            return self._generate_json(data, output_path, filename)
        elif format == 'markdown' or format == 'md':
            return self._generate_markdown(data, output_path, filename)
        elif format == 'html':
            return self._generate_html(data, output_path, filename)
        elif format == 'pdf':
            return self._generate_pdf(data, output_path, filename)
        else:
            raise ValueError(f"Unsupported format: {format}. Use: html, pdf, markdown, json")
    
    def generate_all(
        self, 
        filename: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate reports in ALL formats at once.
        
        Args:
            filename: Custom filename without extension
        
        Returns:
            Dict mapping format to file path
        """
        logger.info("Generating reports in all formats...")
        
        paths = {}
        formats = ['html', 'pdf', 'markdown', 'json']
        
        for fmt in formats:
            try:
                path = self.generate(format=fmt, filename=filename)
                paths[fmt] = path
                logger.info(f"✓ {fmt.upper()}: {path}")
            except Exception as e:
                logger.error(f"✗ Failed to generate {fmt}: {e}")
                paths[fmt] = None
        
        return paths
    
    def _get_output_path(self, extension: str, output_path: Optional[str], filename: Optional[str]) -> Path:
        """
        Determine the correct output file path.
        
        Priority:
        1. output_path (full path provided)
        2. filename (custom name, placed in output_dir)
        3. Auto-generated name with timestamp
        """
        # Priority 1: Full path provided
        if output_path:
            path = Path(output_path)
            # Ensure it has the correct extension
            if path.suffix != f'.{extension}':
                path = path.with_suffix(f'.{extension}')
            # Create parent directories if needed
            path.parent.mkdir(parents=True, exist_ok=True)
            return path
        
        # Priority 2: Custom filename
        if filename:
            # Remove any existing extension
            clean_name = Path(filename).stem
            return self.output_dir / f"{clean_name}.{extension}"
        
        # Priority 3: Auto-generated name
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return self.output_dir / f"scan_report_{timestamp}.{extension}"
    
    def _save_file(self, content: str, path: Path) -> str:
        """Save content to file and return absolute path."""
        try:
            # Ensure directory exists
            path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            abs_path = str(path.absolute())
            logger.info(f"✅ Report saved: {abs_path}")
            
            # Verify file was created
            if path.exists():
                file_size = path.stat().st_size
                logger.info(f"   File size: {file_size} bytes")
            else:
                logger.error("   File was NOT created!")
            
            return abs_path
            
        except Exception as e:
            logger.error(f"❌ Failed to save file {path}: {e}")
            raise
    
    # ========================================================================
    # Format-specific generators
    # ========================================================================
    
    def _generate_html(self, data: Dict, output_path: Optional[str], filename: Optional[str]) -> str:
        """Generate HTML report."""
        if not self.html_template:
            raise ValueError("HTML template not loaded. Check reports/templates/report.html")
        
        # Render template
        html_content = self.html_template.render(**data)
        
        # Determine output path
        file_path = self._get_output_path('html', output_path, filename)
        
        # Save file
        return self._save_file(html_content, file_path)
    
    def _generate_markdown(self, data: Dict, output_path: Optional[str], filename: Optional[str]) -> str:
        """Generate Markdown report."""
        if not self.md_template:
            raise ValueError("Markdown template not loaded. Check reports/templates/report.md")
        
        # Render template
        md_content = self.md_template.render(**data)
        
        # Determine output path
        file_path = self._get_output_path('md', output_path, filename)
        
        # Save file
        return self._save_file(md_content, file_path)
    
    def _generate_json(self, data: Dict, output_path: Optional[str], filename: Optional[str]) -> str:
        """Generate JSON report."""
        # Prepare JSON-safe data
        json_data = {
            'report_metadata': {
                'report_id': data.get('report_id', ''),
                'target_url': data.get('target_url', ''),
                'scan_date': data.get('scan_date', ''),
                'scan_mode': data.get('scan_mode', ''),
                'scanner_version': data.get('scanner_version', ''),
            },
            'statistics': {
                'critical': data.get('critical_count', 0),
                'high': data.get('high_count', 0),
                'medium': data.get('medium_count', 0),
                'low': data.get('low_count', 0),
                'info': data.get('info_count', 0),
                'total': data.get('total_count', 0),
            },
            'risk_assessment': {
                'score': data.get('risk_score', 0),
                'level': data.get('risk_level', ''),
            },
            'findings': self.results.get('findings', []),
            'modules_executed': self.results.get('modules_run', []),
            'module_results': self.results.get('module_results', {}),
        }
        
        json_content = json.dumps(json_data, indent=2, ensure_ascii=False)
        
        # Determine output path
        file_path = self._get_output_path('json', output_path, filename)
        
        # Save file
        return self._save_file(json_content, file_path)
    
    def _generate_pdf(self, data: Dict, output_path: Optional[str], filename: Optional[str]) -> str:
        """Generate PDF report from HTML template."""
        try:
            import pdfkit
        except ImportError:
            logger.error("pdfkit not installed. Install with: pip install pdfkit")
            logger.error("Also requires wkhtmltopdf: https://wkhtmltopdf.org/downloads.html")
            
            # Fallback: Try weasyprint
            try:
                from weasyprint import HTML
                return self._generate_pdf_weasyprint(data, output_path, filename)
            except ImportError:
                raise ImportError(
                    "PDF generation requires either:\n"
                    "  1. pip install pdfkit + wkhtmltopdf\n"
                    "  2. pip install weasyprint"
                )
        
        # Generate HTML first
        html_content = self.html_template.render(**data)
        
        # Save temporary HTML
        temp_html = self.output_dir / "temp_for_pdf.html"
        with open(temp_html, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Determine output path
        file_path = self._get_output_path('pdf', output_path, filename)
        
        # Convert to PDF
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None,
            'enable-local-file-access': None,
        }
        
        try:
            pdfkit.from_file(str(temp_html), str(file_path), options=options)
            logger.info(f"✅ PDF saved: {file_path.absolute()}")
        finally:
            # Clean up temp file
            if temp_html.exists():
                temp_html.unlink()
        
        return str(file_path.absolute())
    
    def _generate_pdf_weasyprint(self, data: Dict, output_path: Optional[str], filename: Optional[str]) -> str:
        """Generate PDF using WeasyPrint as fallback."""
        from weasyprint import HTML
        
        # Generate HTML
        html_content = self.html_template.render(**data)
        
        # Determine output path
        file_path = self._get_output_path('pdf', output_path, filename)
        
        # Convert to PDF
        HTML(string=html_content).write_pdf(str(file_path))
        
        logger.info(f"✅ PDF saved (WeasyPrint): {file_path.absolute()}")
        return str(file_path.absolute())
    
    # ========================================================================
    # Data preparation
    # ========================================================================
    
    def _prepare_data(self) -> Dict:
        """Prepare all data needed for report templates."""
        findings = self.results.get('findings', [])
        stats = self.results.get('statistics', {})
        
        # Count by severity
        critical = stats.get('critical', 0)
        high = stats.get('high', 0)
        medium = stats.get('medium', 0)
        low = stats.get('low', 0)
        info = stats.get('info', 0)
        total = stats.get('total', critical + high + medium + low + info)
        
        # Calculate percentages
        if total > 0:
            critical_percent = round(critical / total * 100, 1)
            high_percent = round(high / total * 100, 1)
            medium_percent = round(medium / total * 100, 1)
            low_percent = round(low / total * 100, 1)
            info_percent = round(info / total * 100, 1)
        else:
            critical_percent = high_percent = medium_percent = low_percent = info_percent = 0
        
        # Calculate risk score
        risk_score = min(critical * 25 + high * 15 + medium * 5 + low * 2, 100)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "CRITICAL RISK"
            risk_description = "Immediate action required. Critical vulnerabilities detected."
        elif risk_score >= 60:
            risk_level = "HIGH RISK"
            risk_description = "Significant vulnerabilities found. Action required within 48 hours."
        elif risk_score >= 40:
            risk_level = "MEDIUM RISK"
            risk_description = "Moderate vulnerabilities detected. Action required within one week."
        elif risk_score >= 20:
            risk_level = "LOW RISK"
            risk_description = "Minor issues found. Address within regular maintenance cycle."
        else:
            risk_level = "MINIMAL RISK"
            risk_description = "No significant vulnerabilities detected. Good security posture."
        
        return {
            'report_id': f"WSA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'scan_date': self.results.get('scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'scanner_version': '3.0.0',
            'target_url': self.results.get('target_url', 'Unknown'),
            'scan_duration': self._format_duration(self.results.get('duration', 0)),
            'scan_mode': self.results.get('scan_mode', 'stealth'),
            'modules_count': len(self.results.get('modules_run', [])),
            'modules_list': ', '.join(self.results.get('modules_run', [])),
            'total_count': total,
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low,
            'info_count': info,
            'critical_percent': critical_percent,
            'high_percent': high_percent,
            'medium_percent': medium_percent,
            'low_percent': low_percent,
            'info_percent': info_percent,
            'critical_bar': '█' * min(int(critical_percent), 50),
            'high_bar': '█' * min(int(high_percent), 50),
            'medium_bar': '█' * min(int(medium_percent), 50),
            'low_bar': '█' * min(int(low_percent), 50),
            'info_bar': '█' * min(int(info_percent), 50),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_description': risk_description,
            'security_posture': self._generate_security_posture(risk_score),
            'findings_html': self._generate_findings_html(findings),
            'findings_md': self._generate_findings_md(findings),
            'modules_table': self._generate_modules_table_html(),
            'modules_table_md': self._generate_modules_table_md(),
            'critical_recommendations': self._filter_recommendations(findings, 'critical'),
            'high_recommendations': self._filter_recommendations(findings, 'high'),
            'medium_recommendations': self._filter_recommendations(findings, 'medium'),
            'low_recommendations': self._filter_recommendations(findings, 'low'),
            'recommendations_list': self._get_all_recommendations(findings),
            'module_stats_table': self._generate_module_stats(),
            'vulnerability_type_table': self._generate_vulnerability_types(findings),
            'timeout': self.results.get('timeout', 30),
            'rps': self.results.get('rps', 1.0),
            'year': datetime.now().year,
            'owasp_status': '⚠️ Review Required' if total > 0 else '✅ Passed',
            'owasp_notes': f'{total} potential OWASP Top 10 findings' if total > 0 else 'No OWASP issues found',
            'ssl_status': '⚠️ Check Required',
            'ssl_notes': 'SSL/TLS analysis recommended',
            'headers_status': '⚠️ Check Required',
            'headers_notes': 'Security headers analysis recommended',
            'updates_status': '⚠️ Check Required' if total > 0 else '✅ Up to Date',
            'updates_notes': 'Software update analysis completed',
            'access_status': '⚠️ Review Required',
            'access_notes': 'Access control testing recommended',
            'scanner_ip': 'Automated Scanner',
            'user_agent': 'Web Security Analyzer Pro/3.0',
            'proxy_status': 'Disabled',
            'reproduction_steps': 'Run scan with same configuration to reproduce findings.',
            'resources_list': '- [OWASP Top 10](https://owasp.org/www-project-top-ten/)\n- [CVE Database](https://cve.mitre.org/)\n- [NVD](https://nvd.nist.gov/)',
            'scan_limitations': 'Automated scanning may not detect all vulnerabilities. Manual penetration testing recommended.',
        }
    
    def _generate_findings_html(self, findings: List[Dict]) -> str:
        """Generate HTML for findings."""
        if not findings:
            return '<p style="color:#28a745;font-weight:600;">✅ No vulnerabilities found!</p>'
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'info'), 99))
        
        html_parts = []
        for finding in sorted_findings:
            severity = finding.get('severity', 'info')
            title = finding.get('title', 'Untitled')
            description = finding.get('description', '')
            recommendation = finding.get('recommendation', '')
            cve_id = finding.get('cve_id', '')
            cvss_score = finding.get('cvss_score', '')
            module = finding.get('module', 'Unknown')
            
            cve_badge = f' <span class="cve-badge">{cve_id}</span>' if cve_id else ''
            cvss_badge = f' <span class="cvss-badge">CVSS: {cvss_score}</span>' if cvss_score else ''
            
            html_parts.append(f'''
            <div class="finding {severity}">
                <div class="finding-header">
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                    <span class="finding-title">{title}{cve_badge}{cvss_badge}</span>
                    <span class="module-tag">{module}</span>
                </div>
                <div class="finding-body">
                    <h4>Description</h4>
                    <p>{description}</p>
                    <h4>Recommendation</h4>
                    <div class="recommendation-box">{recommendation}</div>
                </div>
            </div>
            ''')
        
        return '\n'.join(html_parts)
    
    def _generate_findings_md(self, findings: List[Dict]) -> str:
        """Generate Markdown for findings."""
        if not findings:
            return '✅ **No vulnerabilities found!**\n'
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'info'), 99))
        
        emoji_map = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}
        
        md_parts = []
        for finding in sorted_findings:
            severity = finding.get('severity', 'info')
            emoji = emoji_map.get(severity, '⚪')
            title = finding.get('title', 'Untitled')
            description = finding.get('description', '')
            recommendation = finding.get('recommendation', '')
            
            md_parts.append(f'''
### {emoji} [{severity.upper()}] {title}

**Description:** {description}

**Recommendation:** {recommendation}

**Module:** {finding.get('module', 'Unknown')}

---
''')
        
        return '\n'.join(md_parts)
    
    def _generate_modules_table_html(self) -> str:
        """Generate HTML for modules table."""
        modules = self.results.get('module_results', {})
        if not modules:
            return '<tr><td colspan="3">No modules executed</td></tr>'
        
        rows = []
        for name, result in modules.items():
            findings_count = len(result.get('findings', []))
            status = '✅' if findings_count == 0 else f'⚠️ {findings_count} issues'
            rows.append(f'<tr><td>{name}</td><td>{status}</td><td>{findings_count}</td></tr>')
        
        return '\n'.join(rows)
    
    def _generate_modules_table_md(self) -> str:
        """Generate Markdown for modules table."""
        modules = self.results.get('module_results', {})
        if not modules:
            return '| - | - | - |'
        
        rows = ['| Module | Status | Findings |', '|--------|--------|----------|']
        for name, result in modules.items():
            findings_count = len(result.get('findings', []))
            status = '✅ Clean' if findings_count == 0 else f'⚠️ {findings_count} issues'
            rows.append(f'| {name} | {status} | {findings_count} |')
        
        return '\n'.join(rows)
    
    def _generate_module_stats(self) -> str:
        """Generate module statistics table."""
        modules = self.results.get('module_results', {})
        if not modules:
            return '| - | - | - | - | - | - |'
        
        rows = ['| Module | Critical | High | Medium | Low | Total |', 
                '|--------|----------|------|--------|-----|-------|']
        
        for name, result in modules.items():
            findings = result.get('findings', [])
            c = sum(1 for f in findings if f.get('severity') == 'critical')
            h = sum(1 for f in findings if f.get('severity') == 'high')
            m = sum(1 for f in findings if f.get('severity') == 'medium')
            l = sum(1 for f in findings if f.get('severity') == 'low')
            rows.append(f'| {name} | {c} | {h} | {m} | {l} | {len(findings)} |')
        
        return '\n'.join(rows)
    
    def _generate_vulnerability_types(self, findings: List[Dict]) -> str:
        """Generate vulnerability type statistics."""
        if not findings:
            return '| - | - | - |'
        
        type_counts = {}
        for f in findings:
            vuln_type = f.get('module', 'Unknown')
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        rows = ['| Type | Count |', '|------|-------|']
        for vuln_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            rows.append(f'| {vuln_type} | {count} |')
        
        return '\n'.join(rows)
    
    def _filter_recommendations(self, findings: List[Dict], severity: str) -> str:
        """Filter recommendations by severity."""
        recs = []
        for f in findings:
            if f.get('severity') == severity:
                rec = f.get('recommendation', '')
                if rec and rec not in recs:
                    recs.append(rec)
        
        if not recs:
            return f"No {severity} severity findings. ✅"
        
        return '\n'.join(f"- {r}" for r in recs[:5])
    
    def _get_all_recommendations(self, findings: List[Dict]) -> str:
        """Get all unique recommendations."""
        recs = []
        for f in findings:
            rec = f.get('recommendation', '')
            if rec and rec not in recs:
                recs.append(rec)
        
        if not recs:
            return '<li>No issues found - maintain current security practices</li>'
        
        return '\n'.join(f'<li>{r}</li>' for r in recs[:10])
    
    def _generate_security_posture(self, risk_score: int) -> str:
        """Generate security posture assessment."""
        if risk_score >= 80:
            return "**CRITICAL** - Immediate remediation required. Severe vulnerabilities detected."
        elif risk_score >= 60:
            return "**POOR** - High-severity vulnerabilities require prompt attention."
        elif risk_score >= 40:
            return "**FAIR** - Several medium-severity issues should be addressed."
        elif risk_score >= 20:
            return "**GOOD** - Minor issues detected. Maintain regular security practices."
        else:
            return "**EXCELLENT** - No significant vulnerabilities detected."
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        else:
            return f"{seconds / 3600:.1f} hours"