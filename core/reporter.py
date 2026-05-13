#!/usr/bin/env python3
"""
Report generation module.
Generates security reports in multiple formats: HTML, PDF, JSON, Markdown.

Features:
- Professional HTML reports with charts and styling
- PDF reports using WeasyPrint
- JSON exports for integration
- Markdown reports for documentation
- Customizable templates
- Severity-based color coding
- Remediation recommendations
"""

import os
import json
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
from loguru import logger


class ReportGenerator:
    """Generate security scan reports in multiple formats."""
    
    # Severity colors
    SEVERITY_COLORS = {
        'critical': '#dc3545',  # Red
        'high': '#fd7e14',      # Orange
        'medium': '#ffc107',    # Yellow
        'low': '#28a745',       # Green
        'info': '#17a2b8'       # Blue
    }
    
    SEVERITY_EMOJI = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'info': '🔵'
    }
    
    def __init__(self, scan_result: Any, config: Dict):
        """
        Initialize report generator.
        
        Args:
            scan_result: ScanResult object or dict
            config: Configuration dictionary
        """
        self.scan_result = scan_result
        self.config = config
        
        # Convert to dict if needed
        if hasattr(scan_result, 'to_dict'):
            self.data = scan_result.to_dict()
        else:
            self.data = scan_result
        
        self.report_config = config.get('reporting', {})
        self.output_dir = self.report_config.get('output_directory', 'reports/output')
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate(
        self, 
        format: str = 'html', 
        output_path: Optional[str] = None
    ) -> str:
        """
        Generate report in specified format.
        
        Args:
            format: Output format (html, pdf, json, markdown)
            output_path: Custom output path (optional)
        
        Returns:
            Path to generated report
        """
        generators = {
            'html': self._generate_html,
            'pdf': self._generate_pdf,
            'json': self._generate_json,
            'markdown': self._generate_markdown,
            'md': self._generate_markdown,
        }
        
        generator = generators.get(format.lower())
        if not generator:
            raise ValueError(f"Unsupported format: {format}. Use: {list(generators.keys())}")
        
        return generator(output_path)
    
    def _generate_html(self, output_path: Optional[str] = None) -> str:
        """Generate HTML report."""
        if not output_path:
            target = self.data.get('target_url', 'unknown').replace('https://', '').replace('/', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.output_dir, f"scan_report_{target}_{timestamp}.html")
        
        html_content = self._build_html_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
        return output_path
    
    def _generate_pdf(self, output_path: Optional[str] = None) -> str:
        """Generate PDF report."""
        try:
            from weasyprint import HTML
            
            if not output_path:
                target = self.data.get('target_url', 'unknown').replace('https://', '').replace('/', '_')
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = os.path.join(self.output_dir, f"scan_report_{target}_{timestamp}.pdf")
            
            html_content = self._build_html_report()
            HTML(string=html_content).write_pdf(output_path)
            
            logger.info(f"PDF report generated: {output_path}")
            return output_path
        except ImportError:
            logger.error("WeasyPrint not installed. Install with: pip install weasyprint")
            # Fallback to HTML
            return self._generate_html()
    
    def _generate_json(self, output_path: Optional[str] = None) -> str:
        """Generate JSON report."""
        if not output_path:
            target = self.data.get('target_url', 'unknown').replace('https://', '').replace('/', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.output_dir, f"scan_report_{target}_{timestamp}.json")
        
        json_data = {
            'report_metadata': {
                'generator': 'Web Security Analyzer Pro v3.0',
                'generated_at': datetime.now().isoformat(),
                'target_url': self.data.get('target_url'),
                'scan_time': self.data.get('scan_time'),
                'modules_run': self.data.get('modules_run', []),
            },
            'statistics': self.data.get('statistics', {}),
            'findings': self.data.get('findings', []),
            'module_results': self.data.get('module_results', {}),
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report generated: {output_path}")
        return output_path
    
    def _generate_markdown(self, output_path: Optional[str] = None) -> str:
        """Generate Markdown report."""
        if not output_path:
            target = self.data.get('target_url', 'unknown').replace('https://', '').replace('/', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.output_dir, f"scan_report_{target}_{timestamp}.md")
        
        md_content = self._build_markdown_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        logger.info(f"Markdown report generated: {output_path}")
        return output_path
    
    def _build_html_report(self) -> str:
        """Build complete HTML report."""
        stats = self.data.get('statistics', {})
        findings = self.data.get('findings', [])
        target_url = self.data.get('target_url', 'Unknown')
        scan_time = self.data.get('scan_time', datetime.now().isoformat())
        
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings, 
            key=lambda f: severity_order.get(f.get('severity', 'info'), 5)
        )
        
        # Build findings table rows
        findings_rows = ""
        for finding in sorted_findings:
            severity = finding.get('severity', 'info')
            color = self.SEVERITY_COLORS.get(severity, '#6c757d')
            emoji = self.SEVERITY_EMOJI.get(severity, '⚪')
            
            findings_rows += f"""
            <tr>
                <td><span class="severity-badge" style="background-color: {color};">{emoji} {severity.upper()}</span></td>
                <td><strong>{finding.get('title', 'Unknown')}</strong></td>
                <td>{finding.get('module', 'N/A')}</td>
                <td>{finding.get('cve_id', 'N/A')}</td>
                <td>{finding.get('cvss_score', 'N/A')}</td>
            </tr>
            <tr class="finding-details">
                <td colspan="5">
                    <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
                    <p><strong>Recommendation:</strong> {finding.get('recommendation', 'No recommendation')}</p>
                    {self._format_evidence(finding.get('evidence'))}
                </td>
            </tr>
            """
        
        # Build detailed findings sections
        detailed_sections = ""
        for finding in sorted_findings:
            severity = finding.get('severity', 'info')
            color = self.SEVERITY_COLORS.get(severity, '#6c757d')
            
            detailed_sections += f"""
            <div class="finding-card" style="border-left: 4px solid {color};">
                <h3>{finding.get('title', 'Unknown Finding')}</h3>
                <div class="finding-meta">
                    <span class="badge" style="background-color: {color};">{severity.upper()}</span>
                    <span>Module: {finding.get('module', 'N/A')}</span>
                    <span>CVE: {finding.get('cve_id', 'N/A')}</span>
                    <span>CVSS: {finding.get('cvss_score', 'N/A')}</span>
                </div>
                <div class="finding-body">
                    <h4>Description</h4>
                    <p>{finding.get('description', 'No description available.')}</p>
                    
                    <h4>Remediation</h4>
                    <div class="remediation-box">
                        {finding.get('recommendation', 'No recommendation available.')}
                    </div>
                    
                    {self._format_references(finding.get('references', []))}
                    
                    {self._format_evidence(finding.get('evidence'))}
                </div>
            </div>
            """
        
        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a237e, #0d47a1); color: white; padding: 40px 20px; text-align: center; border-radius: 8px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .summary-card.critical {{ border-top: 4px solid {self.SEVERITY_COLORS['critical']}; }}
        .summary-card.high {{ border-top: 4px solid {self.SEVERITY_COLORS['high']}; }}
        .summary-card.medium {{ border-top: 4px solid {self.SEVERITY_COLORS['medium']}; }}
        .summary-card.low {{ border-top: 4px solid {self.SEVERITY_COLORS['low']}; }}
        .summary-card .count {{ font-size: 3em; font-weight: bold; }}
        .summary-card .label {{ color: #666; }}
        .section {{ background: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .section h2 {{ margin-bottom: 20px; color: #1a237e; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
        th {{ background: #f5f5f5; font-weight: 600; }}
        .severity-badge {{ color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; }}
        .finding-card {{ padding: 20px; margin-bottom: 20px; background: #fafafa; border-radius: 8px; }}
        .finding-meta {{ margin: 10px 0; }}
        .finding-meta span {{ margin-right: 15px; }}
        .badge {{ color: white; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; }}
        .remediation-box {{ background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        .evidence-box {{ background: #263238; color: #aed581; padding: 15px; margin: 15px 0; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; overflow-x: auto; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; }}
        .footer a {{ color: #1a237e; }}
        @media print {{ body {{ background: white; }} .section {{ box-shadow: none; break-inside: avoid; }} }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔒 Security Scan Report</h1>
            <p class="subtitle">Web Security Analyzer Pro v3.0</p>
            <p><strong>Target:</strong> {target_url}</p>
            <p><strong>Scan Date:</strong> {scan_time}</p>
        </div>
        
        <!-- Summary Cards -->
        <div class="summary-cards">
            <div class="summary-card critical">
                <div class="count">{stats.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{stats.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{stats.get('medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{stats.get('low', 0)}</div>
                <div class="label">Low</div>
            </div>
        </div>
        
        <!-- Findings Overview -->
        <div class="section">
            <h2>📊 Findings Overview</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Module</th>
                        <th>CVE</th>
                        <th>CVSS</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>
        
        <!-- Detailed Findings -->
        <div class="section">
            <h2>🔍 Detailed Findings</h2>
            {detailed_sections if detailed_sections else '<p>No findings to display. ✅</p>'}
        </div>
        
        <!-- Modules Run -->
        <div class="section">
            <h2>⚙️ Modules Executed</h2>
            <p>{', '.join(self.data.get('modules_run', []))}</p>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by <strong>Web Security Analyzer Pro v3.0</strong></p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><em>This report is confidential and intended for authorized personnel only.</em></p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _build_markdown_report(self) -> str:
        """Build Markdown report."""
        stats = self.data.get('statistics', {})
        findings = self.data.get('findings', [])
        target_url = self.data.get('target_url', 'Unknown')
        scan_time = self.data.get('scan_time', datetime.now().isoformat())
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get('severity', 'info'), 5)
        )
        
        md = f"""# 🔒 Security Scan Report

**Target:** {target_url}  
**Scan Date:** {scan_time}  
**Generator:** Web Security Analyzer Pro v3.0

---

## 📊 Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {stats.get('critical', 0)} |
| 🟠 High | {stats.get('high', 0)} |
| 🟡 Medium | {stats.get('medium', 0)} |
| 🟢 Low | {stats.get('low', 0)} |
| 🔵 Info | {stats.get('info', 0)} |
| **Total** | **{stats.get('total', 0)}** |

---

## 🔍 Detailed Findings

"""
        
        if not sorted_findings:
            md += "✅ **No vulnerabilities found.**\n\n"
        else:
            for i, finding in enumerate(sorted_findings, 1):
                severity = finding.get('severity', 'info')
                emoji = self.SEVERITY_EMOJI.get(severity, '⚪')
                
                md += f"""### {i}. {emoji} {finding.get('title', 'Unknown')}

**Severity:** {severity.upper()}  
**Module:** {finding.get('module', 'N/A')}  
**CVE:** {finding.get('cve_id', 'N/A')}  
**CVSS Score:** {finding.get('cvss_score', 'N/A')}

**Description:**  
{finding.get('description', 'No description available.')}

**Remediation:**  
{finding.get('recommendation', 'No recommendation available.')}

"""
                
                if finding.get('evidence'):
                    md += f"""**Evidence:** 
                    {finding.get('evidence')}
 
"""
                
                if finding.get('references'):
                    md += "**References:**\n"
                    for ref in finding.get('references', []):
                        md += f"- {ref}\n"
                    md += "\n"
                
                md += "---\n\n"
        
        md += f"""## ⚙️ Modules Executed

{', '.join(self.data.get('modules_run', []))}

---

*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*  
*Web Security Analyzer Pro v3.0*
"""
        
        return md
    
    def _format_evidence(self, evidence: Optional[str]) -> str:
        """Format evidence for HTML display."""
        if not evidence:
            return ""
        return f"""
        <div class="evidence-box">
            <strong>Evidence:</strong>
            <pre>{evidence}</pre>
        </div>
        """
    
    def _format_references(self, references: List[str]) -> str:
        """Format references for HTML display."""
        if not references:
            return ""
        
        refs_html = "<h4>References</h4><ul>"
        for ref in references:
            refs_html += f'<li><a href="{ref}" target="_blank">{ref}</a></li>'
        refs_html += "</ul>"
        
        return refs_html