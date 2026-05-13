#!/usr/bin/env python3
"""
Unrestricted File Upload Vulnerability Scanner.
Tests for file upload vulnerabilities that can lead to RCE.

References:
    - OWASP: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
    - CWE-434: Unrestricted Upload of File with Dangerous Type
"""

import os
import io
import random
import string
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """Unrestricted file upload vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Unrestricted File Upload Detection"
        
        # Test files with unique markers
        self.marker = self._random_string()
        
        self.test_files = {
            'php': {
                'filename': f'test_{self.marker}.php',
                'content': f'<?php echo "UPLOAD_TEST_{self.marker}"; ?>',
                'mime': 'application/x-php',
                'dangerous': True,
            },
            'php5': {
                'filename': f'test_{self.marker}.php5',
                'content': f'<?php echo "UPLOAD_TEST_{self.marker}"; ?>',
                'mime': 'application/x-php',
                'dangerous': True,
            },
            'phtml': {
                'filename': f'test_{self.marker}.phtml',
                'content': f'<?php echo "UPLOAD_TEST_{self.marker}"; ?>',
                'mime': 'application/x-httpd-php',
                'dangerous': True,
            },
            'phar': {
                'filename': f'test_{self.marker}.phar',
                'content': f'<?php echo "UPLOAD_TEST_{self.marker}"; ?>',
                'mime': 'application/x-php',
                'dangerous': True,
            },
            'shtml': {
                'filename': f'test_{self.marker}.shtml',
                'content': f'<!--#echo var="UPLOAD_TEST_{self.marker}"-->',
                'mime': 'text/html',
                'dangerous': True,
            },
            'php_double': {
                'filename': f'test_{self.marker}.php.jpg',
                'content': f'<?php echo "UPLOAD_TEST_{self.marker}"; ?>',
                'mime': 'image/jpeg',
                'dangerous': True,
            },
            'htaccess': {
                'filename': '.htaccess',
                'content': f'AddType application/x-httpd-php .jpg\nphp_value auto_prepend_file php://filter/convert.base64-decode/resource=test_{self.marker}.jpg',
                'mime': 'text/plain',
                'dangerous': True,
            },
            'svg_xss': {
                'filename': f'test_{self.marker}.svg',
                'content': f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("UPLOAD_TEST_{self.marker}")</script></svg>',
                'mime': 'image/svg+xml',
                'dangerous': False,
            },
            'config': {
                'filename': f'config_{self.marker}.php',
                'content': f'<?php echo "UPLOAD_TEST_{self.marker}"; ?>',
                'mime': 'application/x-php',
                'dangerous': True,
            },
        }
        
        # Upload form indicators
        self.upload_indicators = [
            'enctype="multipart/form-data"',
            'type="file"',
            '<input type="file"',
            'upload',
            'Upload',
        ]
        
        # Common upload paths
        self.upload_paths = [
            '/upload',
            '/upload.php',
            '/file-upload',
            '/admin/upload',
            '/media/upload',
            '/api/upload',
            '/wp-admin/media-new.php',
            '/wp-content/plugins/*/upload',
        ]
    
    def _random_string(self, length: int = 8) -> str:
        """Generate random string for unique markers."""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    
    def run(self) -> Dict:
        """Execute file upload vulnerability tests."""
        logger.info(f"Starting {self.module_name} for {self.target_url}")
        
        result = {
            'module': self.module_name,
            'upload_forms_found': [],
            'files_uploaded': [],
            'vulnerable_uploads': [],
            'findings': []
        }
        
        # Find upload forms
        forms = self._find_upload_forms()
        result['upload_forms_found'] = forms
        
        # Test each form
        for form in forms:
            form_vulns = self._test_form(form)
            result['vulnerable_uploads'].extend(form_vulns)
        
        # Generate findings
        for vuln in result['vulnerable_uploads']:
            self.findings.append({
                'title': f"Unrestricted file upload: {vuln['file_type']} files accepted",
                'severity': 'critical' if vuln.get('executable') else 'high',
                'description': (
                    f"The server accepts {vuln['file_type']} file uploads at {vuln['action']}. "
                    f"{'This could lead to remote code execution.' if vuln.get('executable') else ''}"
                ),
                'recommendation': (
                    "1. Use allowlist for file extensions\n"
                    "2. Validate MIME types server-side\n"
                    "3. Scan files for malware\n"
                    "4. Store uploads outside web root\n"
                    "5. Rename files on upload\n"
                    "6. Limit file size"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-434',
                'cvss_score': 9.8 if vuln.get('executable') else 7.5,
                'evidence': f"File: {vuln.get('filename')}",
            })
        
        result['findings'] = self.findings
        return result
    
    def _find_upload_forms(self) -> List[Dict]:
        """Find file upload forms."""
        forms = []
        
        resp = self.browser.get('/')
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                if form.find('input', {'type': 'file'}):
                    action = form.get('action', '')
                    method = form.get('method', 'post').upper()
                    file_input = form.find('input', {'type': 'file'})
                    
                    forms.append({
                        'action': urljoin(self.target_url, action) if action else self.target_url,
                        'method': method,
                        'field_name': file_input.get('name', 'file'),
                        'enctype': form.get('enctype', 'multipart/form-data'),
                    })
        
        return forms[:5]
    
    def _test_form(self, form: Dict) -> List[Dict]:
        """Test an upload form with dangerous file types."""
        vulnerabilities = []
        
        for file_type, file_info in self.test_files.items():
            if not file_info.get('dangerous'):
                continue
            
            uploaded = self._upload_file(
                form['action'],
                form['field_name'],
                file_info['filename'],
                file_info['content'],
                file_info['mime']
            )
            
            if uploaded:
                vulnerabilities.append({
                    'action': form['action'],
                    'file_type': file_type,
                    'filename': file_info['filename'],
                    'executable': file_type in ['php', 'php5', 'phtml', 'phar'],
                })
                break  # One finding per form is sufficient
        
        return vulnerabilities
    
    def _upload_file(self, url: str, field_name: str, filename: str, content: str, mime: str) -> bool:
        """Upload a file and check if accessible."""
        try:
            import requests
            
            files = {field_name: (filename, io.BytesIO(content.encode()), mime)}
            
            session = requests.Session()
            session.verify = False
            
            resp = session.post(url, files=files, timeout=15)
            
            if resp.status_code in [200, 201, 302]:
                # Try to access uploaded file
                test_paths = [
                    f'/uploads/{filename}',
                    f'/upload/{filename}',
                    f'/files/{filename}',
                    f'/media/{filename}',
                    f'/images/{filename}',
                    f'/wp-content/uploads/{filename}',
                ]
                
                for path in test_paths:
                    check = self.browser.get(path)
                    if check and check.status_code == 200:
                        if self.marker in check.text:
                            return True
                
                return True  # Upload succeeded even if we can't find the file
            
            return False
            
        except Exception as e:
            logger.debug(f"Upload test error: {e}")
            return False