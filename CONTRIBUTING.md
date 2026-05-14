# Contributing to WSA Pro

Thank you for your interest in contributing to Web Security Analyzer Pro! This document provides guidelines for contributing to the project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Adding a New Module](#adding-a-new-module)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Reporting Bugs](#reporting-bugs)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold these standards. Be respectful, professional, and constructive.

---

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- pip

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/web-security-scanner-pro.git
cd web-security-scanner-pro
git remote add upstream https://github.com/miladrezanezhad/web-security-scanner-pro.git
```

### Install Dependencies

```bash
pip install -r requirements.txt
pip install pytest pytest-cov  # For testing
```

### Verify Setup

```bash
python main.py
python tests/test_runner.py
```

---

## How to Contribute

There are many ways to contribute:

| Contribution | Description |
|-------------|-------------|
| **New Modules** | Add security test modules for new technologies or vulnerabilities |
| **Bug Fixes** | Fix issues in existing code |
| **CVE Updates** | Add new vulnerabilities to the database |
| **Documentation** | Improve wiki pages, README, or code comments |
| **Tests** | Add or improve automated tests |
| **Feature Requests** | Suggest new features via GitHub Issues |
| **Code Review** | Review pull requests from other contributors |

---

## Development Setup

### Project Structure

```
web-security-scanner-pro/
├── core/                  # Core engine (DO NOT modify unless necessary)
├── modules/               # Security modules (YOUR CONTRIBUTIONS GO HERE)
├── database/              # Vulnerability database files
├── tests/                 # Test suite
├── main.py               # Entry point
└── config.yaml           # Configuration
```

### Running in Development Mode

```bash
# Run with verbose logging
python main.py scan https://example.com -v

# Run specific module
python -c "
from core.browser import StealthBrowser
from core.evasion import EvasionConfig, ScanMode
from modules.cms.wordpress.detector import Scanner

config = EvasionConfig(mode=ScanMode.AGGRESSIVE)
browser = StealthBrowser('https://example.com', config)
scanner = Scanner(browser, 'https://example.com', {})
result = scanner.run()
print(result)
"
```

---

## Adding a New Module

### Step 1: Choose the Right Directory

| Category | Directory | Example |
|----------|-----------|---------|
| CMS | `modules/cms/` | WordPress, Joomla, Drupal |
| Web Servers | `modules/webserver/` | Apache, Nginx, LiteSpeed |
| PHP | `modules/php/` | Version, Config |
| Databases | `modules/database/` | MySQL, PostgreSQL |
| Control Panels | `modules/control_panels/` | cPanel, DirectAdmin |
| Vulnerabilities | `modules/vulnerabilities/` | XSS, SQLi, LFI |
| SSL/TLS | `modules/ssl_tls/` | Certificate, Protocols |
| Headers | `modules/headers/` | Security Headers |
| API Security | `modules/api_security/` | GraphQL, JWT |

### Step 2: Create the Module File

```python
#!/usr/bin/env python3
"""
Module Name - Brief description of what this tests.

References:
    - https://owasp.org/...
    - CWE-XXX: Description
"""

from typing import Dict, List, Optional


class Scanner:
    """Security scanner for [Technology/Vulnerability]."""
    
    def __init__(self, browser, target_url: str, config: Dict):
        """
        Initialize the scanner.
        
        Args:
            browser: StealthBrowser instance for HTTP requests
            target_url: Target URL to scan
            config: Configuration dictionary
        """
        self.browser = browser
        self.target_url = target_url.rstrip('/')
        self.config = config
        self.findings = []
        self.module_name = "Your Module Name"
    
    def run(self) -> Dict:
        """
        Execute the security test.
        
        Returns:
            Dict with 'findings' key containing list of vulnerability dicts
        """
        result = {
            'module': self.module_name,
            'target_url': self.target_url,
            'findings': []
        }
        
        # ============================================================
        # Your test logic here
        # ============================================================
        
        # Example: Make a request
        resp = self.browser.get('/some-path')
        
        # Example: Add a finding if vulnerable
        if resp and self._check_vulnerability(resp):
            self.findings.append({
                'title': 'Vulnerability Title',
                'severity': 'high',  # critical, high, medium, low, info
                'description': 'Detailed description of the vulnerability',
                'recommendation': 'Step-by-step fix instructions',
                'module': self.module_name,
                'cwe_id': 'CWE-XXX',
                'cvss_score': 7.5,
                'evidence': 'Raw data proving the finding',
                'references': [
                    'https://owasp.org/...',
                    'https://cve.mitre.org/...'
                ]
            })
        
        result['findings'] = self.findings
        return result
    
    def _check_vulnerability(self, response) -> bool:
        """Helper method to check for vulnerability."""
        # Your detection logic
        return False
```

### Step 3: Register the Module

In `core/scanner.py`, add to `MODULE_MAP`:

```python
MODULE_MAP = {
    # ... existing modules ...
    'your_module': 'modules.your_category.your_module',
}
```

In `main.py`, add to `module_map`:

```python
module_map = {
    # ... existing modules ...
    '99': 'your_module',
}
```

In `main.py`, add to `show_modules_menu()`:

```python
99. Your Module Name
```

### Step 4: Write Tests

Create `tests/modules/test_your_module.py`:

```python
class TestYourModule:
    def test_module_imports(self):
        from modules.your_category import your_module
        assert hasattr(your_module, 'Scanner')
    
    def test_scanner_initialization(self, browser, sample_target, sample_config):
        from modules.your_category.your_module import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        assert scanner is not None
        assert hasattr(scanner, 'run')
    
    def test_run_returns_dict(self, browser, sample_target, sample_config):
        from modules.your_category.your_module import Scanner
        scanner = Scanner(browser, sample_target, sample_config)
        result = scanner.run()
        assert isinstance(result, dict)
        assert 'findings' in result
        assert isinstance(result['findings'], list)
```

### Step 5: Run Tests

```bash
# Run your module tests
python -m pytest tests/modules/test_your_module.py -v

# Run all tests to check for regressions
python tests/test_runner.py
```

---

## Pull Request Process

1. **Create a branch:**
   ```bash
   git checkout -b feature/your-module-name
   ```

2. **Make your changes** following coding standards

3. **Run all tests:**
   ```bash
   python tests/test_runner.py
   ```

4. **Commit with descriptive message:**
   ```bash
   git commit -m "Add [Module Name] for [what it detects]"
   ```

5. **Push to your fork:**
   ```bash
   git push origin feature/your-module-name
   ```

6. **Create Pull Request** on GitHub

### PR Checklist

- [ ] Module file in correct directory
- [ ] `Scanner` class with `__init__` and `run` methods
- [ ] Returns dict with `findings` key
- [ ] Proper docstrings and comments
- [ ] Registered in `core/scanner.py` MODULE_MAP
- [ ] Registered in `main.py` module_map and menu
- [ ] Tests written and passing
- [ ] No breaking changes to existing functionality
- [ ] No real credentials, tokens, or sensitive data

### PR Title Format

```
Add [Module Name] - [Brief Description]

Example:
Add MongoDB Scanner - Tests for unauthorized access and weak authentication
Fix WordPress Plugin Detection - Handle custom plugin directories
Update CVE Database - Add 2026 Q2 vulnerabilities
```

---

## Coding Standards

### Python

- **Version:** Python 3.9+
- **Style:** [PEP 8](https://peps.python.org/pep-0008/)
- **Line length:** 100 characters
- **Docstrings:** Google style
- **Type hints:** All function parameters and return values
- **Imports order:** Standard library → Third-party → Internal

### Comments

- **Language:** English
- **Explain WHY, not WHAT** (the code shows what)
- Every module file starts with a docstring explaining its purpose

### Security

- Detection only, never exploitation
- No hardcoded credentials
- No malicious code
- Follow responsible disclosure for vulnerabilities found in WSA Pro itself

---

## Testing

### Running Tests

```bash
# All tests
python tests/test_runner.py

# Quick import check
python tests/test_runner.py --quick

# Core tests only
python -m pytest tests/core/ -v

# Module tests only
python -m pytest tests/modules/ -v

# Specific file
python -m pytest tests/modules/test_wordpress.py -v

# With coverage
python -m pytest tests/ --cov=core --cov=modules --cov-report=html
```

### Writing Tests

Each module should have tests that verify:
1. Module can be imported
2. Scanner class exists
3. Scanner initializes correctly
4. `run()` returns a dict
5. Dict has `findings` key

---

## Reporting Bugs

### Bug Report Template

When creating a bug issue, include:

```
**Description:**
Clear description of the bug

**Steps to Reproduce:**
1. Run command '...'
2. Select option '...'
3. See error

**Expected Behavior:**
What should have happened

**Actual Behavior:**
What actually happened

**Environment:**
- OS: Windows 11 / Ubuntu 22.04 / macOS 14
- Python: 3.11.9
- WSA Pro: 3.0.0
```

---

## Security Vulnerabilities

If you discover a security vulnerability in WSA Pro itself:

- **DO NOT** create a public issue
- **DO NOT** submit a public pull request
- Email: miladvf2014@gmail.com
- Allow 90 days for fix before public disclosure

---

## Questions?

- **Documentation:** [Wiki](https://github.com/miladrezanezhad/web-security-scanner-pro/wiki)
- **Issues:** [GitHub Issues](https://github.com/miladrezanezhad/web-security-scanner-pro/issues)
- **Discussions:** [GitHub Discussions](https://github.com/miladrezanezhad/web-security-scanner-pro/discussions)

---

Thank you for contributing to WSA Pro! 🎉