# Web Security Analyzer Pro v3.0

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **Comprehensive web application security scanner with advanced evasion capabilities**

## ⚠️ LEGAL WARNING - READ CAREFULLY

This tool is designed for **legitimate security testing only**. By using this software, you agree that:

✅ **Authorized Use Cases:**
- Security testing of your OWN websites
- Penetration testing with WRITTEN authorization from the owner
- Educational purposes in controlled lab environments
- Capture The Flag (CTF) competitions
- Security research and vulnerability assessment

❌ **Prohibited Use Cases:**
- Scanning websites without explicit permission
- Unauthorized penetration testing
- Any malicious or illegal activities
- Violating computer fraud and abuse laws

**Applicable Laws:**
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act 1990 - United Kingdom
- General Data Protection Regulation (GDPR) - European Union
- Local cybersecurity laws in your jurisdiction

**THE DEVELOPERS ASSUME NO LIABILITY FOR UNAUTHORIZED OR ILLEGAL USE OF THIS TOOL.**

## 🚀 Features

### Core Capabilities
- **20+ Security Modules** covering all major attack vectors
- **Advanced Evasion Engine** with WAF bypass techniques
- **Real-time Vulnerability Database** updated through 2026
- **Multi-format Reporting** (HTML, PDF, JSON, Markdown)
- **REST API** for CI/CD integration
- **Proxy & Tor Support** for anonymous scanning

### Security Testing Modules

| Category | Modules |
|----------|---------|
| **CMS** | WordPress, Joomla, Drupal |
| **Web Servers** | Apache, Nginx, LiteSpeed, IIS, Tomcat |
| **PHP** | Version, Configuration, Dangerous Functions |
| **Databases** | MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch |
| **Control Panels** | cPanel, DirectAdmin, Plesk, Virtualmin |
| **Vulnerabilities** | XSS, SQLi, LFI/RFI, XXE, SSTI, CSRF, Command Injection, File Upload, SSRF |
| **SSL/TLS** | Certificate Analysis, Protocol Check, Cipher Suite |
| **API Security** | GraphQL, REST, JWT Analysis |

### Evasion Features
- Intelligent User-Agent rotation
- Request throttling with jitter
- WAF detection (Cloudflare, Sucuri, AWS WAF, ModSecurity, etc.)
- Captcha detection
- Exponential backoff with jitter
- Proxy rotation support
- Tor network integration

## 📦 Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/web-security-scanner-pro.git
cd web-security-scanner-pro

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py version
```

### Full Install with All Features

```bash
# Install with optional dependencies
pip install -r requirements.txt
pip install weasyprint pdfkit  # For PDF reports
```

## 🔧 Usage

### Basic Scan

```bash
# Quick scan with default settings
python main.py quick https://example.com

# Full scan in stealth mode
python main.py scan https://example.com --mode stealth

# Scan specific modules
python main.py scan https://example.com --modules wordpress,php,xss,sqli

# Generate reports
python main.py scan https://example.com --format html pdf json
```

### Advanced Options

```bash
# Aggressive mode (faster but more detectable)
python main.py scan https://example.com --mode aggressive

# Verbose output for debugging
python main.py scan https://example.com -v

# Save results to file
python main.py scan https://example.com -o results.json

# Start REST API server
python main.py api --port 8000

# Update vulnerability database
python main.py update --all
```

### REST API Usage

```bash
# Start API server
python main.py api --host 0.0.0.0 --port 8000

# API documentation available at:
# http://localhost:8000/docs
```

```python
import requests

# Start a scan
response = requests.post('http://localhost:8000/scan', json={
    'target_url': 'https://example.com',
    'modules': ['wordpress', 'xss', 'sqli']
})

# Get results
scan_id = response.json()['scan_id']
results = requests.get(f'http://localhost:8000/results/{scan_id}')
```

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════════╗
║              Web Security Analyzer Pro v3.0                         ║
║              Comprehensive Security Analysis Tool                    ║
╚══════════════════════════════════════════════════════════════════════╝

Target: https://example.com
Mode: stealth
Time: 2026-05-14 10:30:00

Running 15 security modules...

✓ wordpress: WordPress 6.4.2 detected
✓ php: PHP 8.1.26 detected
✓ ssl: TLS 1.3, Grade A
✓ headers: 3 missing security headers
🚨 xss: 2 reflected XSS found
🚨 sqli: 1 time-based SQLi found

═══════════════════════════════════════════════════
📊 Scan Summary
═══════════════════════════════════════════════════
CRITICAL:  2  ⚠️
HIGH:      4  ⚠️
MEDIUM:    7  ⚠️
LOW:       3  ✅
INFO:      8  ℹ️
───────────────────────────────────────────────────
TOTAL:    24 findings
═══════════════════════════════════════════════════
```

## 📁 Project Structure

```
web-security-scanner-pro/
├── main.py                 # Entry point
├── config.yaml            # Configuration
├── core/                  # Core engine
├── modules/               # Security test modules
├── database/              # Vulnerability database
├── reports/               # Report templates
└── docs/                  # Documentation
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md).

### Adding New Modules

Create a new file in the appropriate `modules/` directory:

```python
# modules/vulnerabilities/my_test.py

class Scanner:
    def __init__(self, browser, target_url, config):
        self.browser = browser
        self.target_url = target_url
        self.config = config
        self.findings = []
    
    def run(self):
        # Your test logic here
        return {'findings': self.findings}
```

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚡ Credits

Created by [Your Name] - Security Researcher

## 📞 Contact

- Security Issues: security@example.com
- General Questions: contact@example.com
- GitHub Issues: [Create an issue](https://github.com/YOUR_USERNAME/web-security-scanner-pro/issues)

## 🌟 Star History

If you find this tool useful, please consider giving it a star ⭐
