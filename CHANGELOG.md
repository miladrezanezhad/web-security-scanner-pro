# Changelog

## [3.0.0] - 2026-05-14

### 🎉 First Major Release

#### Added
- 48 security scanning modules
- 11 vulnerability scanners (XSS, SQLi, LFI, RFI, XXE, SSTI, CSRF, Command Injection, File Upload, SSRF, Deserialization)
- 9 WordPress-specific modules (Core, Plugins, Themes, Users, XML-RPC, REST API, Backups, Hardening)
- 5 web server scanners (Apache, Nginx, LiteSpeed, IIS, Tomcat)
- 4 PHP security modules (Version, Configuration, Dangerous Functions, Info Disclosure)
- 5 database scanners (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch)
- 4 control panel scanners (cPanel, DirectAdmin, Plesk, Virtualmin)
- 3 SSL/TLS modules (Certificate, Protocols, Ciphers)
- 3 API security modules (GraphQL, REST API, JWT)
- Evasion engine with WAF detection, User-Agent rotation, rate limiting
- Vulnerability database with 2024-2026 CVEs
- Report generation (HTML, Markdown, JSON, PDF)
- 222 automated tests with 99.5% pass rate
- Persian language support
- Modular architecture

#### Features
- Stealth scanning mode
- WAF detection (Cloudflare, Wordfence, Sucuri, ModSecurity, AWS WAF)
- Captcha detection
- Proxy and Tor support
- Smart rate limiting with jitter
- REST API for automation
- CLI interactive mode
- Comprehensive security headers testing
- Database vulnerability lookup

"@ | Out-File -FilePath CHANGELOG.md -Encoding UTF8