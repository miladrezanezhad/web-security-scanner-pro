# Security Policy

## Supported Versions

| Version | Supported | Status |
|---------|:---------:|--------|
| 3.0.x | ✅ | Current release - Full support |
| 2.x | ❌ | End of life |
| 1.x | ❌ | End of life |

---

## Reporting a Vulnerability

If you discover a security vulnerability in WSA Pro itself, please report it responsibly.

### DO NOT

- ❌ Create a public GitHub issue
- ❌ Submit a public pull request with the fix
- ❌ Disclose the vulnerability on social media
- ❌ Share exploit details publicly before a fix is available

### DO

- ✅ Email: **miladvf2014@gmail.com**
- ✅ Use subject line: "WSA Pro Security Vulnerability"
- ✅ Include detailed description
- ✅ Include steps to reproduce
- ✅ Allow time for investigation and fix

---

## What to Include in Your Report

```
Subject: WSA Pro Security Vulnerability

Description:
[Detailed description of the vulnerability]

Steps to Reproduce:
1. Step one
2. Step two
3. Observe vulnerability

Impact:
[What an attacker could do]

Affected Version:
3.0.0

Suggested Fix (optional):
[Your suggestion]

Your Contact:
[Name and email for follow-up questions]
```

---

## Response Timeline

| Phase | Timeline | Description |
|-------|----------|-------------|
| Acknowledgment | 48 hours | Confirmation of receipt |
| Initial Assessment | 7 days | Determine severity and scope |
| Fix Development | 30 days | Create and test a patch |
| Public Disclosure | 90 days | Publish advisory and fix |

---

## Severity Classification

| Level | CVSS Score | Examples |
|-------|:----------:|----------|
| Critical | 9.0 - 10.0 | Remote code execution, authentication bypass |
| High | 7.0 - 8.9 | SQL injection, serious data exposure |
| Medium | 4.0 - 6.9 | XSS, information disclosure |
| Low | 0.1 - 3.9 | Minor configuration issues |

---

## Disclosure Policy

- Reporter will be credited in the advisory (unless anonymity requested)
- CVE ID will be requested for critical/high vulnerabilities
- Fix will be released before public disclosure
- Advisory will be published on GitHub Security Advisories

---

## Bug Bounty

We do not currently offer a paid bug bounty program. However, we greatly appreciate responsible disclosure and will:

- Credit you in the advisory
- Acknowledge your contribution publicly
- List you in the project's Hall of Fame

---

## Security Best Practices for Users

### When Using WSA Pro

1. **Scan only authorized targets** — Never scan systems without permission
2. **Use stealth mode** — Reduce impact on production systems
3. **Review findings** — Verify before taking action
4. **Keep updated** — Use the latest version for security fixes

### Protecting Your Scan Data

1. **Store reports securely** — They contain vulnerability information
2. **Use encryption** — Encrypt sensitive scan results
3. **Limit access** — Share reports only with authorized personnel
4. **Delete when done** — Remove scan data when no longer needed

---

## Known Limitations

### Will Not Fix

| Issue | Reason |
|-------|--------|
| Detection by advanced WAFs | Cat and mouse game, not a security vulnerability |
| False positives in specific configurations | Inherent in automated scanning |

### Under Investigation

No known security vulnerabilities at this time.

---

## Security Advisories

Security advisories are published on:

- [GitHub Security Advisories](https://github.com/miladrezanezhad/web-security-scanner-pro/security/advisories)
- [Release Notes](https://github.com/miladrezanezhad/web-security-scanner-pro/releases)

---

## Contact

- **Security Issues:** miladvf2014@gmail.com
- **General Questions:** [GitHub Discussions](https://github.com/miladrezanezhad/web-security-scanner-pro/discussions)
- **Bug Reports:** [GitHub Issues](https://github.com/miladrezanezhad/web-security-scanner-pro/issues)

---

## Acknowledgments

We thank the following individuals for responsibly disclosing vulnerabilities:

- No reports received yet. You could be the first!

---

**Last Updated:** May 14, 2026
