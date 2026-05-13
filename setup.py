#!/usr/bin/env python3
"""
Setup configuration for Web Security Analyzer Pro.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="web-security-analyzer-pro",
    version="3.0.0",
    author="Security Research Team",
    author_email="dev@example.com",
    description="Comprehensive web application security scanner with advanced evasion capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_USERNAME/web-security-scanner-pro",
    project_urls={
        "Bug Tracker": "https://github.com/YOUR_USERNAME/web-security-scanner-pro/issues",
        "Documentation": "https://github.com/YOUR_USERNAME/web-security-scanner-pro/wiki",
        "Source Code": "https://github.com/YOUR_USERNAME/web-security-scanner-pro",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    packages=find_packages(include=["core", "core.*", "modules", "modules.*"]),
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=8.2.0",
            "pytest-cov>=5.0.0",
            "pytest-asyncio>=0.23.7",
            "black>=24.0.0",
            "flake8>=7.0.0",
            "mypy>=1.9.0",
            "isort>=5.13.0",
        ],
        "pdf": [
            "weasyprint>=61.2",
            "pdfkit>=1.0.0",
        ],
        "api": [
            "fastapi>=0.111.0",
            "uvicorn>=0.29.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "wsap=main:cli",
            "web-security-scanner=main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.json", "*.txt", "*.html", "*.md"],
        "database": ["*.db", "*.json", "wordlists/*.txt"],
        "reports": ["templates/*.html", "templates/*.md"],
    },
    data_files=[
        ("", ["config.yaml", "README.md", "LICENSE", "DISCLAIMER.md"]),
    ],
    zip_safe=False,
    keywords="security scanner vulnerability penetration-testing web-security wordpress xss sqli",
)