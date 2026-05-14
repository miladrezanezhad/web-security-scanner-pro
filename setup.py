#!/usr/bin/env python3
"""
Setup configuration for WSA Pro - Web Security Analyzer.
"""

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8") if (this_directory / "README.md").exists() else ""

requirements = [
    "requests>=2.31",
    "beautifulsoup4>=4.12",
    "colorama>=0.4.6",
    "packaging>=24.0",
    "pyyaml>=6.0",
    "tabulate>=0.9.0",
    "rich>=13.7",
    "click>=8.1",
    "loguru>=0.7",
    "jinja2>=3.1",
    "cryptography>=42.0",
    "pyOpenSSL>=24.0",
    "dnspython>=2.6",
    "httpx>=0.27",
    "sqlalchemy>=2.0",
    "tqdm>=4.66",
]

setup(
    name="wsa-pro",
    version="3.0.0",
    author="Milad Rezanezhad",
    author_email="miladvf2014@gmail.com",
    description="Web Security Analyzer Pro - Advanced Security Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/miladrezanezhad/web-security-scanner-pro",
    packages=find_packages(include=["core", "core.*", "modules", "modules.*", "database", "database.*"]),
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "wsa=main:cli",
        ],
    },
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)