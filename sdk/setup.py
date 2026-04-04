"""
sdk/setup.py — CYBERDUDEBIVASH® Sentinel APEX Python SDK
pip install -e .  (development)
pip install sentinel-apex-sdk  (production — PyPI)
"""
from setuptools import setup, find_packages

try:
    with open("../README_SDK.md", encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = (
        "CYBERDUDEBIVASH® Sentinel APEX — Python SDK for the "
        "Sentinel APEX Threat Intelligence Platform."
    )

setup(
    name="sentinel-apex-sdk",
    version="100.0.0",
    author="CYBERDUDEBIVASH Pvt. Ltd.",
    author_email="api@cyberdudebivash.com",
    description="Official Python SDK for CYBERDUDEBIVASH® Sentinel APEX Threat Intelligence API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cyberdudebivash/sentinel-apex-sdk",
    project_urls={
        "Documentation": "https://docs.sentinel.cyberdudebivash.com",
        "API Reference":  "https://api.sentinelapex.cyberdudebivash.com/docs",
        "Issue Tracker":  "https://github.com/cyberdudebivash/sentinel-apex-sdk/issues",
    },
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[],           # Zero external dependencies (stdlib only)
    extras_require={
        "requests": ["requests>=2.28.0"],  # Optional HTTP/2 + connection reuse
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
            "responses",           # Mock HTTP for tests
            "mypy",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "cybersecurity", "threat-intelligence", "cve", "vulnerability",
        "sentinel", "siem", "soc", "stix", "cisa-kev", "threat-intel",
    ],
    entry_points={
        "console_scripts": [
            "sentinel=sentinel_sdk.cli:main",
        ],
    },
)
