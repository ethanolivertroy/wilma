"""
Setup configuration for Wilma - AWS Bedrock Security Checker

Copyright (C) 2025  Ethan Troy
Licensed under GNU GPL v3.0 or later

DEPRECATED: This file is maintained for legacy compatibility only.
Use pyproject.toml for all dependency management (PEP 517/518).
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="wilma-sec",
    version="1.2.0",
    author="Ethan Troy",
    author_email="",  # Optional - leave empty or use a project email
    description="Wilma - AWS Bedrock Security Configuration Checker with GenAI-specific security features",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ethanolivertroy/wilma",
    project_urls={
        "Bug Tracker": "https://github.com/ethanolivertroy/wilma/issues",
        "Documentation": "https://github.com/ethanolivertroy/wilma#readme",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=[
        "boto3>=1.34.0",
        "botocore>=1.34.0",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "pyyaml>=6.0.0",
    ],
    entry_points={
        "console_scripts": [
            "wilma=wilma.__main__:main",
        ],
    },
    keywords="aws bedrock security genai ai ml audit compliance wilma",
    include_package_data=True,
    zip_safe=False,
)
