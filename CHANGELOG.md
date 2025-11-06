# Changelog

## [1.1.0] - 2025-11-05
### Published to PyPI

Wilma is now available on PyPI as **`wilma-sec`** for easy installation worldwide.

```bash
pip install wilma-sec
```

### Major Improvements
- **Published to PyPI** as `wilma-sec` - Install anywhere with pip/uv
- **Comprehensive Test Suite** - 2,114 lines of tests across 7 modules, 82 test cases with mocking
- **CI/CD Automation** - GitHub Actions workflows for automated testing and PyPI publishing
  - Tests run automatically on every push/PR across Python 3.8-3.12
  - Automated security scanning (bandit), linting (ruff), and type checking (mypy)
  - Smart version detection - only publishes when version changes
- **Knowledge Bases Security Module** - 12 security checks implemented (67% complete)
  - S3 bucket security validation
  - Vector store encryption checks
  - PII pattern detection
  - Prompt injection scanning
- **Utility Functions** - 600+ lines of reusable security utilities
  - PII detection patterns (SSN, credit cards, emails, etc.)
  - Prompt injection pattern detection
  - ARN parsing and validation
  - Tag validation utilities
- **Enhanced Configuration** - YAML-based configuration system with validation

### Technical Details
- 80% test coverage requirement enforced by CI/CD
- Development dependencies managed via `pyproject.toml` optional dependencies
- Security-first approach with bandit scanning in CI/CD pipeline
- Multi-Python version testing (3.8, 3.9, 3.10, 3.11, 3.12)

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for complete details of all 31 improvements.

---

## [1.0.0] - 2025-01-03
### Initial Release

Wilma is a comprehensive security auditing tool for AWS Bedrock that combines
traditional cloud security best practices with cutting-edge GenAI security capabilities.

### Features
- **GenAI-Specific Security Checks**
  - Prompt injection detection
  - PII exposure scanning
  - Model access policy validation
  - Cost anomaly detection

- **Traditional Security Auditing**
  - IAM permission auditing
  - Encryption validation
  - Network security (VPC endpoints)
  - Audit logging configuration
  - Resource tagging compliance

- **Three Operational Modes**
  - Beginner Mode: Plain English explanations with actionable fixes
  - Expert Mode: Technical details for security professionals
  - Learning Mode: Educational content about each security check

- **Flexible Output**
  - Human-readable text reports
  - JSON output for CI/CD integration
  - Risk scoring system (1-10 scale)

### Architecture
- Modern modular package structure (src/wilma/)
- Clean separation of concerns
- Professional text-based output (no emojis)
- Extensible check module system