# Changelog

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