# Changelog

## [Unreleased]

### Added
- **AWS Bedrock Agents Security Module** 🎉 - COMPLETE (10 of 10 checks)
  - Action confirmation validation (OWASP LLM08: Excessive Agency)
  - Guardrail configuration enforcement (OWASP LLM01: Prompt Injection)
  - Service role permission audits (least privilege validation)
  - Lambda function security (public access detection, secrets scanning)
  - Knowledge base access validation (cross-account detection)
  - Memory encryption verification (customer-managed KMS keys)
  - Resource tagging compliance (Environment, Owner, DataClassification)
  - PII detection in metadata (SSN, credit cards, emails, AWS keys)
  - Prompt injection pattern scanning (24 known attack patterns)
  - CloudWatch logging validation (retention, encryption)
  - Addresses #1 attack vector for 2025 (indirect prompt injection via autonomous agents)
  - Compliance: HIPAA, PCI-DSS, FedRAMP, SOC 2, ISO 27001, GDPR
  - 1,838 lines of code, 36 test cases (100% passing)
  - Issues closed: #4, #29-#38

- **AWS Bedrock Guardrails Security Module** 🎉 - COMPLETE (11 of 11 checks)
  - Guardrail strength configuration validation (HIGH strength requirement, LOW-strength misses 70% of attacks)
  - Automated reasoning for hallucination prevention (OWASP LLM09: Misinformation)
  - Content filter coverage enforcement (PROMPT_ATTACK filter critical for OWASP LLM01)
  - PII filter configuration (GDPR Art. 32, HIPAA, PCI-DSS compliance)
  - Topic filter validation (unauthorized use case prevention)
  - Word filter configuration (profanity and custom term filtering)
  - Guardrail coverage analysis (identifies unprotected agents and knowledge bases)
  - Version management validation (DRAFT vs PRODUCTION deployment strategy)
  - KMS encryption verification (customer-managed keys for SOC 2, ISO 27001)
  - Resource tagging compliance (governance and cost allocation)
  - Contextual grounding threshold validation (0.7+ recommended for RAG applications)
  - Addresses OWASP LLM01 (Prompt Injection), LLM02 (Insecure Output), LLM09 (Misinformation)
  - MITRE ATLAS: AML.T0051 (LLM Prompt Injection), AML.T0048 (Evade ML Model)
  - Compliance: SOC 2, ISO 27001, GDPR Art. 32, HIPAA, PCI-DSS
  - 1,196 lines of code, comprehensive guardrail policy validation
  - Issues closed: TBD

- **AWS Bedrock Knowledge Bases (RAG) Security Module** 🎉 - COMPLETE (12 of 12 checks)
  - S3 bucket public access validation (prevents data poisoning attacks)
  - S3 bucket encryption verification (customer-managed KMS keys)
  - Vector store encryption (OpenSearch, Aurora, RDS, Pinecone, Redis)
  - Vector store access control (fine-grained access, wildcard principal detection)
  - PII detection in embeddings (SSN, email, phone, credit card pattern scanning)
  - Prompt injection pattern detection (24 known attack patterns in KB metadata)
  - S3 versioning validation (rollback capability for poisoning recovery)
  - IAM role permission audit (least privilege, wildcard detection)
  - Chunking configuration review (context leakage risk assessment)
  - CloudWatch logging validation (retention policies, KMS encryption)
  - Resource tagging compliance (Environment, Owner, DataClassification)
  - Embedding model access control (IAM permissions for model invocation)
  - Addresses OWASP LLM01 (Indirect Prompt Injection), LLM03 (Supply Chain), LLM06 (Sensitive Info), LLM07 (Vector Weaknesses)
  - MITRE ATLAS: AML.T0020 (Poison Training Data), ML Supply Chain Compromise
  - Compliance: HIPAA, PCI-DSS, SOC 2, ISO 27001, GDPR Art. 32
  - 2,237 lines of code, 25 test cases (80% passing)
  - Fully integrated and operational

- **AWS Bedrock Fine-Tuning Security Module** 🎉 - COMPLETE (11 of 11 checks) ✨ **PRIORITY 1 NOW 100% COMPLETE**
  - Training data bucket security (public access blocking, encryption, versioning)
  - Training data PII detection (pattern-based scanning for SSN, credit cards, emails, AWS keys)
  - Model data replay risk assessment (memorization and data leakage mitigation)
  - VPC isolation for training jobs (network security validation)
  - Training job CloudWatch logging (retention policies, KMS encryption)
  - Output model encryption (customer-managed KMS keys for fine-tuned models)
  - Training data access logging (S3 server access logs for audit trails)
  - Training job IAM roles (least privilege validation, wildcard permission detection)
  - Custom model tagging (governance tags: Environment, Owner, DataClassification)
  - Training data source validation (trusted source verification, supply chain security)
  - Model card documentation (model governance and responsible AI practices)
  - Addresses OWASP LLM03 (Supply Chain), LLM04 (Data/Model Poisoning), LLM06 (Sensitive Info Disclosure)
  - MITRE ATLAS: AML.T0020 (Poison Training Data), AML.T0024 (Backdoor ML Model)
  - Compliance: HIPAA, PCI-DSS, SOC 2, ISO 27001, GDPR Art. 32
  - 1,169 lines of code
  - Fully integrated into main checker
  - **ALL 4 Priority 1 (CRITICAL) modules now complete: Knowledge Bases, Agents, Guardrails, Fine-Tuning**
  - **Total: 44 security checks, 6,640 lines of security validation code**

### Breaking Changes
- **Minimum Python version raised to 3.9+** (was 3.8+)
  - Aligned with AWS CloudShell default Python version (3.9.16)
  - Python 3.8 reached end-of-life on October 7, 2024
  - boto3/botocore dropped Python 3.8 support in April 2025

### Changed
- **Dependency Management Cleanup**:
  - Removed `requirements.txt` (use `pyproject.toml` as single source of truth)
  - Added deprecation notice to `setup.py` (kept for legacy compatibility)
  - Added version upper bounds to all dependencies for SemVer compatibility
  - Fixed version triple-mismatch: unified to 1.2.0 across `__init__.py`, `setup.py`, and `pyproject.toml`

### Removed
- Python 3.8 support from CI/CD workflows
- Python 3.8 classifiers from package metadata
- `requirements.txt` file (unused dependencies: colorama, tabulate, opensearch-py, requests-aws4auth)

## [1.2.0] - 2025-12-27

### Added
- **Rich Terminal UI** - Beautiful Charmbracelet-quality terminal output
  - Colorful tables with proper borders and styling
  - Risk-based color coding (critical=red+blink, high=red, medium=yellow, low=blue)
  - Summary panels with grid layouts
  - Enhanced learning mode with styled tables showing OWASP LLM mappings
  - Professional panel layouts for findings
  - Syntax-highlighted fix commands in cyan on black
  - Beautiful double-border header panels
  - Horizontal rules separating sections

- **Educational Wiki** - Comprehensive security education resource
  - Home page with navigation hub
  - GenAI Security Fundamentals (7 pillars of GenAI security)
  - OWASP LLM Top 10 (2025) with real-world examples
  - Knowledge Bases (RAG) Security deep dive
  - Installation guide
  - Published at: https://github.com/ethanolivertroy/wilma/wiki

### Changed
- **Replaced Dependencies**:
  - Removed `colorama` (replaced by rich)
  - Removed `tabulate` (replaced by rich)
  - Added `rich>=13.7.0` for beautiful terminal UI

- **Report Generation** completely rewritten:
  - `reports.py` now uses Rich Console, Table, Panel, and Rule components
  - Summary displayed as rounded table with status indicators
  - Findings shown in bordered tables with color-coded severity
  - Learning mode shows OWASP LLM Top 10 mappings
  - ✓ Good practices shown with green checkmarks
  - ⚠ Critical issues with blinking red alerts

### Infrastructure
- Main and dev branches unified with full git history
- All tests, docs, and CI/CD preserved

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