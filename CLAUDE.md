# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Wilma is an AWS Bedrock security configuration checker that combines traditional cloud security best practices with GenAI-specific security capabilities. It audits AWS Bedrock deployments for security vulnerabilities, misconfigurations, and compliance issues.

**Key Technologies:**
- Python 3.9+ (support for 3.9, 3.10, 3.11, 3.12, 3.13)
- boto3/botocore for AWS API access
- Rich library for terminal UI
- pytest with moto for testing
- Ruff for linting, Bandit for security scanning

## Development Commands

### Installation & Setup
```bash
# Install in development mode (recommended)
pip install -e ".[dev]"

# Or install production dependencies only
pip install -e .

# Or manually install dependencies
pip install -r requirements.txt
```

### Running Wilma
```bash
# Basic security check
wilma

# Learning mode (educational explanations)
wilma --learn

# JSON output for CI/CD
wilma --output json

# Use specific AWS profile/region
wilma --profile production --region us-west-2

# Run selective checks
wilma --checks genai,iam,knowledge_bases

# Filter by minimum risk level
wilma --min-risk HIGH
```

### Testing
```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_genai_checks.py

# Run specific test class or method
pytest tests/test_genai_checks.py::TestPromptInjectionCheck
pytest tests/test_genai_checks.py::TestPromptInjectionCheck::test_no_guardrails_configured

# Run with coverage (required: 50% minimum)
pytest --cov=wilma --cov-report=term-missing --cov-report=html --cov-fail-under=50

# Run without slow tests (default in CI)
pytest -v -m "not slow"

# Run contract tests only
pytest -v -m contract

# Run in verbose mode
pytest -v tests/
```

### Code Quality & Linting
```bash
# Run ruff linter (style + security checks)
ruff check src/ tests/

# Auto-fix ruff issues where possible
ruff check --fix src/ tests/

# Format code with ruff
ruff format src/ tests/

# Run bandit security scanner
bandit -r src/ -s B101,B106,B107,B112,B601

# Run mypy type checker
mypy src/wilma --show-error-codes --pretty
```

### Demo & Local Testing
```bash
# Create demo AWS resources with security issues
python scripts/demo_setup.py --setup --region us-east-1

# Run Wilma against demo resources
python scripts/demo_setup.py --test

# Clean up demo resources
python scripts/demo_setup.py --cleanup

# All three steps at once
python scripts/demo_setup.py --all --confirm
```

## Architecture

### Module Structure

```
src/wilma/
├── __main__.py          # CLI entry point, argument parsing
├── checker.py           # BedrockSecurityChecker - main orchestrator
├── config.py            # WilmaConfig - configuration management
├── enums.py             # SecurityMode, RiskLevel enumerations
├── reports.py           # ReportGenerator - output formatting (text/JSON)
├── utils.py             # Shared utilities (PII detection, prompt injection patterns, AWS helpers)
└── checks/              # Security check modules (each inherits checker instance)
    ├── __init__.py      # Exports all check classes
    ├── genai.py         # GenAI-specific threats (OWASP LLM Top 10)
    ├── iam.py           # IAM & access control
    ├── logging.py       # Logging & monitoring
    ├── network.py       # VPC endpoints & network security
    ├── tagging.py       # Resource tagging compliance
    ├── knowledge_bases.py  # Knowledge Base (RAG) security (12 checks)
    ├── agents.py        # Bedrock Agents security (not yet implemented)
    ├── guardrails.py    # Advanced guardrails validation (not yet implemented)
    └── fine_tuning.py   # Model fine-tuning security (not yet implemented)
```

### Core Architecture Patterns

**1. Central Orchestrator Pattern:**
- `BedrockSecurityChecker` initializes all AWS clients once (bedrock, bedrock-agent, bedrock-runtime, iam, s3, ec2, cloudtrail, cloudwatch)
- Each check module receives the checker instance via `__init__(self, checker)` for client access
- Findings are centrally collected via `checker.add_finding()` and `checker.add_good_practice()`

**2. Check Module Pattern:**
Each check module in `checks/` follows this structure:
```python
class SecurityChecks:
    def __init__(self, checker):
        self.checker = checker
        # Access AWS clients: self.checker.bedrock, self.checker.iam, etc.

    def check_something(self) -> List[Dict]:
        """Perform security check, report findings via self.checker.add_finding()"""
        findings = []
        # Check logic here
        if issue_found:
            self.checker.add_finding(
                risk_level=RiskLevel.HIGH,
                category="Security Category",
                resource="resource-name",
                issue="Simple explanation",
                recommendation="How to fix",
                fix_command="aws cli command",  # Optional
                technical_details="Technical depth",  # Optional
                learn_more="Educational context"  # Optional
            )
        return findings
```

**3. Finding Structure:**
Findings are dictionaries with these fields:
- `risk_level`: RiskLevel enum (CRITICAL=9, HIGH=8, MEDIUM=6, LOW=3, INFO=1)
- `risk_score`: Numeric score from risk_level
- `category`: Check category (e.g., "Knowledge Base Security")
- `resource`: Affected AWS resource
- `issue`: Simple explanation for standard mode
- `recommendation`: How to fix
- `fix_command`: AWS CLI command to remediate (optional)
- `technical_details`: Technical depth for experts (optional)
- `learn_more`: Educational OWASP/MITRE context (optional)
- `timestamp`: ISO format UTC timestamp

**4. Configuration System:**
- `WilmaConfig` loads from `~/.wilma/config.yaml` (or custom path via `--config`)
- Supports: required_tags, thresholds (chunk sizes, log retention), output filtering, enabled checks
- CLI arguments override config file settings
- Use `wilma --create-config path.yaml` to generate example config

**5. AWS Pagination Handling:**
Knowledge Base checks handle pagination via `paginate_aws_results()` utility for accounts with >100 resources.

## Important Implementation Details

### AWS Client Access
- **Never create new boto3 clients in check modules** - always use `self.checker.bedrock`, `self.checker.s3`, etc.
- **bedrock-agent client** is required for Knowledge Base API access (use `self.checker.bedrock_agent`)
- Session details available: `self.checker.region`, `self.checker.account_id`, `self.checker.session`

### Security Check Execution Flow
Order matters for contextual checks:
1. IAM & Access Control (foundation)
2. Logging & Monitoring (visibility)
3. Network Security (connectivity)
4. Resource Tagging (organization)
5. GenAI Threats (OWASP LLM Top 10)
6. Knowledge Bases (RAG-specific, 12 comprehensive checks)

### Exit Codes
- `0`: Success, no HIGH/CRITICAL findings
- `1`: HIGH findings detected
- `2`: CRITICAL findings detected
- `3`: Error (credential issues, KeyboardInterrupt, exceptions)

### Pattern Detection
Two critical security patterns in `utils.py`:
- `PII_PATTERNS`: Email, SSN, phone, credit card, AWS access keys
- `PROMPT_INJECTION_PATTERNS`: Jailbreak attempts, suspicious unicode, system prompt overrides

### Testing Strategy
- **All tests are fully mocked** - no AWS credentials required
- Use `mock_checker` fixture from `conftest.py` - provides pre-configured checker with mocked AWS clients
- Test both pass and fail cases for every check
- Coverage minimum: 50% (enforced in CI)
- Contract tests marked with `@pytest.mark.contract`
- Slow tests marked with `@pytest.mark.slow`

## CI/CD Integration

### GitHub Actions Workflows

**test.yml** (runs on push/PR):
- Tests all Python versions (3.9-3.13)
- Runs: ruff, bandit, mypy, pytest with coverage
- Uploads coverage reports (from Python 3.11 only)

**publish.yml** (runs on main branch changes to src/ or pyproject.toml):
- Runs full test suite across all Python versions
- Publishes to PyPI on version bump in `pyproject.toml`
- Automated release process (no manual intervention)

**codeql.yml**: SAST security analysis

**scorecard.yml**: OSSF Scorecard security assessment

### Version Bumping & Release
1. Update version in `pyproject.toml` (single source of truth)
2. Push to main branch
3. GitHub Actions automatically publishes to PyPI as `wilma-sec`
4. No need to manually create git tags

## Security Considerations

### Bandit Skips (intentional)
- `B101`: assert_used (tests need asserts)
- `B106/B107`: hardcoded_password_funcarg (false positives on AWS pagination tokens like `nextToken`)
- `B112`: try_except_continue (acceptable in check modules for resilience)
- `B601`: shell_injection (context-specific, vetted usage)

### Ruff Ignores (intentional)
- `S101`: Allow asserts in tests
- `S104-S108`: AWS-related false positives
- Line length flexible (120 chars) due to AWS API verbosity

## Code Style & Conventions

- **No emojis in output** - text-based status indicators for terminal compatibility
- **Professional tone** - simple explanations + optional technical details
- **Actionable remediation** - include AWS CLI fix commands when possible
- **Educational mode** - OWASP/MITRE references in `learn_more` field
- **Rich terminal UI** - use Rich library for tables, panels, colors in reports.py

## Testing AWS Resources Locally

Use `scripts/demo_setup.py` to create real AWS resources with intentional security issues:
- Creates: S3 buckets (unencrypted, no versioning, public access), Knowledge Bases, IAM roles
- Cost: Minimal (< $0.10, usually free tier)
- **Always run cleanup** to avoid ongoing charges

## Common Gotchas

1. **Knowledge Base API**: Requires `bedrock-agent` client, NOT `bedrock` client
2. **AWS Pagination**: Use `paginate_aws_results()` for any list operations to handle >100 resources
3. **Test Mocking**: When adding AWS API calls, update mock clients in `tests/conftest.py`
4. **Config Priority**: CLI args > custom config file > ~/.wilma/config.yaml > defaults
5. **Exit Codes**: Respect the exit code convention for CI/CD integration
6. **Version Sync**: Only update version in `pyproject.toml` - it's the single source of truth
