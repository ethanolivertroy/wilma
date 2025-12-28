# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Wilma seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Where to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:
- **Security Contact**: Create an issue with the title "SECURITY: [Brief Description]" and mark it as confidential, OR
- **Direct Contact**: Open a private security advisory at https://github.com/ethanolivertroy/wilma/security/advisories/new

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the vulnerability
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Updates**: We will send you regular updates about our progress every 5-7 days
- **Verification**: We will work to verify the vulnerability and determine its impact
- **Fix Timeline**: For confirmed vulnerabilities, we aim to:
  - **Critical**: Patch within 7 days
  - **High**: Patch within 14 days
  - **Medium**: Patch within 30 days
  - **Low**: Patch in next regular release
- **Disclosure**: Once a fix is available, we will:
  - Release a security advisory
  - Credit you for the discovery (unless you prefer to remain anonymous)
  - Publish a CVE if applicable

### Public Disclosure

We follow a coordinated disclosure approach:
1. We will work with you to understand and verify the issue
2. We will develop and test a fix
3. We will prepare a security advisory
4. We will release the fix and advisory simultaneously
5. We ask that you wait for our advisory before publicly disclosing the issue

## Security Best Practices for Users

When using Wilma to audit your AWS Bedrock infrastructure:

### AWS Credentials
- **Never commit AWS credentials** to git repositories
- Use AWS IAM roles when running on AWS infrastructure
- Use temporary credentials (STS) when possible
- Rotate access keys every 90 days
- Apply least-privilege permissions (see README for minimum required permissions)

### Running Wilma
- Always use the latest version from PyPI: `pip install --upgrade wilma-sec`
- Review the output carefully - Wilma only performs read-only operations
- Run in isolated environments when testing
- Use AWS profiles to separate different accounts: `wilma --profile production`

### CI/CD Integration
- Store AWS credentials as encrypted secrets in your CI/CD platform
- Use OIDC/federated authentication when available
- Limit Wilma execution to protected branches
- Review security findings before merging

### Data Handling
- Wilma's output may contain sensitive configuration details
- Do not share raw output publicly without redacting account IDs and resource ARNs
- Use `--output json` for programmatic processing in secure pipelines

## Security Features in Wilma

Wilma is designed with security in mind:

- **Read-Only Operations**: Wilma only uses AWS read/describe/list APIs - it never modifies your infrastructure
- **No Data Exfiltration**: All data stays local - no telemetry or external API calls
- **Offline Capable**: Works without internet connectivity (after installation)
- **Open Source**: All code is auditable (GPL-3.0 license)
- **Minimal Dependencies**: Reduces supply chain attack surface
- **Static Analysis**: Code is scanned with bandit, ruff, and mypy

## Known Security Limitations

### Current Limitations
- **Document Scanning**: Wilma cannot scan the actual content of S3 documents in Knowledge Bases (only metadata)
  - Recommendation: Use Amazon Macie for document-level PII detection
- **Real-time Monitoring**: Wilma is a point-in-time assessment tool, not continuous monitoring
  - Recommendation: Run in CI/CD on schedule or use AWS Config for real-time monitoring
- **Cross-Account**: Wilma checks one AWS account at a time
  - Recommendation: Use AWS Organizations for multi-account governance

### Dependencies
We use Moto for AWS service mocking in tests. While Moto is widely used, it's a testing dependency only and not included in production installations.

## Vulnerability Disclosure History

No vulnerabilities have been reported or disclosed at this time.

## Security Tools

We use the following security tools in our CI/CD pipeline:

- **Bandit**: Python security linter (scans for common vulnerabilities)
- **Ruff**: Fast Python linter with security rules
- **MyPy**: Static type checking
- **OSSF Scorecard**: Security health assessment
- **Dependabot**: Automated dependency updates
- **GitHub CodeQL**: Semantic code analysis (future)

## Contact

For general questions about security in Wilma, please open a GitHub issue with the "security" label.

For reporting vulnerabilities, please follow the reporting process above.

---

**Last Updated**: 2025-12-28
**Version**: 1.2.0
