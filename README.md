# Wilma - AWS Bedrock Security Configuration Checker
[![PyPI version](https://badge.fury.io/py/wilma-sec.svg)](https://pypi.org/project/wilma-sec/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security Audit](https://img.shields.io/badge/Security-Audit%20Tool-red)](https://github.com/ethanolivertroy/wilma)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-darkblue)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![AWS](https://img.shields.io/badge/AWS-Security%20Best%20Practices-orange)](https://aws.amazon.com/security/)
[![Tests](https://github.com/ethanolivertroy/wilma/actions/workflows/test.yml/badge.svg)](https://github.com/ethanolivertroy/wilma/actions/workflows/test.yml)
[![Publish](https://github.com/ethanolivertroy/wilma/actions/workflows/publish.yml/badge.svg)](https://github.com/ethanolivertroy/wilma/actions/workflows/publish.yml)
[![OSSF Scorecard](https://api.scorecard.dev/projects/github.com/ethanolivertroy/wilma/badge)](https://scorecard.dev/viewer/?uri=github.com/ethanolivertroy/wilma)

![Wilma Logo](wilma-logo.jpg)


## Enhanced with GenAI-Specific Security Features

A comprehensive security auditing tool for AWS Bedrock that combines traditional cloud security best practices with cutting-edge GenAI security capabilities. Perfect for organizations adopting generative AI while maintaining enterprise security standards.


## Key Features for GenAI Security

### GenAI-Specific Security Checks
- **Prompt Injection Detection**: Identifies vulnerabilities to prompt manipulation attacks
- **Data Privacy Compliance**: Detects PII exposure risks in model interactions
- **Model Poisoning Detection**: Monitors for signs of compromised training data
- **Cost Anomaly Detection**: Alerts on unusual usage patterns indicating potential abuse
- **Guardrail Validation**: Ensures content filtering and safety measures are in place

### User-Friendly Design
- **Standard Mode** (default): Clear explanations with both simple and technical details
- **Learning Mode**: Educational content about each security check

## Prerequisites & Setup

### AWS Authentication Setup

This tool requires AWS credentials to access your Bedrock resources. 

#### Quick Setup via AWS Console

1. **Create IAM User**
   - Go to [AWS IAM Console](https://console.aws.amazon.com/iam/)
   - Click "Users" → "Create user"
   - Name it `wilma-security-checker`
   - Select "Programmatic access"

2. **Set Permissions**
   - Choose "Attach existing policies directly"
   - Either use "PowerUserAccess" OR create a custom policy with:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:List*",
                "bedrock:Get*",
                "bedrock:Describe*",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "logs:DescribeLogGroups",
                "ec2:DescribeVpcEndpoints",
                "s3:GetBucketEncryption",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

3. **Save Credentials**
   - Download CSV or copy Access Key ID and Secret Access Key
   - WARNING: You won't see the secret key again!

#### Configure Your Local Machine

**Option 1: AWS CLI (Recommended)**
```bash
aws configure
# Enter your Access Key ID
# Enter your Secret Access Key
# Enter default region: us-east-1
# Enter default output: json
```

**Option 2: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID="your-access-key-here"
export AWS_SECRET_ACCESS_KEY="your-secret-key-here"
export AWS_DEFAULT_REGION="us-east-1"
```

**Option 3: AWS Profile**
```bash
# Add to ~/.aws/credentials
[bedrock-checker]
aws_access_key_id = your-access-key
aws_secret_access_key = your-secret-key

# Use with: wilma --profile bedrock-checker
```

### Supported AWS Regions

Bedrock is available in:
- US East (N. Virginia) - `us-east-1`
- US West (Oregon) - `us-west-2`
- Asia Pacific (Singapore) - `ap-southeast-1`
- Asia Pacific (Tokyo) - `ap-northeast-1`
- Europe (Frankfurt) - `eu-central-1`
- Europe (Ireland) - `eu-west-1`

### Security Best Practices

- Never commit AWS credentials to git
- Use IAM roles when on AWS infrastructure
- Apply least privilege permissions
- Rotate access keys every 90 days
- Enable MFA on your AWS account

## Quick Start

### Installation

**Option 1: Install from PyPI (Recommended)**
```bash
pip install wilma-sec

# Or with uv
uv pip install wilma-sec

# Run directly from command line
wilma
```

**Option 2: Install from Source**
```bash
git clone https://github.com/ethanolivertroy/wilma.git
cd wilma
pip install -e .

# Or manually install dependencies
pip install -r requirements.txt
wilma
```

### Usage

```bash
# Run security check (default mode)
wilma

# Learning mode - understand the security checks
wilma --learn

# Output as JSON for CI/CD integration
wilma --output json

# Use specific AWS profile
wilma --profile production

# Check specific region
wilma --region us-west-2
```

## Testing Locally

Want to test Wilma with real AWS resources? We've got you covered!

Use the included demo script to create sample AWS Bedrock resources with intentional security issues:

```bash
# Install Wilma first
pip install -e .

# Create demo resources (with security issues)
python scripts/demo_setup.py --setup --region us-east-1

# Run Wilma to detect the issues
python scripts/demo_setup.py --test

# Clean up all demo resources
python scripts/demo_setup.py --cleanup

# Or do all three steps at once
python scripts/demo_setup.py --all --confirm
```

**What the demo creates:**
- S3 bucket without encryption (HIGH risk)
- S3 bucket without versioning (MEDIUM risk)
- S3 bucket without Block Public Access (CRITICAL risk)
- Knowledge Base without proper tags (LOW risk)
- IAM role with permissions for testing

**Cost:** Minimal (usually free tier eligible, < $0.10)

**Important:** Remember to run cleanup to avoid ongoing charges!

### Current Security Check Coverage

**Knowledge Bases (RAG) - 12 checks:**
- S3 bucket public access validation (CRITICAL)
- S3 bucket encryption verification (HIGH)
- Vector store encryption (OpenSearch, Aurora, RDS) (HIGH)
- Vector store access control (CRITICAL)
- PII pattern detection in configurations (HIGH)
- Prompt injection pattern detection (HIGH)
- S3 versioning validation (MEDIUM)
- IAM role permission audit (HIGH)
- Chunking configuration review (LOW)
- CloudWatch logging validation (MEDIUM)
- Resource tagging compliance (LOW)
- Embedding model access control (MEDIUM)

**Coming Soon:**
- AWS Bedrock Agents security (10 checks)
- Advanced Guardrails validation (11 checks)
- Model Fine-Tuning security (11 checks)

## Example Output

```
AWS Bedrock Security Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Good News: 3 security best practices are properly configured
Critical: 1 high-risk issue needs immediate attention
Attention Needed: 2 medium-risk issues found

CRITICAL ISSUES:
─────────────────────────
1. Policy allows unrestricted access to ALL Bedrock operations
   Where: IAM Policy: BedrockAdminPolicy
   Risk Score: 9/10

   What this means: This is like giving someone admin access to all your AI models
   Technical details: Policy contains wildcard actions (bedrock:*) with no resource restrictions

   To fix this, run:
   > aws iam create-policy-version --policy-arn arn:aws:iam::123456789012:policy/BedrockAdminPolicy --policy-document file://restricted-policy.json --set-as-default
```

## Security Checks Performed

### Traditional Security
- IAM permission auditing
- Encryption validation
- Network security (VPC endpoints)
- Audit logging configuration
- Resource tagging compliance

### GenAI-Specific Security
- Prompt injection vulnerability assessment
- PII detection in model configurations
- Model access pattern analysis
- Usage anomaly detection setup
- Real-time threat monitoring

### Knowledge Bases (RAG) Security - NEW!
- **S3 Data Source Security**: Public access blocking, encryption, versioning
- **Vector Store Security**: Encryption and access control for OpenSearch/Aurora/RDS
- **PII Detection**: Pattern-based scanning of configurations and metadata
- **Prompt Injection Detection**: Identifies suspicious patterns in KB content
- **Access Control**: IAM role and policy validation
- **Configuration Review**: Chunking strategies, logging, and tagging compliance

## Architecture

The tool is designed with modularity and extensibility in mind:

```
wilma/
├── Security Checks
│   ├── Traditional AWS Security
│   └── GenAI-Specific Security
├── Reporting Modes
│   ├── Standard (default)
│   └── Learning
└── Output Formats
    ├── Human-readable text
    └── JSON for automation
```

## DevSecOps Integration

### CI/CD Pipeline Example

```yaml
# .github/workflows/bedrock-security.yml
name: Bedrock Security Audit
on: [push, pull_request]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Run Bedrock Security Audit
        run: |
          pip install wilma-sec
          wilma --output json > security-report.json
          
          # Fail the build if critical issues found
          if [ $? -eq 2 ]; then
            echo "Critical security issues detected!"
            cat security-report.json
            exit 1
          fi
```

## Risk Scoring System

The tool uses a simple 1-10 risk scoring system:

- **9-10**: Critical - Immediate action required
- **7-8**: High - Address within 24 hours
- **4-6**: Medium - Plan remediation
- **1-3**: Low - Best practice improvements

## GenAI Threat Model Coverage

Based on OWASP Top 10 for LLMs and MITRE ATLAS:

| Threat Category | Coverage | Detection Method |
|----------------|----------|------------------|
| Prompt Injection | Yes | Pattern matching & guardrail checks |
| Data Poisoning | Yes | Training source validation |
| Model Theft | Yes | Access pattern analysis |
| PII Leakage | Yes | Content scanning |
| Denial of Service | Yes | Cost & rate monitoring |
| Supply Chain | Partial | Basic model source verification |

## Learning Mode

To understand the security concepts and checks performed:

```bash
wilma --learn
```

This explains:
- Prompt injection detection techniques
- PII pattern recognition
- Model access control principles
- Audit logging importance
- Network security for AI
- Cost monitoring for abuse detection

## Contributing

We welcome contributions! Areas of interest:
- Additional GenAI attack patterns
- Integration with more AWS services
- Support for other cloud providers
- Enhanced remediation automation

### Development Setup
```bash
# Clone and install in development mode
git clone https://github.com/ethanolivertroy/wilma.git
cd wilma

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run linting
ruff check src/ tests/

# Run security scan
bandit -r src/

# Format code
ruff format src/ tests/
```

### Releasing New Versions
Releases are automated via GitHub Actions:
- Version changes in `pyproject.toml` trigger automatic PyPI publishing
- All tests must pass before publishing
- Git tags are automatically created
- See `.github/workflows/publish.yml` for workflow details

## Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:List*",
                "bedrock:Get*",
                "bedrock:Describe*",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "logs:DescribeLogGroups",
                "ec2:DescribeVpcEndpoints",
                "s3:GetBucketEncryption",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Why This Tool Stands Out

1. **Dual Focus**: Combines traditional cloud security with GenAI-specific risks
2. **Accessibility**: Beginner-friendly without sacrificing technical depth
3. **Actionable**: Provides exact commands to fix issues
4. **Educational**: Learning mode helps teams understand GenAI security
5. **Automated**: JSON output enables CI/CD integration
6. **Comprehensive**: Covers the full spectrum of Bedrock security concerns

## Troubleshooting

### Common Issues

#### "Unable to locate credentials"
```bash
# Check if AWS CLI is configured
aws configure list

# If not configured, run:
aws configure
```

#### "You must specify a region"
```bash
# Set default region
export AWS_DEFAULT_REGION=us-east-1

# Or specify in command
wilma --region us-east-1
```

#### "Access Denied" errors
Ensure your IAM user/role has the required permissions listed in the IAM Permissions section above.

#### Testing without AWS Account
While the main security checker requires AWS credentials, you can:
1. Use the learning mode to understand security concepts: `wilma --learn`
2. Review the documentation in this README
3. Use the tool with read-only IAM credentials to explore safely

#### "command not found: wilma" after pip install
If pip installed the package but the command isn't found:

```bash
# Option 1: Add Python user bin to PATH
echo 'export PATH="$HOME/Library/Python/3.11/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Option 2: Use the full path
~/Library/Python/3.11/bin/wilma

# Option 3: Create an alias
echo 'alias wilma="$HOME/Library/Python/3.11/bin/wilma"' >> ~/.zshrc
source ~/.zshrc

# Option 4: Install with pipx (recommended for CLI tools)
pipx install wilma-sec
```

## Project History

Wilma evolved from my earlier AWS Bedrock Security Configuration Checker project. After extensive use and feedback from the community, I rebuilt it from the ground up with a focus on:

- **Cleaner Architecture**: Modular design replacing the original monolithic structure
- **Professional Output**: Text-based status indicators instead of emojis for better terminal compatibility
- **Better Maintainability**: Separated concerns with dedicated modules for different security checks
- **Enhanced Usability**: Streamlined installation and CLI experience

The rebranding to "Wilma" represents this fresh start while maintaining the core security-first approach that made the original tool valuable.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See the [LICENSE](LICENSE) file for details.

---

**Built by ET for the GenAI security community**
