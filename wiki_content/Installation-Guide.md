# Installation Guide

Get Wilma running in under 5 minutes.

## Quick Start (Recommended)

```bash
# Install from PyPI
pip install wilma-sec

# Run your first security scan
wilma

# That's it! 🎉
```

---

## Prerequisites

### 1. Python 3.10+

```bash
# Check your Python version
python --version  # Should be 3.10 or higher

# If needed, install Python 3.10+
# macOS (Homebrew):
brew install python@3.11

# Ubuntu/Debian:
sudo apt update && sudo apt install python3.11

# Windows:
# Download from https://www.python.org/downloads/
```

### 2. AWS Credentials

Wilma needs read access to your AWS Bedrock resources.

**Option A: AWS CLI (Easiest)**
```bash
# Configure AWS CLI
aws configure
# Enter:
#   AWS Access Key ID: YOUR_ACCESS_KEY
#   AWS Secret Access Key: YOUR_SECRET_KEY
#   Default region: us-east-1
#   Default output format: json

# Test it works
aws sts get-caller-identity
```

**Option B: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

**Option C: AWS CloudShell (Zero Setup!)**
```bash
# 1. Open AWS Console
# 2. Click CloudShell icon (bottom-left)
# 3. Wait for shell to load
# 4. Credentials are automatically configured!

pip install wilma-sec
wilma
```

### 3. Required IAM Permissions

Wilma needs **read-only** access. Minimum required permissions:

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
        "bedrock-agent:List*",
        "bedrock-agent:Get*",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "logs:DescribeLogGroups",
        "ec2:DescribeVpcEndpoints",
        "aoss:ListCollections",
        "aoss:BatchGetCollection",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**⚠️ Note**: Wilma never modifies resources, only reads configurations.

---

## Installation Methods

### Method 1: PyPI (Recommended for Users)

```bash
# Standard installation
pip install wilma-sec

# Verify installation
wilma --version
# Output: wilma 1.1.0
```

**Upgrade to latest version**:
```bash
pip install --upgrade wilma-sec
```

### Method 2: From Source (Recommended for Developers)

```bash
# Clone repository
git clone https://github.com/ethanolivertroy/wilma.git
cd wilma

# Install in development mode
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run linting
ruff check src/ tests/
```

### Method 3: Using pipx (Isolated Installation)

```bash
# Install pipx if you don't have it
python -m pip install --user pipx
python -m pipx ensurepath

# Install Wilma in isolated environment
pipx install wilma-sec

# Wilma is now available globally
wilma
```

### Method 4: AWS CloudShell (Zero Local Setup)

```bash
# 1. Open AWS Console → CloudShell
# 2. Install Wilma:
pip install wilma-sec

# 3. Run scan:
wilma

# 4. Export results:
wilma --output json > security-report.json

# 5. Download report:
# Actions → Download file → security-report.json
```

---

## First Run

### Basic Scan

```bash
# Scan default region (from AWS config)
wilma

# Output:
# AWS Bedrock Security Check
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Region: us-east-1
# Account: 123456789012
#
# Good News: 8 security best practices are properly configured
# Critical: 2 high-risk issues need immediate attention
# Attention Needed: 3 medium-risk issues found
# ...
```

### Scan Specific Region

```bash
# Bedrock is available in multiple regions
wilma --region us-west-2
wilma --region eu-central-1
wilma --region ap-northeast-1
```

### Learning Mode

```bash
# Educational mode - learn about each security check
wilma --learn

# Output includes:
# - What each check does
# - Why it matters
# - How attacks work
# - How to fix issues
```

### Export Results

```bash
# JSON format (for CI/CD, SIEM, etc.)
wilma --output json > security-report.json

# Pretty-printed JSON
wilma --output json | jq '.'

# Save to file
wilma > security-report.txt
```

### Use AWS Profile

```bash
# If you have multiple AWS profiles
wilma --profile production
wilma --profile dev
wilma --profile staging
```

---

## Troubleshooting

### "command not found: wilma"

**Problem**: pip installed to user directory not in PATH

**Solution**:
```bash
# Option 1: Add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Option 2: Run with full path
~/.local/bin/wilma

# Option 3: Use pipx (recommended)
pipx install wilma-sec
```

### "Unable to locate credentials"

**Problem**: No AWS credentials configured

**Solution**:
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_DEFAULT_REGION="us-east-1"

# Verify
aws sts get-caller-identity
```

### "You must specify a region"

**Problem**: No default region set

**Solution**:
```bash
# Option 1: Set default region
aws configure set region us-east-1

# Option 2: Use --region flag
wilma --region us-east-1

# Option 3: Environment variable
export AWS_DEFAULT_REGION=us-east-1
```

### "Access Denied" errors

**Problem**: IAM user/role lacks required permissions

**Solution**:
```bash
# Check current permissions
aws iam get-user
aws sts get-caller-identity

# Attach read-only Bedrock policy (ask your admin)
# Or use the minimal policy shown in Prerequisites section
```

### "No Knowledge Bases found"

**Problem**: No Bedrock resources in the region

**This is normal!** If you haven't created any Bedrock resources yet:
```bash
# Run in learning mode to understand what Wilma checks
wilma --learn

# Or test with a different region
wilma --region us-west-2
```

---

## Next Steps

Now that Wilma is installed:

1. **[Understanding Wilma Output](Understanding-Wilma-Output)** - Interpret security findings
2. **[GenAI Security Fundamentals](GenAI-Security-Fundamentals)** - Learn about threats
3. **[Remediation Workflows](Remediation-Workflows)** - Fix vulnerabilities
4. **[CI/CD Integration](CI-CD-Integration)** - Automate security scans

---

## Uninstallation

```bash
# Remove Wilma
pip uninstall wilma-sec

# Or with pipx
pipx uninstall wilma-sec
```

---

[← Home](Home) | [Understanding Wilma Output →](Understanding-Wilma-Output)
