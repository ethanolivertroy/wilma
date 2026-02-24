# Wilma

Wilma is a **single-purpose AWS CloudShell script** for checking whether your AWS Bedrock setup follows core security best practices.

It is intentionally simple: run one command, get findings, prioritize fixes.

## What Wilma checks

- Bedrock API accessibility in your target region
- CloudTrail multi-region + log file validation posture
- Bedrock Guardrails adoption
- Private networking posture (VPC endpoint for `bedrock-runtime`)
- IAM wildcard policy usage for Bedrock actions

## Quick start (AWS CloudShell)

```bash
python -m pip install wilma-sec
wilma
```

Or run from source:

```bash
git clone https://github.com/ethanolivertroy/wilma
cd wilma
python -m pip install -e .
wilma
```

## Usage

```bash
wilma --region us-east-1
wilma --profile prod-audit --region us-west-2
wilma --json > wilma-report.json
```

## Exit codes

- `0` = no failing checks
- `1` = one or more non-critical failing checks
- `2` = at least one critical failing check

## Notes

- Wilma only reads AWS configuration/state; it does not modify your account.
- Some checks may return `warn` if your role is missing permissions required to audit that control.
