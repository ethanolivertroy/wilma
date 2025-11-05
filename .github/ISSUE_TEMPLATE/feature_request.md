---
name: Feature Request
about: Suggest a new security check or feature for Wilma
title: '[FEATURE] '
labels: enhancement, needs-triage
assignees: ''

---

## Feature Description
A clear and concise description of the security check or feature you'd like to see.

## Security Impact
**Which OWASP LLM Top 10 category does this address?**
- [ ] LLM01: Prompt Injection
- [ ] LLM02: Insecure Output Handling
- [ ] LLM03: Training Data Poisoning
- [ ] LLM04: Model Denial of Service
- [ ] LLM05: Supply Chain Vulnerabilities
- [ ] LLM06: Sensitive Information Disclosure
- [ ] LLM07: Insecure Plugin Design
- [ ] LLM08: Excessive Agency
- [ ] LLM09: Overreliance
- [ ] LLM10: Model Theft
- [ ] Other/Not applicable

**Which MITRE ATLAS technique does this address?**
- [ ] AML.T0051: LLM Prompt Injection
- [ ] AML.T0020: Poison Training Data
- [ ] AML.T0024: Backdoor ML Model
- [ ] AML.T0043: Craft Adversarial Data
- [ ] Other (please specify): ___________

**Risk Level:**
- [ ] Critical (9-10)
- [ ] High (7-8)
- [ ] Medium (4-6)
- [ ] Low (1-3)

## AWS Bedrock Component
Which AWS Bedrock component does this feature relate to?
- [ ] Agents
- [ ] Knowledge Bases (RAG)
- [ ] Guardrails
- [ ] Model Fine-Tuning
- [ ] Flows
- [ ] Model Invocation Logging
- [ ] IAM & Permissions
- [ ] Other: ___________

## Use Case
Describe the security scenario or misconfiguration this feature would detect.

**Example:**
"An agent configured without requireConfirmation=ENABLED could execute dangerous Lambda functions without human approval, leading to unauthorized actions in the AWS environment."

## Proposed Implementation
If you have ideas about how this check should work, please share them here.

## Detection Criteria
What should trigger this security finding?

## Remediation
What action should users take to fix this issue?

## Additional Context
Add any other context, screenshots, AWS documentation links, or examples about the feature request.

## Related Issues
Are there any related issues or features?

---

**Note:** See [ROADMAP.md](../../ROADMAP.md) for our current feature priorities and implementation timeline.
