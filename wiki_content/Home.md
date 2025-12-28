# Wilma Security Wiki

Welcome to the Wilma Security Wiki - your guide to understanding and securing AWS Bedrock deployments.

## What is Wilma?

Wilma is an AWS Bedrock security configuration checker that helps you identify and fix security vulnerabilities in your GenAI deployments. Unlike traditional cloud security tools, Wilma focuses on threats unique to Large Language Models and generative AI systems.

## Why GenAI Security is Different

Traditional application security focuses on SQL injection, XSS, and authentication bypasses. GenAI introduces entirely new attack vectors:

- **Prompt Injection**: Attackers manipulate AI behavior through crafted inputs
- **Data Poisoning**: Compromising training data or RAG knowledge bases
- **Model Extraction**: Stealing your fine-tuned models
- **Excessive Agency**: AI agents performing unauthorized actions
- **PII Leakage**: Models memorizing and exposing sensitive data

Wilma checks for these and 40+ other GenAI-specific security issues.

## Quick Links

### Understanding the Threats
- [GenAI Security Fundamentals](GenAI-Security-Fundamentals) - Start here if you're new
- [OWASP LLM Top 10](OWASP-LLM-Top-10) - The industry standard threat model
- [MITRE ATLAS Framework](MITRE-ATLAS-Framework) - Advanced AI threat tactics
- [Real-World Attack Examples](Real-World-Attack-Examples) - Learn from actual incidents

### AWS Bedrock Security Deep Dives
- [Knowledge Bases (RAG) Security](Knowledge-Bases-RAG-Security) - 12 security checks explained
- [Guardrails Security](Guardrails-Security) - Content filtering and protection
- [Agents Security](Agents-Security) - Securing AI agents with tools
- [Fine-Tuning Security](Fine-Tuning-Security) - Protecting custom model training

### Using Wilma
- [Installation Guide](Installation-Guide) - Get started in 5 minutes
- [Understanding Wilma Output](Understanding-Wilma-Output) - Interpret security findings
- [Remediation Workflows](Remediation-Workflows) - Fix vulnerabilities step-by-step
- [CloudShell Guide](CloudShell-Guide) - Running Wilma in AWS CloudShell
- [CI/CD Integration](CI-CD-Integration) - Automate security scanning

### Security Best Practices
- [AWS Bedrock Security Checklist](AWS-Bedrock-Security-Checklist)
- [Compliance Frameworks](Compliance-Frameworks) - SOC 2, HIPAA, GDPR
- [Security Architecture Patterns](Security-Architecture-Patterns)
- [Incident Response for GenAI](Incident-Response-GenAI)

## Educational Philosophy

This wiki teaches **why** things are insecure, not just **what** to fix. Each security check includes:

1. **The Threat**: What attack does this prevent?
2. **Real-World Impact**: What happens if exploited?
3. **How Attackers Think**: Understanding the attacker's perspective
4. **Defense in Depth**: Why multiple layers matter
5. **Remediation**: Concrete steps to fix the issue

## Contributing

Found a gap in our security coverage? Have a real-world attack example to share? [Contribute to Wilma on GitHub](https://github.com/ethanolivertroy/wilma).

## License

Wilma is free and open source under GPL v3. Built by [Ethan Troy](https://github.com/ethanolivertroy) for the GenAI security community.

---

**Start Learning**: [GenAI Security Fundamentals →](GenAI-Security-Fundamentals)
