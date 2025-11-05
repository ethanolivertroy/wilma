"""
Security Report Generation

Formats security findings for human-readable and machine-parseable output.

Output Formats:
- Standard Mode (text): User-friendly with simple + technical explanations
- Learn Mode (text): Educational with security concept explanations
- JSON: Machine-parseable for CI/CD integration

Report Structure:
- Summary (counts by risk level, good practices)
- Findings grouped by severity (CRITICAL > HIGH > MEDIUM > LOW)
- Each finding includes: risk score, explanation, technical details, fix command

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import json
from datetime import datetime
from collections import defaultdict
from typing import List, Dict

from wilma.enums import SecurityMode, RiskLevel


class ReportGenerator:
    """
    Formats security findings into readable reports.

    Supports both human-friendly text and machine-parseable JSON.
    """

    def __init__(self, checker):
        """Initialize with BedrockSecurityChecker containing findings."""
        self.checker = checker

    def generate_report(self, output_format: str = 'text') -> str:
        """
        Generate security report in specified format.

        Args:
            output_format: 'text' (default) or 'json'

        Returns:
            Formatted report string
        """
        if output_format == 'json':
            return self._generate_json_report()
        elif self.checker.mode == SecurityMode.LEARN:
            return self._generate_learn_report()
        else:  # STANDARD mode
            return self._generate_standard_report()

    def _generate_standard_report(self) -> str:
        """Generate a comprehensive security report with clear explanations and technical details."""
        report = []

        # Header with ASCII art
        report.append("")
        report.append("    ╦ ╦╦╦  ╔╦╗╔═╗  ┌─┐┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ┬─┐┌─┐┌─┐┌─┐┬─┐┌┬┐")
        report.append("    ║║║║║  ║║║╠═╣  └─┐├┤ │  │ │├┬┘│ │ └┬┘  ├┬┘├┤ ├─┘│ │├┬┘ │ ")
        report.append("    ╚╩╝╩╩═╝╩ ╩╩ ╩  └─┘└─┘└─┘└─┘┴└─┴ ┴  ┴   ┴└─└─┘┴  └─┘┴└─ ┴ ")
        report.append("")
        report.append("=" * 65)
        report.append(f"Account: {self.checker.account_id} | Region: {self.checker.region}")
        report.append("")

        # Summary
        critical_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.CRITICAL)
        high_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.HIGH)
        medium_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.MEDIUM)
        low_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.LOW)

        if self.checker.good_practices:
            report.append(f"[PASS] Well done! {len(self.checker.good_practices)} security best practices are properly configured")

        if critical_count > 0:
            report.append(f"[CRITICAL] {critical_count} critical issue{'s' if critical_count != 1 else ''}")
        if high_count > 0:
            report.append(f"[HIGH] {high_count} high-risk issue{'s' if high_count != 1 else ''}")
        if medium_count > 0:
            report.append(f"[MEDIUM] {medium_count} medium-risk issue{'s' if medium_count != 1 else ''}")
        if low_count > 0:
            report.append(f"[LOW] {low_count} low-priority improvement{'s' if low_count != 1 else ''}")

        # Good practices
        if self.checker.good_practices:
            report.append("\n    ◆ ◇ ◆")
            report.append("\n[PASS] WHAT'S WORKING WELL:")
            report.append("-" * 30)
            for practice in self.checker.good_practices:
                report.append(f"  - {practice['practice']}")

        # Issues by priority - SHOW ALL FINDINGS (not limited)
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            level_findings = [f for f in self.checker.findings if f['risk_level'] == risk_level]

            if level_findings:
                report.append("\n    ◆ ◇ ◆")
                report.append(f"\n{risk_level.symbol} {risk_level.label} ISSUES:")
                report.append("-" * 30)

                for i, finding in enumerate(level_findings, 1):
                    report.append(f"\n{i}. {finding['issue']}")
                    report.append(f"   Location: {finding['resource']}")
                    report.append(f"   Risk Score: {finding['risk_score']}/10")

                    # Show simple explanation
                    if finding.get('learn_more'):
                        report.append(f"   \n   What this means: {finding['learn_more']}")

                    # Show technical details
                    if finding.get('technical_details'):
                        report.append(f"   Technical details: {finding['technical_details']}")

                    # Show recommendation
                    report.append(f"   \n   To fix this, run:")
                    if finding.get('fix_command'):
                        report.append(f"   > {finding['fix_command']}")
                    else:
                        report.append(f"   {finding['recommendation']}")

        # Footer
        report.append("\n    ◆ ◇ ◆")
        report.append("\n" + "-" * 50)
        report.append("[TIPS]")
        report.append("  - Fix critical issues first")
        report.append("  - Run with --learn to understand each check")
        report.append("  - Run with --fix <issue> for step-by-step remediation")
        report.append("\nThere! That wasn't so hard, was it?")

        return "\n".join(report)

    def _generate_learn_report(self) -> str:
        """Generate an educational report about the security checks."""
        report = []

        report.append("\nWilma's Security Education - Learning Mode")
        report.append("=" * 50)
        report.append("\nLet me explain what each security check does and why it matters.")
        report.append("Run without --learn to perform the actual security audit.")

        report.append("\n\nSecurity Checks Explained:\n")

        checks = [
            {
                "name": "Prompt Injection Protection",
                "description": "Prevents attackers from tricking your AI into ignoring its instructions",
                "example": "Like someone trying to convince a security guard to let them in",
                "why_important": "Protects your AI from generating harmful or inappropriate content"
            },
            {
                "name": "Data Privacy Compliance",
                "description": "Ensures personal information (PII) isn't exposed through AI logs or responses",
                "example": "Making sure credit card numbers or SSNs don't appear in logs",
                "why_important": "Helps you comply with privacy laws and protect user data"
            },
            {
                "name": "Cost Anomaly Detection",
                "description": "Monitors AI usage costs to detect potential abuse or compromised credentials",
                "example": "Like getting alerts for unusual credit card charges",
                "why_important": "Catches unauthorized use before it becomes expensive"
            },
            {
                "name": "Model Access Control",
                "description": "Controls who can use your AI models and what they can do",
                "example": "Like having different keys for different rooms in a building",
                "why_important": "Prevents unauthorized use and potential abuse of your AI"
            },
            {
                "name": "Audit Logging",
                "description": "Keeps records of all AI model usage for security and compliance",
                "example": "Like security camera footage - you can review who did what",
                "why_important": "Helps detect abuse and provides evidence for investigations"
            },
            {
                "name": "Network Security",
                "description": "Ensures AI traffic uses private, encrypted connections",
                "example": "Like using a secure tunnel instead of shouting across a room",
                "why_important": "Protects sensitive data from interception"
            },
            {
                "name": "Resource Tagging",
                "description": "Validates that AI resources have proper labels for governance",
                "example": "Like labeling files in a filing cabinet so you can find them",
                "why_important": "Enables cost tracking, access control, and compliance reporting"
            },
            {
                "name": "Knowledge Base S3 Public Access",
                "description": "Prevents public access to S3 buckets containing your knowledge base data",
                "example": "Making sure your filing cabinets aren't left unlocked on the street",
                "why_important": "Stops attackers from injecting malicious documents into your AI's knowledge"
            },
            {
                "name": "Knowledge Base S3 Encryption",
                "description": "Ensures knowledge base documents are encrypted at rest in S3",
                "example": "Like storing documents in a locked safe, not a cardboard box",
                "why_important": "Protects your proprietary data if storage is compromised"
            },
            {
                "name": "Vector Store Encryption",
                "description": "Validates that vector databases (OpenSearch/Aurora) use encryption",
                "example": "Encrypting the index cards in your library catalog",
                "why_important": "Secures the AI embeddings that represent your documents"
            },
            {
                "name": "Vector Store Access Control",
                "description": "Ensures vector databases aren't publicly accessible over the internet",
                "example": "Not leaving your database server open to the whole world",
                "why_important": "Prevents unauthorized access to your AI's embedded knowledge"
            },
            {
                "name": "PII Detection in Embeddings",
                "description": "Scans knowledge base configurations for sensitive personal information",
                "example": "Making sure SSNs and credit cards aren't in the documents you're indexing",
                "why_important": "Prevents accidental exposure of private data through AI responses"
            },
            {
                "name": "Prompt Injection in Documents",
                "description": "Detects malicious instruction patterns in knowledge base source documents",
                "example": "Finding hidden instructions someone snuck into your reference materials",
                "why_important": "Stops indirect attacks where bad documents manipulate AI behavior"
            },
            {
                "name": "Knowledge Base Versioning",
                "description": "Checks if S3 versioning is enabled for knowledge base buckets",
                "example": "Like having undo/redo for your documents",
                "why_important": "Lets you recover from accidental deletions or data poisoning attacks"
            },
            {
                "name": "Knowledge Base IAM Permissions",
                "description": "Audits IAM roles to ensure least-privilege access to knowledge bases",
                "example": "Not giving the janitor keys to the executive suite",
                "why_important": "Limits damage if credentials are compromised"
            },
            {
                "name": "Knowledge Base Chunking Strategy",
                "description": "Reviews how documents are split to prevent information leakage",
                "example": "Making sure sensitive context doesn't bleed between sections",
                "why_important": "Reduces risk of exposing unintended information in AI responses"
            },
            {
                "name": "Knowledge Base Logging",
                "description": "Validates that knowledge base queries and access are being logged",
                "example": "Keeping a logbook of who looked at which documents",
                "why_important": "Enables investigation of suspicious activity or data breaches"
            },
            {
                "name": "Knowledge Base Tagging",
                "description": "Ensures knowledge bases have proper tags for governance",
                "example": "Labeling which project or team owns each knowledge base",
                "why_important": "Critical for cost allocation and access control policies"
            },
            {
                "name": "Embedding Model Access",
                "description": "Checks that embedding models have appropriate access restrictions",
                "example": "Controlling who can use the translator that converts your docs to AI format",
                "why_important": "Prevents unauthorized use of custom or expensive models"
            }
        ]

        for i, check in enumerate(checks, 1):
            report.append(f"{i}. {check['name']}")
            report.append(f"   What it does: {check['description']}")
            report.append(f"   Example: {check['example']}")
            report.append(f"   Why it matters: {check['why_important']}")
            report.append("")

        report.append("-" * 50)
        report.append("Ready to run a real security check? Remove the --learn flag!")

        return "\n".join(report)

    def _generate_json_report(self) -> str:
        """Generate a JSON report with all findings."""
        report_data = {
            'account_id': self.checker.account_id,
            'region': self.checker.region,
            'scan_time': datetime.utcnow().isoformat(),
            'mode': self.checker.mode.value,
            'summary': {
                'total_findings': len(self.checker.findings),
                'critical': sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.CRITICAL),
                'high': sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.HIGH),
                'medium': sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.MEDIUM),
                'low': sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.LOW),
                'good_practices': len(self.checker.good_practices)
            },
            'findings': [
                {
                    'risk_level': f['risk_level'].label,
                    'risk_score': f['risk_score'],
                    'category': f['category'],
                    'resource': f['resource'],
                    'issue': f['issue'],
                    'recommendation': f['recommendation'],
                    'fix_command': f.get('fix_command'),
                    'learn_more': f.get('learn_more'),
                    'technical_details': f.get('technical_details')
                }
                for f in self.checker.findings
            ],
            'good_practices': self.checker.good_practices,
            'available_models': self.checker.available_models
        }

        return json.dumps(report_data, indent=2, default=str)
