"""
Report generation for Wilma security checks

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import json
from datetime import datetime
from collections import defaultdict
from typing import List, Dict

from wilma.enums import SecurityMode, RiskLevel


class ReportGenerator:
    """Generate security reports in various formats."""

    def __init__(self, checker):
        """Initialize with a BedrockSecurityChecker instance."""
        self.checker = checker

    def generate_report(self, output_format: str = 'text') -> str:
        """Generate a security report based on the mode."""
        if output_format == 'json':
            return self._generate_json_report()
        else:
            if self.checker.mode == SecurityMode.BEGINNER:
                return self._generate_beginner_report()
            elif self.checker.mode == SecurityMode.EXPERT:
                return self._generate_expert_report()
            else:  # LEARN mode
                return self._generate_learn_report()

    def _generate_beginner_report(self) -> str:
        """Generate a beginner-friendly report with clear guidance."""
        report = []

        # Header
        report.append("\nAWS Bedrock Security Check - Beginner Mode")
        report.append("=" * 50)
        report.append(f"Account: {self.checker.account_id} | Region: {self.checker.region}")
        report.append("")

        # Summary
        critical_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.CRITICAL)
        high_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.HIGH)
        medium_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.MEDIUM)
        low_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.LOW)

        if self.checker.good_practices:
            report.append(f"[PASS] Good News: {len(self.checker.good_practices)} security best practices are properly configured")

        if critical_count > 0:
            report.append(f"[CRITICAL] {critical_count} high-risk issues need immediate attention")
        if high_count > 0:
            report.append(f"[HIGH] {high_count} important issues to address")
        if medium_count > 0:
            report.append(f"[MEDIUM] {medium_count} medium-risk issues found")
        if low_count > 0:
            report.append(f"[LOW] {low_count} low-priority improvements suggested")

        # Good practices
        if self.checker.good_practices:
            report.append("\n[PASS] WHAT'S WORKING WELL:")
            report.append("-" * 30)
            for practice in self.checker.good_practices[:3]:  # Show top 3
                report.append(f"  - {practice['practice']}")

        # Issues by priority
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            level_findings = [f for f in self.checker.findings if f['risk_level'] == risk_level]

            if level_findings:
                report.append(f"\n{risk_level.symbol} {risk_level.label} ISSUES:")
                report.append("-" * 30)

                for i, finding in enumerate(level_findings[:3], 1):  # Limit to top 3 per level
                    report.append(f"\n{i}. {finding['issue']}")
                    report.append(f"   Location: {finding['resource']}")
                    report.append(f"   Risk Score: {finding['risk_score']}/10")
                    report.append(f"   \n   What this means: {finding.get('learn_more', finding['recommendation'])}")

                    if finding.get('fix_command'):
                        report.append(f"   \n   To fix this, run:")
                        report.append(f"   > {finding['fix_command']}")

                if len(level_findings) > 3:
                    report.append(f"\n   ... and {len(level_findings) - 3} more {risk_level.label.lower()} issues")

        # Footer
        report.append("\n" + "-" * 50)
        report.append("[TIPS]")
        report.append("  - Fix critical issues first")
        report.append("  - Run with --expert for technical details")
        report.append("  - Run with --learn to understand each check")
        report.append("  - Run with --fix <issue> for step-by-step remediation")

        return "\n".join(report)

    def _generate_expert_report(self) -> str:
        """Generate a detailed technical report."""
        report = []

        report.append("\n" + "=" * 80)
        report.append("AWS BEDROCK SECURITY CONFIGURATION REPORT - EXPERT MODE")
        report.append("=" * 80)
        report.append(f"Account: {self.checker.account_id}")
        report.append(f"Region: {self.checker.region}")
        report.append(f"Scan Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Total Findings: {len(self.checker.findings)}")
        report.append(f"Good Practices: {len(self.checker.good_practices)}")

        # Detailed findings
        if self.checker.findings:
            report.append("\n" + "-" * 80)
            report.append("DETAILED FINDINGS")
            report.append("-" * 80)

            # Group by category
            findings_by_category = defaultdict(list)
            for finding in self.checker.findings:
                findings_by_category[finding['category']].append(finding)

            for category, category_findings in findings_by_category.items():
                report.append(f"\n[{category}]")
                for finding in category_findings:
                    report.append(f"\n  Risk Level: {finding['risk_level'].label} (Score: {finding['risk_score']}/10)")
                    report.append(f"  Resource: {finding['resource']}")
                    report.append(f"  Issue: {finding['issue']}")
                    report.append(f"  Recommendation: {finding['recommendation']}")

                    if finding.get('technical_details'):
                        report.append(f"  Technical Details: {finding['technical_details']}")

                    if finding.get('fix_command'):
                        report.append(f"  Remediation Command: {finding['fix_command']}")

        # Good practices
        if self.checker.good_practices:
            report.append("\n" + "-" * 80)
            report.append("PROPERLY CONFIGURED SECURITY CONTROLS")
            report.append("-" * 80)
            for practice in self.checker.good_practices:
                report.append(f"  ✓ [{practice['category']}] {practice['practice']}")

        report.append("\n" + "=" * 80)

        return "\n".join(report)

    def _generate_learn_report(self) -> str:
        """Generate an educational report about the security checks."""
        report = []

        report.append("\nAWS Bedrock Security - Learning Mode")
        report.append("=" * 50)
        report.append("\nThis mode explains what each security check does and why it matters.")
        report.append("\nRun without --learn to perform the actual security audit.")

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
                "name": "Cost Monitoring",
                "description": "Alerts you to unusual AI usage that might indicate abuse",
                "example": "Like getting a notification for unusual credit card charges",
                "why_important": "Helps detect compromised credentials or abuse early"
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
