"""
Security Report Generation

Formats security findings for human-readable and machine-parseable output with rich terminal UI.

Output Formats:
- Standard Mode (text): Beautiful terminal UI with tables, panels, and colors
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

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.rule import Rule

from wilma.enums import RiskLevel, SecurityMode


class ReportGenerator:
    """
    Formats security findings into beautiful terminal reports using Rich.

    Supports both human-friendly rich text and machine-parseable JSON.
    """

    def __init__(self, checker):
        """Initialize with BedrockSecurityChecker containing findings."""
        self.checker = checker
        self.console = Console()

    def generate_report(self, output_format: str = 'text') -> str:
        """
        Generate security report in specified format.

        Args:
            output_format: 'text' (default) or 'json'

        Returns:
            Formatted report string (or prints directly for rich text)
        """
        if output_format == 'json':
            return self._generate_json_report()
        elif self.checker.mode == SecurityMode.LEARN:
            self._generate_learn_report_rich()
            return ""  # Rich prints directly
        else:  # STANDARD mode
            self._generate_standard_report_rich()
            return ""  # Rich prints directly

    def _generate_standard_report_rich(self):
        """Generate a beautiful security report using Rich."""
        # Header
        header_text = Text()
        header_text.append("WILMA SECURITY REPORT\n", style="bold cyan")
        header_text.append(f"AWS Bedrock Configuration Checker", style="dim")

        self.console.print(Panel(
            header_text,
            box=box.DOUBLE,
            border_style="cyan",
            padding=(1, 2)
        ))

        # Account info
        info_table = Table.grid(padding=(0, 2))
        info_table.add_column(style="bold")
        info_table.add_column()
        info_table.add_row("Account:", self.checker.account_id)
        info_table.add_row("Region:", self.checker.region)
        info_table.add_row("Scan Time:", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        self.console.print(info_table)
        self.console.print()

        # Summary counts
        critical_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.CRITICAL)
        high_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.HIGH)
        medium_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.MEDIUM)
        low_count = sum(1 for f in self.checker.findings if f['risk_level'] == RiskLevel.LOW)

        # Summary table
        summary = Table(title="Security Summary", box=box.ROUNDED, show_header=True, header_style="bold magenta")
        summary.add_column("Category", style="cyan", width=30)
        summary.add_column("Count", justify="center", width=10)
        summary.add_column("Status", justify="center", width=20)

        if self.checker.good_practices:
            summary.add_row(
                "✓ Good Practices",
                str(len(self.checker.good_practices)),
                Text("PASSING", style="bold green")
            )

        if critical_count > 0:
            summary.add_row(
                "⚠ Critical Issues",
                str(critical_count),
                Text("IMMEDIATE ACTION REQUIRED", style="bold red blink")
            )

        if high_count > 0:
            summary.add_row(
                "◆ High Risk Issues",
                str(high_count),
                Text("ADDRESS SOON", style="bold red")
            )

        if medium_count > 0:
            summary.add_row(
                "▲ Medium Risk Issues",
                str(medium_count),
                Text("PLAN REMEDIATION", style="bold yellow")
            )

        if low_count > 0:
            summary.add_row(
                "◇ Low Priority Items",
                str(low_count),
                Text("BEST PRACTICE", style="bold blue")
            )

        self.console.print(summary)
        self.console.print()

        # Good practices
        if self.checker.good_practices:
            self.console.print(Rule("[bold green]What's Working Well", style="green"))
            practices_table = Table(box=box.SIMPLE, show_header=False)
            practices_table.add_column("", style="green")
            for practice in self.checker.good_practices:
                practices_table.add_row(f"✓ {practice['practice']}")
            self.console.print(practices_table)
            self.console.print()

        # Findings by severity
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            level_findings = [f for f in self.checker.findings if f['risk_level'] == risk_level]

            if level_findings:
                # Color scheme based on risk level
                if risk_level == RiskLevel.CRITICAL:
                    style = "bold red"
                    box_style = "red"
                elif risk_level == RiskLevel.HIGH:
                    style = "bold red"
                    box_style = "red"
                elif risk_level == RiskLevel.MEDIUM:
                    style = "bold yellow"
                    box_style = "yellow"
                else:
                    style = "bold blue"
                    box_style = "blue"

                self.console.print(Rule(f"[{style}]{risk_level.symbol} {risk_level.label} Issues", style=box_style))

                for i, finding in enumerate(level_findings, 1):
                    # Create finding table
                    finding_table = Table(
                        title=f"{i}. {finding['issue']}",
                        box=box.ROUNDED,
                        show_header=False,
                        title_style=style,
                        border_style=box_style,
                        padding=(0, 1)
                    )
                    finding_table.add_column("Field", style="bold", width=18)
                    finding_table.add_column("Value", width=80)

                    finding_table.add_row("Location", finding['resource'])
                    finding_table.add_row("Risk Score", f"{finding['risk_score']}/10")

                    if finding.get('learn_more'):
                        finding_table.add_row("What This Means", finding['learn_more'])

                    if finding.get('technical_details'):
                        finding_table.add_row("Technical Details", finding['technical_details'])

                    # Fix command in a highlighted panel
                    if finding.get('fix_command'):
                        finding_table.add_row(
                            "Fix Command",
                            Text(finding['fix_command'], style="bold cyan on black")
                        )
                    else:
                        finding_table.add_row("Recommendation", finding['recommendation'])

                    self.console.print(finding_table)
                    self.console.print()

        # Footer tips
        tips_panel = Panel(
            Text.from_markup(
                "💡 [bold]Tips:[/bold]\n"
                "  • Fix [bold red]critical[/bold red] issues first\n"
                "  • Run with [cyan]--learn[/cyan] to understand each check\n"
                "  • Run with [cyan]--output json[/cyan] for CI/CD integration\n\n"
                "[dim italic]There! That wasn't so hard, was it?[/dim italic]"
            ),
            title="Next Steps",
            border_style="dim",
            box=box.ROUNDED
        )
        self.console.print(tips_panel)

    def _generate_learn_report_rich(self):
        """Generate an educational report using Rich."""
        # Header
        header = Panel(
            Text("WILMA'S SECURITY EDUCATION - LEARNING MODE", justify="center", style="bold magenta"),
            box=box.DOUBLE,
            border_style="magenta"
        )
        self.console.print(header)
        self.console.print()

        intro = Text()
        intro.append("Let me explain what each security check does and why it matters.\n", style="bold")
        intro.append("Run without ", style="dim")
        intro.append("--learn", style="cyan")
        intro.append(" to perform the actual security audit.\n", style="dim")
        self.console.print(intro)
        self.console.print()

        checks = [
            {
                "name": "Prompt Injection Protection",
                "description": "Prevents attackers from tricking your AI into ignoring its instructions",
                "example": "Like someone trying to convince a security guard to let them in",
                "why_important": "Protects your AI from generating harmful or inappropriate content",
                "owasp": "LLM01"
            },
            {
                "name": "Data Privacy Compliance",
                "description": "Ensures personal information (PII) isn't exposed through AI logs or responses",
                "example": "Making sure credit card numbers or SSNs don't appear in logs",
                "why_important": "Helps you comply with privacy laws and protect user data",
                "owasp": "LLM02"
            },
            {
                "name": "Knowledge Base S3 Security",
                "description": "Protects RAG document storage from unauthorized access and poisoning",
                "example": "Making sure your filing cabinets aren't left unlocked on the street",
                "why_important": "Stops attackers from injecting malicious documents into your AI's knowledge",
                "owasp": "LLM04"
            },
            {
                "name": "Vector Store Encryption",
                "description": "Validates that vector databases (OpenSearch/Aurora) use encryption",
                "example": "Encrypting the index cards in your library catalog",
                "why_important": "Secures the AI embeddings that represent your documents",
                "owasp": "LLM02"
            },
            {
                "name": "Guardrail Configuration",
                "description": "Validates content filtering and safety guardrails are properly configured",
                "example": "Safety rails that prevent the AI from saying dangerous things",
                "why_important": "Critical defense against prompt injection and harmful outputs",
                "owasp": "LLM01"
            },
            {
                "name": "IAM Access Control",
                "description": "Ensures only authorized users and services can access Bedrock",
                "example": "Like having different keys for different rooms in a building",
                "why_important": "Prevents unauthorized use and potential abuse of your AI",
                "owasp": "LLM06"
            },
            {
                "name": "Audit Logging",
                "description": "Keeps records of all AI model usage for security and compliance",
                "example": "Like security camera footage - you can review who did what",
                "why_important": "Helps detect abuse and provides evidence for investigations",
                "owasp": "LLM10"
            },
            {
                "name": "Network Security",
                "description": "Ensures AI traffic uses private, encrypted connections via VPC",
                "example": "Like using a secure tunnel instead of shouting across a room",
                "why_important": "Protects sensitive data from interception",
                "owasp": "LLM06"
            }
        ]

        for i, check in enumerate(checks, 1):
            check_table = Table(
                title=f"{i}. {check['name']}",
                box=box.ROUNDED,
                show_header=False,
                title_style="bold cyan",
                border_style="cyan"
            )
            check_table.add_column("", style="bold dim", width=20)
            check_table.add_column("", width=70)

            check_table.add_row("What it does:", check['description'])
            check_table.add_row("Example:", Text(check['example'], style="italic"))
            check_table.add_row("Why it matters:", Text(check['why_important'], style="green"))
            check_table.add_row("OWASP LLM:", Text(check['owasp'], style="bold magenta"))

            self.console.print(check_table)
            self.console.print()

        # Footer
        footer = Panel(
            Text.from_markup(
                "[bold cyan]Ready to run a real security check?[/bold cyan]\n\n"
                "Remove the [yellow]--learn[/yellow] flag and I'll scan your AWS Bedrock configuration:\n"
                "  [cyan]wilma[/cyan]\n\n"
                "Or check out the comprehensive wiki:\n"
                "  [cyan]https://github.com/ethanolivertroy/wilma/wiki[/cyan]"
            ),
            title="Next Steps",
            border_style="green",
            box=box.ROUNDED
        )
        self.console.print(footer)

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
