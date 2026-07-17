"""
Security report generation for Wilma.

Reports are built from the versioned assessment schema in wilma.assessment so
text output and JSON output describe the same posture result.
"""

import io
import json
import sys
from datetime import datetime, timezone
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from wilma.assessment import (
    BEDROCK_SECURITY_INDICATORS,
    MANUAL_EVIDENCE_ITEMS,
    AssessmentBuilder,
)
from wilma.enums import RiskLevel

# Presentation themes change terminal styling only; evidence, scores, JSON
# output, and exit codes are identical across themes.
REPORT_THEMES = {
    "standard": {
        "title": "WILMA BEDROCK SECURITY POSTURE ASSESSMENT",
        "subtitle": "AWS Bedrock security best-practice and framework-mapped assessment",
        "border_style": "cyan",
        "score_title": "Posture Summary",
        "score_label": "Bedrock Security Posture: {rating} ({score}/100)",
        "footer_note": None,
    },
    "yabba_dabba_doo": {
        "title": "WILMA'S BEDROCK STONE TABLET",
        "subtitle": "Yabba Dabba Doo mode - same evidence, more fun",
        "border_style": "magenta",
        "score_title": "Stone Tablet Summary",
        "score_label": "Fred, your Bedrock Security Posture is {rating} ({score}/100)",
        "footer_note": (
            "Yabba Dabba Doo mode changed presentation only; "
            "evidence, score, and exit codes are unchanged."
        ),
    },
}


class ReportGenerator:
    """
    Formats Wilma assessments for terminal and JSON output.

    Rich text can be emitted to stdout or captured for --output-file. JSON is
    always returned as a string.
    """

    def __init__(self, checker=None, presentation_mode: str = "standard", emit: bool = True):
        self.checker = checker
        self.theme = REPORT_THEMES[presentation_mode]
        self._buffer = None if emit else io.StringIO()
        self.console = Console(file=self._buffer or sys.stdout, record=True)

    def generate_report(self, output_format: str = "text", explain: bool = False) -> str:
        """
        Generate a report in the specified format.

        Args:
            output_format: "text" or "json".
            explain: Render the auditor-oriented explanation view instead of a scan result.
        """
        if explain:
            self._generate_explain_report_rich()
            return self.console.export_text()

        if output_format == "json":
            return self._generate_json_report()

        self._generate_standard_report_rich()
        return self.console.export_text()

    def _assessment(self) -> dict[str, Any]:
        return AssessmentBuilder(self.checker).build()

    def _generate_standard_report_rich(self):
        assessment = self._assessment()
        score = assessment["posture_score"]
        confidence = assessment["assessment_confidence"]
        summary = assessment["summary"]

        border_style = self.theme["border_style"]
        header_text = Text()
        header_text.append(f"{self.theme['title']}\n", style=f"bold {border_style}")
        header_text.append(self.theme["subtitle"], style="dim")
        self.console.print(Panel(header_text, box=box.DOUBLE, border_style=border_style, padding=(1, 2)))

        self._print_account_context(assessment)
        self._print_score_summary(score, confidence, summary)
        self._print_indicator_scorecard(assessment["bedrock_security_indicators"])
        self._print_good_practices(assessment["good_practices"])
        self._print_findings(assessment["findings"])
        self._print_manual_evidence(assessment["manual_evidence_needed"])
        self._print_footer()

    def _print_account_context(self, assessment: dict[str, Any]):
        info_table = Table.grid(padding=(0, 2))
        info_table.add_column(style="bold")
        info_table.add_column()
        info_table.add_row("Account:", str(assessment.get("account_id") or "unknown"))
        info_table.add_row("Region:", str(assessment.get("region") or "unknown"))
        info_table.add_row("Scan Time:", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
        info_table.add_row("Schema:", assessment["schema_version"])
        self.console.print(info_table)
        self.console.print()

    def _print_score_summary(self, score: dict[str, Any], confidence: dict[str, Any], summary: dict[str, Any]):
        score_label = self.theme["score_label"].format(rating=score["rating"], score=score["score"])

        score_table = Table(title=self.theme["score_title"], box=box.ROUNDED, show_header=True, header_style="bold cyan")
        score_table.add_column("Metric", style="bold", width=28)
        score_table.add_column("Value", width=68)
        score_table.add_row("Posture Score", score_label)
        score_table.add_row(
            "Assessment Confidence",
            f"{confidence['rating']} ({confidence['score']}%) - {confidence['assessed_indicators']}/{confidence['total_indicators']} indicators assessed",
        )
        score_table.add_row(
            "Finding Counts",
            (
                f"{summary['critical']} critical, {summary['high']} high, "
                f"{summary['medium']} medium, {summary['low']} low"
            ),
        )
        score_table.add_row("Audit Readiness", "Incomplete - manual evidence checklist generated")
        score_table.add_row("Main Drivers", "; ".join(score["drivers"]))
        self.console.print(score_table)
        self.console.print()

        if confidence["blind_spots"]:
            blind_spots = ", ".join(item["indicator"] for item in confidence["blind_spots"])
            self.console.print(Panel(
                Text(f"Blind spots: {blind_spots}", style="bold yellow"),
                title="Assessment Confidence",
                border_style="yellow",
                box=box.ROUNDED,
            ))
            self.console.print()

    def _print_indicator_scorecard(self, indicators: list[dict[str, Any]]):
        table = Table(title="Bedrock Security Indicators", box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("Indicator", style="cyan", width=32)
        table.add_column("Score", justify="center", width=8)
        table.add_column("Status", width=20)
        table.add_column("Confidence", justify="center", width=12)
        table.add_column("Findings", justify="center", width=10)

        for indicator in indicators:
            score = "n/a" if indicator["score"] is None else str(indicator["score"])
            style = self._status_style(indicator["status"])
            table.add_row(
                indicator["name"],
                score,
                Text(indicator["status"], style=style),
                indicator["confidence"],
                str(indicator["finding_count"]),
            )

        self.console.print(table)
        self.console.print()

    def _print_good_practices(self, good_practices: list[dict[str, Any]]):
        if not good_practices:
            return

        self.console.print(Rule("[bold green]What Is Working", style="green"))
        practices_table = Table(box=box.SIMPLE, show_header=False)
        practices_table.add_column("", style="green")
        for practice in good_practices:
            category = practice.get("category", "Good Practice")
            practices_table.add_row(f"{category}: {practice.get('practice', '')}")
        self.console.print(practices_table)
        self.console.print()

    def _print_findings(self, findings: list[dict[str, Any]]):
        if not findings:
            self.console.print(Panel(
                Text("No automated security findings were recorded.", style="bold green"),
                title="Findings",
                border_style="green",
                box=box.ROUNDED,
            ))
            self.console.print()
            return

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for severity in severity_order:
            severity_findings = [finding for finding in findings if finding["severity"] == severity]
            if not severity_findings:
                continue

            style = self._severity_style(severity)
            self.console.print(Rule(f"[{style}]{severity} Findings", style=style.split()[-1]))
            for index, finding in enumerate(severity_findings, 1):
                finding_table = Table(
                    title=f"{index}. {finding['title']}",
                    box=box.ROUNDED,
                    show_header=False,
                    title_style=style,
                    border_style=style.split()[-1],
                    padding=(0, 1),
                )
                finding_table.add_column("Field", style="bold", width=18)
                finding_table.add_column("Value", width=88)

                finding_table.add_row("Indicator", finding["indicator"])
                finding_table.add_row("Resource", finding["resource"])
                finding_table.add_row("Risk Score", f"{finding['risk_score']}/10")
                finding_table.add_row("Why It Matters", finding["description"])
                finding_table.add_row("Recommendation", finding["recommendation"])

                frameworks = finding.get("framework_mappings", {})
                mapped = self._format_frameworks(frameworks)
                if mapped:
                    finding_table.add_row("Mapped To", mapped)

                details = finding.get("technical_details")
                if details:
                    finding_table.add_row("Technical Details", str(details))

                if finding.get("fix_command"):
                    finding_table.add_row("Fix Command", Text(str(finding["fix_command"]), style="bold cyan"))

                self.console.print(finding_table)
                self.console.print()

    def _print_manual_evidence(self, manual_items: list[dict[str, Any]]):
        self.console.print(Rule("[bold yellow]Manual Evidence Needed", style="yellow"))
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold yellow")
        table.add_column("Indicator", style="cyan", width=30)
        table.add_column("Evidence", width=58)
        table.add_column("Frameworks", width=28)

        for item in manual_items[:8]:
            table.add_row(
                item["indicator"],
                item["evidence"],
                ", ".join(item["frameworks"]),
            )

        self.console.print(table)
        self.console.print(Text(
            "Manual evidence affects audit readiness and assessment confidence language, not the automated posture score.",
            style="dim",
        ))
        self.console.print()

    def _print_footer(self):
        tips = Text.from_markup(
            "[bold]Next Steps:[/bold]\n"
            "  - Fix critical and high findings first\n"
            "  - Use [cyan]--explain[/cyan] for the scoring and framework model\n"
            "  - Use [cyan]--output json[/cyan] for CI, GRC ingestion, or dashboards\n"
        )
        if self.theme["footer_note"]:
            tips.append(f"\n{self.theme['footer_note']}", style="dim italic")

        self.console.print(Panel(tips, title="Next Steps", border_style="dim", box=box.ROUNDED))

    def _generate_explain_report_rich(self):
        header = Panel(
            Text("WILMA EXPLAIN MODE", justify="center", style="bold magenta"),
            subtitle="How Wilma evaluates AWS Bedrock security posture",
            box=box.DOUBLE,
            border_style="magenta",
        )
        self.console.print(header)
        self.console.print()

        intro = Text()
        intro.append("Wilma is a Bedrock security posture assessment tool.\n", style="bold")
        intro.append(
            "It groups automated AWS evidence into Bedrock Security Indicators, maps findings to external frameworks, "
            "and separates automated posture from manual audit evidence.\n",
            style="dim",
        )
        self.console.print(intro)
        self.console.print()

        for indicator in BEDROCK_SECURITY_INDICATORS:
            table = Table(
                title=indicator["name"],
                box=box.ROUNDED,
                show_header=False,
                title_style="bold cyan",
                border_style="cyan",
            )
            table.add_column("Field", style="bold dim", width=20)
            table.add_column("Value", width=88)
            table.add_row("Purpose", indicator["description"])
            table.add_row("OWASP", ", ".join(indicator["frameworks"]["owasp_llm"]))
            table.add_row("NIST AI RMF", ", ".join(indicator["frameworks"]["nist_ai_rmf"]))
            table.add_row("NIST 800-53", ", ".join(indicator["frameworks"]["nist_800_53"]))
            table.add_row("AIUC-1", ", ".join(indicator["frameworks"]["aiuc_1"]))
            self.console.print(table)
            self.console.print()

        evidence_table = Table(title="Manual Evidence Model", box=box.ROUNDED, show_header=True, header_style="bold yellow")
        evidence_table.add_column("Indicator", width=30)
        evidence_table.add_column("Evidence Wilma Requests", width=72)
        for item in MANUAL_EVIDENCE_ITEMS[:6]:
            evidence_table.add_row(item["indicator"], item["evidence"])
        self.console.print(evidence_table)
        self.console.print()

        footer = Panel(
            Text.from_markup(
                "[bold cyan]Run a posture assessment:[/bold cyan]\n"
                "  [cyan]wilma[/cyan]\n\n"
                "[bold cyan]Fun terminal presentation mode:[/bold cyan]\n"
                "  [cyan]wilma --yabba-dabba-doo[/cyan]\n\n"
                "[dim]--learn is kept as a compatibility alias for --explain.[/dim]"
            ),
            title="Usage",
            border_style="green",
            box=box.ROUNDED,
        )
        self.console.print(footer)

    def _generate_json_report(self) -> str:
        return json.dumps(self._assessment(), indent=2, default=str)

    def _format_frameworks(self, frameworks: dict[str, list[str]]) -> str:
        pieces = []
        labels = {
            "owasp_llm": "OWASP",
            "nist_ai_rmf": "NIST AI RMF",
            "nist_800_53": "NIST 800-53",
            "aiuc_1": "AIUC-1",
            "mitre_atlas": "MITRE ATLAS",
        }
        for key in ["owasp_llm", "nist_ai_rmf", "nist_800_53", "aiuc_1", "mitre_atlas"]:
            values = frameworks.get(key)
            if values:
                pieces.append(f"{labels[key]}: {', '.join(values[:4])}")
        return "\n".join(pieces)

    def _severity_style(self, severity: str) -> str:
        if severity == RiskLevel.CRITICAL.label:
            return "bold red"
        if severity == RiskLevel.HIGH.label:
            return "bold red"
        if severity == RiskLevel.MEDIUM.label:
            return "bold yellow"
        if severity == RiskLevel.LOW.label:
            return "bold blue"
        return "dim"

    def _status_style(self, status: str) -> str:
        if status == "High Risk":
            return "bold red"
        if status == "Needs Improvement":
            return "bold yellow"
        if status == "Minor Gaps":
            return "bold blue"
        if status == "Not Assessed":
            return "dim"
        return "bold green"
