from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console
from rich.table import Table

from wilma.audit import BedrockAuditor, findings_as_json, score_findings

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wilma: quick AWS Bedrock security posture script for CloudShell.",
    )
    parser.add_argument("--profile", help="AWS profile name", default=None)
    parser.add_argument("--region", help="AWS region", default=None)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    return parser.parse_args()


def print_report(findings: list[dict[str, str]], score: int, grade: str) -> None:
    table = Table(title="Wilma - Bedrock Security Posture")
    table.add_column("Check")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Details")

    for finding in findings:
        table.add_row(
            f"{finding['check_id']} {finding['title']}",
            finding["severity"].upper(),
            finding["status"].upper(),
            finding["details"],
        )

    console.print(table)
    console.print(f"\nSecurity score: [bold]{score}/100[/bold] | Grade: [bold]{grade}[/bold]")
    console.print("Fix failed checks first, then warning checks. Re-run until stable.")


def main() -> int:
    args = parse_args()
    auditor = BedrockAuditor(profile=args.profile, region=args.region)
    findings = auditor.run()
    score, grade = score_findings(findings)

    if args.json:
        payload = {
            "region": auditor.region,
            "score": score,
            "grade": grade,
            "findings": findings_as_json(findings),
        }
        print(json.dumps(payload, indent=2))
    else:
        print_report(findings_as_json(findings), score, grade)

    if any(f.status == "fail" and f.severity == "critical" for f in findings):
        return 2
    if any(f.status == "fail" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
