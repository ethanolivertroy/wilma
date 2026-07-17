"""Tests for report generation."""

import json
from types import SimpleNamespace

from wilma.enums import RiskLevel, SecurityMode
from wilma.reports import ReportGenerator


def _fake_checker():
    findings = [
        {
            "risk_level": RiskLevel.HIGH,
            "category": "Audit & Compliance",
            "resource": "Model Invocation Logging",
            "issue": "Logging disabled",
            "recommendation": "Enable model invocation logging",
        }
    ]
    return SimpleNamespace(
        account_id="123456789012",
        region="us-east-1",
        mode=SecurityMode.STANDARD,
        findings=findings,
        filtered_findings=lambda: findings,
        good_practices=[
            {
                "category": "Logging",
                "practice": "CloudWatch log group retention configured",
            }
        ],
        available_models=["anthropic.claude-v2"],
        assessed_indicators={"monitoring_logging_detection"},
        visibility_gaps=[],
    )


def test_json_report_uses_assessment_schema():
    report = ReportGenerator(_fake_checker(), emit=False).generate_report(output_format="json")

    assessment = json.loads(report)

    assert assessment["schema_version"] == "2.0"
    assert assessment["summary"]["high"] == 1
    assert assessment["findings"][0]["resource"] == "Model Invocation Logging"


def test_text_report_renders_core_sections():
    report = ReportGenerator(_fake_checker(), emit=False).generate_report(output_format="text")

    assert "WILMA BEDROCK SECURITY POSTURE ASSESSMENT" in report
    assert "Posture Summary" in report
    assert "HIGH Findings" in report
    assert "Manual Evidence Needed" in report


def test_explain_report_renders_without_checker():
    report = ReportGenerator(None, emit=False).generate_report(output_format="text", explain=True)

    assert "WILMA EXPLAIN MODE" in report
    assert "Bedrock Security Indicators" in report
