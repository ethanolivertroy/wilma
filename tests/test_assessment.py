"""
Tests for Wilma's versioned assessment model.
"""

from types import SimpleNamespace

from wilma.assessment import AssessmentBuilder, normalize_finding
from wilma.enums import RiskLevel, SecurityMode


def test_normalize_legacy_finding_maps_to_bsi_and_frameworks():
    finding = {
        "risk_level": RiskLevel.HIGH,
        "category": "Audit & Compliance",
        "resource": "Model Invocation Logging",
        "issue": "AI model usage is not being logged",
        "recommendation": "Enable model invocation logging",
        "learn_more": "Without logs, you cannot detect misuse. OWASP LLM10 applies.",
    }

    normalized = normalize_finding(finding, 1)

    assert normalized["finding_id"] == "WILMA-0001"
    assert normalized["severity"] == "HIGH"
    assert normalized["indicator"] == "Monitoring, Logging & Detection"
    assert "LLM10" in normalized["framework_mappings"]["owasp_llm"]
    assert normalized["issue"] == "AI model usage is not being logged"


def test_normalize_rich_finding_preserves_evidence_details():
    finding = {
        "risk_level": RiskLevel.CRITICAL,
        "title": "Agent action group lacks confirmation requirement",
        "description": "Agent can execute Lambda actions without user confirmation.",
        "location": "Agent: SupportBot",
        "resource": "bedrock-agent:agent/agent-123/action-group/ag-123",
        "remediation": "Use RETURN_CONTROL for mutating operations.",
        "details": {
            "agent_id": "agent-123",
            "requires_confirmation": False,
            "owasp": "LLM06 (Excessive Agency)",
        },
    }

    normalized = normalize_finding(finding, 2)

    assert normalized["severity"] == "CRITICAL"
    assert normalized["indicator"] == "Identity, Access & Agency Control"
    assert normalized["evidence"]["observed_fields"]["requires_confirmation"] is False
    assert "LLM06" in normalized["framework_mappings"]["owasp_llm"]


def test_assessment_builder_separates_posture_score_and_manual_evidence():
    checker = SimpleNamespace(
        account_id="123456789012",
        region="us-east-1",
        mode=SecurityMode.STANDARD,
        presentation_mode="standard",
        findings=[
            {
                "risk_level": RiskLevel.HIGH,
                "category": "Network Security",
                "resource": "VPC Endpoint: bedrock-runtime",
                "issue": "AI model invocation traffic goes over the public internet",
                "recommendation": "Create a VPC endpoint for private model invocations",
            }
        ],
        good_practices=[],
        available_models=[],
        assessed_indicators={"network_runtime_isolation"},
    )

    assessment = AssessmentBuilder(checker).build()

    assert assessment["schema_version"] == "2.0"
    assert assessment["assessment_type"] == "bedrock_security_posture"
    assert assessment["posture_score"]["score"] == 85
    assert assessment["posture_score"]["rating"] == "Needs Improvement"
    assert assessment["assessment_confidence"]["rating"] == "Low"
    assert assessment["audit_readiness"]["status"] == "Incomplete"
    assert assessment["manual_evidence_needed"]
    assert assessment["summary"]["high"] == 1
