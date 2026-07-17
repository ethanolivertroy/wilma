"""Tests for AWS Bedrock Guardrail security checks."""

from wilma.checks.guardrails import GuardrailSecurityChecks
from wilma.enums import RiskLevel


def _current_guardrail_details(guardrail_id="gr-123"):
    return {
        "guardrailId": guardrail_id,
        "name": "ProductionGuardrail",
        "status": "READY",
        "contentPolicy": {
            "filters": [
                {"type": "VIOLENCE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                {"type": "HATE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                {"type": "INSULTS", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                {"type": "MISCONDUCT", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                {"type": "PROMPT_ATTACK", "inputStrength": "HIGH", "outputStrength": "HIGH"},
            ]
        },
        "sensitiveInformationPolicy": {
            "piiEntities": [
                {"type": "NAME", "action": "BLOCK"},
                {"type": "EMAIL", "action": "BLOCK"},
                {"type": "PHONE", "action": "BLOCK"},
                {"type": "ADDRESS", "action": "BLOCK"},
                {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"},
                {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCK"},
            ]
        },
        "topicPolicy": {
            "topics": [
                {"name": "medical-advice", "definition": "Medical diagnosis", "type": "DENY"}
            ]
        },
        "wordPolicy": {
            "managedWordLists": [{"type": "PROFANITY"}],
            "words": [{"text": "internal-forbidden-term"}],
        },
        "contextualGroundingPolicy": {
            "filters": [
                {"type": "GROUNDING", "threshold": 0.8},
                {"type": "RELEVANCE", "threshold": 0.8},
            ]
        },
        "automatedReasoningPolicy": {
            "policies": [{"policyArn": "arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/pol-1"}],
            "confidenceThreshold": 0.8,
        },
        "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/1234",
    }


def _setup_guardrail_inventory(mock_checker, guardrail_id="gr-123", version="1"):
    mock_checker.bedrock.list_guardrails.return_value = {
        "guardrails": [
            {
                "id": guardrail_id,
                "arn": f"arn:aws:bedrock:us-east-1:123456789012:guardrail/{guardrail_id}",
                "name": "ProductionGuardrail",
                "version": version,
                "status": "READY",
            }
        ]
    }
    mock_checker.bedrock.get_guardrail.return_value = _current_guardrail_details(guardrail_id)
    mock_checker.bedrock.list_tags_for_resource.return_value = {
        "tags": [
            {"key": "Environment", "value": "prod"},
            {"key": "Owner", "value": "security"},
            {"key": "DataClassification", "value": "confidential"},
        ]
    }
    mock_checker.bedrock_agent.list_agents.return_value = {"agentSummaries": []}
    mock_checker.bedrock_agent.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}


def test_guardrails_accept_current_get_guardrail_shape(mock_checker):
    """A complete current-shape guardrail should not be flagged as missing policies."""
    _setup_guardrail_inventory(mock_checker)
    checks = GuardrailSecurityChecks(mock_checker)

    findings = checks.run_all_checks()

    titles = {finding["title"] for finding in findings}
    assert "Guardrail missing PROMPT_ATTACK filter" not in titles
    assert "Guardrail missing PII filter configuration" not in titles
    assert "Guardrail missing topic filter configuration" not in titles
    assert "Guardrail missing word filter configuration" not in titles
    assert "Guardrail missing automated reasoning configuration" not in titles
    assert "Guardrail using AWS-managed encryption key" not in titles


def test_guardrail_strength_uses_current_filter_shape(mock_checker):
    """LOW current-shape content filters should still be detected."""
    _setup_guardrail_inventory(mock_checker)
    details = _current_guardrail_details()
    details["contentPolicy"]["filters"][0]["inputStrength"] = "LOW"
    mock_checker.bedrock.get_guardrail.return_value = details
    checks = GuardrailSecurityChecks(mock_checker)

    findings = checks.check_guardrail_strength_configuration()

    assert any(
        finding["risk_level"] == RiskLevel.HIGH
        and finding["title"] == "Guardrail uses LOW input filter strength"
        for finding in findings
    )


def test_guardrail_pagination_uses_lowercase_nexttoken(mock_checker):
    """Bedrock guardrail lists should follow the current lowercase nextToken contract."""
    first_page = {
        "guardrails": [{"id": "gr-1", "name": "First", "version": "1"}],
        "nextToken": "token-2",
    }
    second_page = {
        "guardrails": [{"id": "gr-2", "name": "Second", "version": "1"}],
    }
    mock_checker.bedrock.list_guardrails.side_effect = [first_page, second_page]
    checks = GuardrailSecurityChecks(mock_checker)

    guardrails = checks._list_guardrails()

    assert [guardrail["id"] for guardrail in guardrails] == ["gr-1", "gr-2"]
    assert mock_checker.bedrock.list_guardrails.call_args_list[1].kwargs["nextToken"] == "token-2"
