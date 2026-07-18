"""Tests for Wilma's embeddable library API."""

import wilma.api as api
from wilma import ScanResult, WilmaScanner
from wilma.enums import RiskLevel


class FakeChecker:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.account_id = "123456789012"
        self.region = "us-east-1"
        self.mode = kwargs["mode"]
        self.findings = [
            {
                "risk_level": RiskLevel.HIGH,
                "category": "Audit & Compliance",
                "resource": "Model Invocation Logging",
                "issue": "Logging disabled",
                "recommendation": "Enable invocation logging",
            }
        ]
        self.good_practices = []
        self.available_models = []
        self.assessed_indicators = {"monitoring_logging_detection"}
        self.visibility_gaps = []

    def run_all_checks(self):
        return self.findings

    def filtered_findings(self):
        return self.findings


def test_wilma_scanner_returns_structured_result(monkeypatch):
    created = {}

    def fake_checker(**kwargs):
        created.update(kwargs)
        return FakeChecker(**kwargs)

    monkeypatch.setattr(api, "BedrockSecurityChecker", fake_checker)

    result = WilmaScanner(profile="prod", region="us-east-1").scan()

    assert isinstance(result, ScanResult)
    assert result.assessment["summary"]["high"] == 1
    assert result.findings == result.assessment["findings"]
    assert created["profile_name"] == "prod"
    assert created["exit_on_error"] is False
