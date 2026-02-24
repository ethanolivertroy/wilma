from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import boto3
import botocore.exceptions


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    status: str
    details: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3}


class BedrockAuditor:
    """Simple Bedrock posture auditor for AWS CloudShell use."""

    def __init__(self, profile: str | None = None, region: str | None = None) -> None:
        session_args: dict[str, str] = {}
        if profile:
            session_args["profile_name"] = profile
        if region:
            session_args["region_name"] = region

        self.session = boto3.Session(**session_args)
        self.region = self.session.region_name or region or "us-east-1"

    def run(self) -> list[Finding]:
        checks = [
            self._check_bedrock_access,
            self._check_cloudtrail,
            self._check_guardrails,
            self._check_private_network_path,
            self._check_iam_wildcards,
        ]
        findings: list[Finding] = []
        for check in checks:
            findings.append(check())
        return findings

    def _check_bedrock_access(self) -> Finding:
        try:
            client = self.session.client("bedrock", region_name=self.region)
            models = client.list_foundation_models().get("modelSummaries", [])
            if models:
                return Finding(
                    check_id="BR-001",
                    title="Bedrock API access",
                    severity="low",
                    status="pass",
                    details=f"Connected to Bedrock in {self.region} and discovered {len(models)} foundation models.",
                    recommendation="No action required.",
                )
            return Finding(
                check_id="BR-001",
                title="Bedrock API access",
                severity="medium",
                status="warn",
                details=f"Connected to Bedrock in {self.region} but no foundation models were returned.",
                recommendation="Confirm Bedrock is available in this region and account.",
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code", error.__class__.__name__)
            return Finding(
                check_id="BR-001",
                title="Bedrock API access",
                severity="high",
                status="fail",
                details=f"Unable to query Bedrock in {self.region}: {code}.",
                recommendation="Grant bedrock:ListFoundationModels and verify region access.",
            )

    def _check_cloudtrail(self) -> Finding:
        try:
            cloudtrail = self.session.client("cloudtrail", region_name=self.region)
            trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
            healthy = [t for t in trails if t.get("IsMultiRegionTrail") and t.get("LogFileValidationEnabled")]
            if healthy:
                return Finding(
                    check_id="BR-002",
                    title="CloudTrail coverage",
                    severity="medium",
                    status="pass",
                    details="At least one multi-region CloudTrail trail has log file validation enabled.",
                    recommendation="No action required.",
                )
            return Finding(
                check_id="BR-002",
                title="CloudTrail coverage",
                severity="high",
                status="fail",
                details="No CloudTrail trail with both multi-region + log file validation was detected.",
                recommendation="Enable a multi-region trail and turn on log file validation.",
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code", error.__class__.__name__)
            return Finding(
                check_id="BR-002",
                title="CloudTrail coverage",
                severity="high",
                status="warn",
                details=f"Could not evaluate CloudTrail configuration: {code}.",
                recommendation="Grant cloudtrail:DescribeTrails to evaluate audit logging posture.",
            )

    def _check_guardrails(self) -> Finding:
        try:
            bedrock = self.session.client("bedrock", region_name=self.region)
            guardrails = bedrock.list_guardrails().get("guardrails", [])
            if guardrails:
                return Finding(
                    check_id="BR-003",
                    title="Bedrock Guardrails adoption",
                    severity="medium",
                    status="pass",
                    details=f"Detected {len(guardrails)} Bedrock guardrail configuration(s).",
                    recommendation="Ensure each production app maps to a tested guardrail.",
                )
            return Finding(
                check_id="BR-003",
                title="Bedrock Guardrails adoption",
                severity="medium",
                status="fail",
                details="No Bedrock guardrails found.",
                recommendation="Create and enforce guardrails for harmful content, prompt injection, and sensitive data.",
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code", error.__class__.__name__)
            return Finding(
                check_id="BR-003",
                title="Bedrock Guardrails adoption",
                severity="medium",
                status="warn",
                details=f"Could not list guardrails: {code}.",
                recommendation="Grant bedrock:ListGuardrails and verify Bedrock permissions.",
            )

    def _check_private_network_path(self) -> Finding:
        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            endpoints = ec2.describe_vpc_endpoints(
                Filters=[{"Name": "service-name", "Values": [f"com.amazonaws.{self.region}.bedrock-runtime"]}]
            ).get("VpcEndpoints", [])
            available = [e for e in endpoints if e.get("State") == "available"]
            if available:
                return Finding(
                    check_id="BR-004",
                    title="Private Bedrock runtime path",
                    severity="high",
                    status="pass",
                    details=f"Found {len(available)} available VPC endpoint(s) for bedrock-runtime.",
                    recommendation="No action required.",
                )
            return Finding(
                check_id="BR-004",
                title="Private Bedrock runtime path",
                severity="high",
                status="fail",
                details="No available VPC endpoint for bedrock-runtime was found.",
                recommendation="Use AWS PrivateLink VPC endpoints to avoid public egress for model traffic.",
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code", error.__class__.__name__)
            return Finding(
                check_id="BR-004",
                title="Private Bedrock runtime path",
                severity="high",
                status="warn",
                details=f"Could not inspect VPC endpoints: {code}.",
                recommendation="Grant ec2:DescribeVpcEndpoints to validate private networking posture.",
            )

    def _check_iam_wildcards(self) -> Finding:
        try:
            iam = self.session.client("iam")
            paginator = iam.get_paginator("list_policies")
            risky_policies = 0
            for page in paginator.paginate(Scope="Local", OnlyAttached=True):
                for policy in page.get("Policies", []):
                    version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    doc = version["PolicyVersion"]["Document"]
                    for statement in _normalize_statement(doc.get("Statement", [])):
                        actions = statement.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if any(a in {"bedrock:*", "*"} for a in actions):
                            risky_policies += 1
                            break

            if risky_policies == 0:
                return Finding(
                    check_id="BR-005",
                    title="Least privilege IAM",
                    severity="critical",
                    status="pass",
                    details="No attached customer-managed policies with wildcard Bedrock permissions were found.",
                    recommendation="No action required.",
                )
            return Finding(
                check_id="BR-005",
                title="Least privilege IAM",
                severity="critical",
                status="fail",
                details=f"Detected {risky_policies} attached customer-managed IAM policy/policies with wildcard Bedrock access.",
                recommendation="Replace wildcard Bedrock actions with explicit API allowlists and scoped resources.",
            )
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code", error.__class__.__name__)
            return Finding(
                check_id="BR-005",
                title="Least privilege IAM",
                severity="critical",
                status="warn",
                details=f"Could not analyze IAM policies: {code}.",
                recommendation="Grant iam:ListPolicies and iam:GetPolicyVersion to check least-privilege posture.",
            )


def _normalize_statement(statement: Any) -> list[dict[str, Any]]:
    if isinstance(statement, dict):
        return [statement]
    if isinstance(statement, list):
        return [item for item in statement if isinstance(item, dict)]
    return []


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    score = 100
    for finding in findings:
        if finding.status == "fail":
            score -= SEVERITY_WEIGHT[finding.severity]
        elif finding.status == "warn":
            score -= max(SEVERITY_WEIGHT[finding.severity] // 2, 1)

    score = max(0, score)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def findings_as_json(findings: list[Finding]) -> list[dict[str, str]]:
    return [finding.to_dict() for finding in findings]
