"""
Assessment model for Wilma's Bedrock security posture reports.

This module adapts the existing finding dictionaries into a versioned
assessment schema. It is intentionally tolerant of both legacy findings from
checker.add_finding() and richer check-module findings that already include
title, description, remediation, and details.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from wilma.enums import RiskLevel

SCHEMA_VERSION = "2.0"
ASSESSMENT_TYPE = "bedrock_security_posture"


BEDROCK_SECURITY_INDICATORS = [
    {
        "id": "governance_inventory",
        "name": "Governance & Inventory",
        "description": "Resource ownership, tagging, environment classification, and audit inventory completeness.",
        "frameworks": {
            "owasp_llm": ["LLM03", "LLM09"],
            "nist_ai_rmf": ["Govern", "Map"],
            "nist_800_53": ["CM-8", "PM-5", "RA-3"],
            "aws": ["AWS Well-Architected: Operational Excellence", "AWS Bedrock security governance"],
            "aiuc_1": ["Inventory", "ownership", "risk governance", "deployment environment evidence"],
        },
    },
    {
        "id": "identity_access_agency",
        "name": "Identity, Access & Agency Control",
        "description": "Least privilege, service roles, cross-account access, and agent/tool authorization boundaries.",
        "frameworks": {
            "owasp_llm": ["LLM06"],
            "nist_ai_rmf": ["Govern", "Manage"],
            "nist_800_53": ["AC-2", "AC-3", "AC-6", "IA-2"],
            "aws": ["IAM least privilege", "Bedrock Agents action group controls"],
            "aiuc_1": ["Agent data access limits", "unauthorized agent action prevention", "user privileges"],
        },
    },
    {
        "id": "data_protection_privacy",
        "name": "Data Protection & Privacy",
        "description": "Encryption, PII exposure, training data protection, logs, and customer data isolation.",
        "frameworks": {
            "owasp_llm": ["LLM02"],
            "nist_ai_rmf": ["Map", "Measure", "Manage"],
            "nist_800_53": ["SC-13", "SC-28", "SI-12", "PT-2"],
            "aws": ["Bedrock data protection", "KMS encryption", "S3 data protection"],
            "aiuc_1": ["PII leakage prevention", "IP and trade secret protection", "cross-customer data isolation"],
        },
    },
    {
        "id": "ai_safety_guardrails",
        "name": "AI Safety & Guardrails",
        "description": "Guardrails, content filters, prompt attack protection, grounding, and output safety.",
        "frameworks": {
            "owasp_llm": ["LLM01", "LLM05", "LLM09"],
            "nist_ai_rmf": ["Measure", "Manage"],
            "nist_800_53": ["SI-10", "SI-15", "RA-5"],
            "aws": ["Amazon Bedrock Guardrails", "prompt injection controls", "responsible AI controls"],
            "aiuc_1": ["Adversarial input detection", "real-time input filtering", "adversarial robustness testing"],
        },
    },
    {
        "id": "rag_model_integrity",
        "name": "RAG & Model Integrity",
        "description": "Knowledge base security, vector store controls, poisoning resilience, and model/data provenance.",
        "frameworks": {
            "owasp_llm": ["LLM03", "LLM04", "LLM08"],
            "nist_ai_rmf": ["Map", "Measure", "Manage"],
            "nist_800_53": ["SA-10", "SI-7", "SR-3", "SR-11"],
            "aws": ["Knowledge Bases for Amazon Bedrock security", "model customization governance"],
            "aiuc_1": ["Data provenance", "model integrity", "RAG source validation", "poisoning resilience"],
        },
    },
    {
        "id": "monitoring_logging_detection",
        "name": "Monitoring, Logging & Detection",
        "description": "Invocation logging, CloudTrail/CloudWatch evidence, retention, alerts, and anomaly signals.",
        "frameworks": {
            "owasp_llm": ["LLM10"],
            "nist_ai_rmf": ["Measure", "Manage"],
            "nist_800_53": ["AU-2", "AU-6", "AU-11", "SI-4"],
            "aws": ["Bedrock model invocation logging", "CloudTrail", "CloudWatch Logs"],
            "aiuc_1": ["Logs", "monitoring evidence", "abuse detection", "audit trail evidence"],
        },
    },
    {
        "id": "network_runtime_isolation",
        "name": "Network & Runtime Isolation",
        "description": "Private connectivity, VPC endpoints, TLS paths, runtime boundaries, and integration exposure.",
        "frameworks": {
            "owasp_llm": ["LLM02", "LLM06"],
            "nist_ai_rmf": ["Manage"],
            "nist_800_53": ["SC-7", "SC-8", "SC-12", "AC-4"],
            "aws": ["VPC endpoints", "private connectivity", "network segmentation"],
            "aiuc_1": ["Deployment environment protection", "service isolation", "external exposure review"],
        },
    },
    {
        "id": "resilience_consumption_controls",
        "name": "Resilience & Consumption Controls",
        "description": "Quotas, throttling, runaway usage, model DoS, cost abuse, and agent loop containment.",
        "frameworks": {
            "owasp_llm": ["LLM10", "LLM06"],
            "nist_ai_rmf": ["Measure", "Manage"],
            "nist_800_53": ["CP-10", "SC-5", "SI-4"],
            "aws": ["Service quotas", "cost anomaly detection", "resilience engineering"],
            "aiuc_1": ["AI endpoint scraping prevention", "abuse prevention", "operational resilience evidence"],
        },
    },
]

INDICATOR_BY_ID = {indicator["id"]: indicator for indicator in BEDROCK_SECURITY_INDICATORS}

MANUAL_EVIDENCE_ITEMS = [
    {
        "indicator": "Governance & Inventory",
        "frameworks": ["AIUC-1", "NIST AI RMF Govern"],
        "evidence": "Documented AI system owner, business purpose, deployment environment, and data classification.",
        "reason": "AWS configuration can show resources and tags, but not whether governance ownership is formally approved.",
    },
    {
        "indicator": "Identity, Access & Agency Control",
        "frameworks": ["AIUC-1", "NIST 800-53 AC-2", "NIST 800-53 AC-6"],
        "evidence": "Recent access review for Bedrock users, service roles, agent operators, and privileged administrators.",
        "reason": "Wilma can inspect permissions, but it cannot prove the organization reviewed and approved them.",
    },
    {
        "indicator": "Data Protection & Privacy",
        "frameworks": ["AIUC-1", "NIST AI RMF Map/Manage"],
        "evidence": "Input/output data policy covering retention, secondary use, PII handling, and customer data boundaries.",
        "reason": "AWS APIs expose technical controls, not legal retention commitments or approved data handling policy.",
    },
    {
        "indicator": "Data Protection & Privacy",
        "frameworks": ["AIUC-1"],
        "evidence": "Privacy review or DPIA for Bedrock use cases that process sensitive or personal data.",
        "reason": "Privacy impact analysis is an organizational artifact outside Bedrock configuration.",
    },
    {
        "indicator": "AI Safety & Guardrails",
        "frameworks": ["AIUC-1", "OWASP LLM Top 10"],
        "evidence": "Adversarial robustness test results for prompt injection, jailbreaks, unsafe outputs, and bypass attempts.",
        "reason": "Configuration shows controls exist, but test evidence shows whether they work against expected attacks.",
    },
    {
        "indicator": "RAG & Model Integrity",
        "frameworks": ["AIUC-1", "OWASP LLM03", "OWASP LLM04"],
        "evidence": "Approved data source inventory, provenance checks, and change control for RAG/fine-tuning data.",
        "reason": "Wilma can inspect storage and metadata, but cannot validate business provenance without records.",
    },
    {
        "indicator": "Monitoring, Logging & Detection",
        "frameworks": ["AIUC-1", "NIST 800-53 AU-6", "NIST 800-53 SI-4"],
        "evidence": "Incident response procedure and alert runbooks for Bedrock misuse, data leakage, and abnormal usage.",
        "reason": "Logging configuration is not the same as an operational detection and response process.",
    },
    {
        "indicator": "Resilience & Consumption Controls",
        "frameworks": ["AIUC-1", "OWASP LLM10"],
        "evidence": "Load, abuse, scraping, and runaway-agent test results with documented thresholds and response actions.",
        "reason": "AWS service quotas and alarms do not prove the application handles abusive workloads safely.",
    },
]

SEVERITY_PENALTIES = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

INDICATOR_KEYWORDS = [
    (
        "resilience_consumption_controls",
        ["cost", "quota", "throttle", "consumption", "anomaly", "denial", "dos", "scraping", "runaway"],
    ),
    (
        "network_runtime_isolation",
        ["vpc", "endpoint", "private dns", "network", "security group", "public endpoint", "subnet", "runtime isolation"],
    ),
    (
        "monitoring_logging_detection",
        ["log", "logging", "cloudtrail", "cloudwatch", "monitor", "retention", "audit trail", "detection"],
    ),
    (
        "rag_model_integrity",
        ["knowledge base", "vector", "embedding", "rag", "chunk", "fine-tuning", "training", "custom model", "poison"],
    ),
    (
        "ai_safety_guardrails",
        [
            "guardrail",
            "prompt injection",
            "prompt attack",
            "content filter",
            "topic filter",
            "word filter",
            "automated reasoning",
            "contextual grounding",
            "harmful output",
            "jailbreak",
        ],
    ),
    (
        "data_protection_privacy",
        ["pii", "privacy", "encrypt", "kms", "s3", "bucket", "sensitive", "data protection", "secret"],
    ),
    (
        "identity_access_agency",
        [
            "iam",
            "role",
            "permission",
            "least privilege",
            "cross-account",
            "action group",
            "lambda",
            "agency",
            "administratoraccess",
            "poweruseraccess",
        ],
    ),
    (
        "governance_inventory",
        ["tag", "owner", "governance", "inventory", "environment", "classification", "documentation", "model card"],
    ),
]


def risk_level_label(value: Any) -> str:
    """Return a stable severity label from RiskLevel enums or strings."""
    if isinstance(value, RiskLevel):
        return value.label
    if value is None:
        return "INFO"
    if isinstance(value, str):
        label = value.split(".")[-1].upper()
        if label in SEVERITY_PENALTIES:
            return label
    return "INFO"


def risk_level_score(value: Any) -> int:
    """Return Wilma's existing 1-10 risk score for a risk value."""
    if isinstance(value, RiskLevel):
        return value.score
    label = risk_level_label(value)
    scores = {
        "CRITICAL": RiskLevel.CRITICAL.score,
        "HIGH": RiskLevel.HIGH.score,
        "MEDIUM": RiskLevel.MEDIUM.score,
        "LOW": RiskLevel.LOW.score,
        "INFO": RiskLevel.INFO.score,
    }
    return scores[label]


def _join_finding_text(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("category"),
        finding.get("title"),
        finding.get("issue"),
        finding.get("description"),
        finding.get("resource"),
        finding.get("location"),
        finding.get("recommendation"),
        finding.get("remediation"),
        finding.get("technical_details"),
        str(finding.get("details", "")),
    ]
    return " ".join(str(part) for part in parts if part).lower()


def infer_indicator_id(finding: dict[str, Any]) -> str:
    """Infer a Bedrock Security Indicator from the current finding shape."""
    explicit_indicator = finding.get("indicator") or finding.get("bedrock_security_indicator")
    if explicit_indicator:
        normalized = str(explicit_indicator).lower().replace(" ", "_").replace("&", "and")
        if normalized in INDICATOR_BY_ID:
            return normalized

    text = _join_finding_text(finding)
    for indicator_id, keywords in INDICATOR_KEYWORDS:
        if any(keyword in text for keyword in keywords):
            return indicator_id

    return "governance_inventory"


def _extract_owasp_categories(finding: dict[str, Any]) -> list[str]:
    text = " ".join(
        str(value)
        for value in [
            finding.get("learn_more"),
            finding.get("technical_details"),
            finding.get("description"),
            finding.get("details", ""),
        ]
        if value
    )
    return sorted(set(re.findall(r"LLM\d{2}", text)))


def framework_mappings_for(finding: dict[str, Any], indicator_id: str) -> dict[str, list[str]]:
    """Return explicit finding mappings plus the indicator's baseline mappings."""
    indicator_frameworks = INDICATOR_BY_ID[indicator_id]["frameworks"]
    mappings = {key: list(value) for key, value in indicator_frameworks.items()}

    owasp = _extract_owasp_categories(finding)
    if owasp:
        mappings["owasp_llm"] = sorted(set(mappings.get("owasp_llm", []) + owasp))

    details = finding.get("details", {})
    if isinstance(details, dict):
        if details.get("mitre_atlas"):
            mappings["mitre_atlas"] = [str(details["mitre_atlas"])]
        elif details.get("mitre"):
            mappings["mitre_atlas"] = [str(details["mitre"])]

    return mappings


def normalize_finding(finding: dict[str, Any], index: int) -> dict[str, Any]:
    """Normalize legacy and rich findings into the 0.2.x assessment shape."""
    severity = risk_level_label(finding.get("risk_level"))
    indicator_id = infer_indicator_id(finding)
    indicator = INDICATOR_BY_ID[indicator_id]
    title = finding.get("title") or finding.get("issue") or "Security finding"
    description = finding.get("description") or finding.get("learn_more") or finding.get("technical_details") or title
    recommendation = finding.get("recommendation") or finding.get("remediation") or "Review and remediate this control."
    resource = finding.get("resource") or finding.get("location") or "Unknown resource"

    normalized = {
        "finding_id": f"WILMA-{index:04d}",
        "status": "fail" if severity != "INFO" else "info",
        "severity": severity,
        "risk_level": severity,
        "risk_score": finding.get("risk_score", risk_level_score(finding.get("risk_level"))),
        "category": finding.get("category") or indicator["name"],
        "indicator_id": indicator_id,
        "indicator": indicator["name"],
        "title": title,
        "issue": finding.get("issue") or title,
        "description": description,
        "resource": resource,
        "location": finding.get("location") or resource,
        "recommendation": recommendation,
        "remediation": finding.get("remediation") or recommendation,
        "fix_command": finding.get("fix_command"),
        "learn_more": finding.get("learn_more"),
        "technical_details": finding.get("technical_details"),
        "evidence": {
            "type": "aws_resource",
            "resource": resource,
            "observed_fields": finding.get("details", {}),
            "timestamp": finding.get("timestamp"),
        },
        "framework_mappings": framework_mappings_for(finding, indicator_id),
    }

    return normalized


def _rating_from_score(score: int, counts: dict[str, int]) -> str:
    if counts.get("CRITICAL", 0) > 0:
        return "High Risk"
    if counts.get("HIGH", 0) > 0:
        return "Needs Improvement"
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 55:
        return "Needs Improvement"
    return "High Risk"


def _confidence_rating(score: int) -> str:
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def _highest_severity(findings: Iterable[dict[str, Any]]):
    severities = [finding["severity"] for finding in findings]
    if not severities:
        return None
    return max(severities, key=lambda severity: SEVERITY_ORDER.get(severity, 0))


class AssessmentBuilder:
    """Build the versioned Wilma assessment from a checker instance."""

    def __init__(self, checker: Any):
        self.checker = checker

    def build(self) -> dict[str, Any]:
        raw_findings = list(getattr(self.checker, "findings", []))
        normalized_findings = [normalize_finding(finding, index) for index, finding in enumerate(raw_findings, 1)]
        counts = self._severity_counts(normalized_findings)
        score = self._posture_score(normalized_findings)
        assessed_indicators = set(getattr(self.checker, "assessed_indicators", set()))
        assessed_indicators.update(finding["indicator_id"] for finding in normalized_findings)
        indicator_scores = self._indicator_scores(normalized_findings, assessed_indicators)
        confidence = self._assessment_confidence(assessed_indicators)

        summary = {
            "total_findings": len(normalized_findings),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "info": counts["INFO"],
            "good_practices": len(getattr(self.checker, "good_practices", [])),
            "posture_score": score,
            "posture_rating": _rating_from_score(score, counts),
            "assessment_confidence": confidence["rating"],
        }

        return {
            "schema_version": SCHEMA_VERSION,
            "assessment_type": ASSESSMENT_TYPE,
            "tool": {
                "name": "Wilma",
                "version": self._tool_version(),
            },
            "account_id": getattr(self.checker, "account_id", None),
            "region": getattr(self.checker, "region", None),
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "mode": getattr(getattr(self.checker, "mode", None), "value", "standard"),
            "presentation_mode": getattr(self.checker, "presentation_mode", "standard"),
            "posture_score": {
                "score": score,
                "rating": summary["posture_rating"],
                "scale": "0-100",
                "drivers": self._posture_drivers(normalized_findings),
            },
            "assessment_confidence": confidence,
            "audit_readiness": {
                "status": "Incomplete",
                "manual_evidence_open": len(MANUAL_EVIDENCE_ITEMS),
                "note": "Manual organizational evidence is listed separately and does not reduce the automated posture score.",
            },
            "bedrock_security_indicators": indicator_scores,
            "framework_mappings": self._framework_summary(indicator_scores),
            "manual_evidence_needed": MANUAL_EVIDENCE_ITEMS,
            "summary": summary,
            "findings": normalized_findings,
            "good_practices": getattr(self.checker, "good_practices", []),
            "available_models": getattr(self.checker, "available_models", []),
        }

    def _tool_version(self) -> str:
        try:
            from wilma import __version__
        except Exception:
            return "unknown"
        return __version__

    def _severity_counts(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITY_PENALTIES, 0)
        for finding in findings:
            counts[finding["severity"]] += 1
        return counts

    def _posture_score(self, findings: list[dict[str, Any]]) -> int:
        penalty = sum(SEVERITY_PENALTIES.get(finding["severity"], 0) for finding in findings)
        return max(0, 100 - min(100, penalty))

    def _indicator_scores(
        self,
        findings: list[dict[str, Any]],
        assessed_indicators: set[str],
    ) -> list[dict[str, Any]]:
        scorecards = []
        for indicator in BEDROCK_SECURITY_INDICATORS:
            indicator_findings = [finding for finding in findings if finding["indicator_id"] == indicator["id"]]
            finding_penalty = sum(SEVERITY_PENALTIES.get(finding["severity"], 0) for finding in indicator_findings)
            assessed = indicator["id"] in assessed_indicators
            score = max(0, 100 - min(100, finding_penalty)) if assessed else None
            worst = _highest_severity(indicator_findings)
            status = self._indicator_status(assessed, worst)

            scorecards.append(
                {
                    "id": indicator["id"],
                    "name": indicator["name"],
                    "description": indicator["description"],
                    "status": status,
                    "score": score,
                    "confidence": "High" if assessed else "Low",
                    "finding_count": len(indicator_findings),
                    "worst_severity": worst,
                    "frameworks": indicator["frameworks"],
                }
            )
        return scorecards

    def _indicator_status(self, assessed: bool, worst_severity) -> str:
        if not assessed:
            return "Not Assessed"
        if worst_severity in ("CRITICAL", "HIGH"):
            return "High Risk"
        if worst_severity == "MEDIUM":
            return "Needs Improvement"
        if worst_severity == "LOW":
            return "Minor Gaps"
        return "No Findings"

    def _assessment_confidence(self, assessed_indicators: set[str]) -> dict[str, Any]:
        total = len(BEDROCK_SECURITY_INDICATORS)
        assessed = len([indicator for indicator in BEDROCK_SECURITY_INDICATORS if indicator["id"] in assessed_indicators])
        score = int(round((assessed / total) * 100)) if total else 0
        blind_spots = [
            {
                "indicator_id": indicator["id"],
                "indicator": indicator["name"],
                "reason": "No automated check coverage was recorded for this indicator.",
            }
            for indicator in BEDROCK_SECURITY_INDICATORS
            if indicator["id"] not in assessed_indicators
        ]
        return {
            "score": score,
            "rating": _confidence_rating(score),
            "assessed_indicators": assessed,
            "total_indicators": total,
            "blind_spots": blind_spots,
        }

    def _posture_drivers(self, findings: list[dict[str, Any]]) -> list[str]:
        if not findings:
            return ["No security findings were recorded by the automated checks."]

        drivers = []
        by_severity = self._severity_counts(findings)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = by_severity[severity]
            if count:
                drivers.append(f"{count} {severity.lower()} finding{'s' if count != 1 else ''}")

        top_indicators: dict[str, int] = {}
        for finding in findings:
            top_indicators[finding["indicator"]] = top_indicators.get(finding["indicator"], 0) + 1
        for indicator, count in sorted(top_indicators.items(), key=lambda item: item[1], reverse=True)[:3]:
            drivers.append(f"{indicator}: {count} finding{'s' if count != 1 else ''}")
        return drivers

    def _framework_summary(self, indicators: list[dict[str, Any]]) -> dict[str, list[str]]:
        summary: dict[str, set[str]] = {}
        for indicator in indicators:
            for framework, mappings in indicator["frameworks"].items():
                summary.setdefault(framework, set()).update(str(mapping) for mapping in mappings)
        return {framework: sorted(values) for framework, values in summary.items()}
