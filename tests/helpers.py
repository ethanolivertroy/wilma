"""
Test helper functions for Wilma test suite.

Provides utilities for asserting findings, filtering results, and
common test patterns.
"""

from typing import Any, Dict, List, Optional

from wilma.enums import RiskLevel


def assert_finding_exists(
    findings: List[Dict[str, Any]],
    risk_level: RiskLevel,
    category: Optional[str] = None,
    issue_contains: Optional[str] = None,
    resource_contains: Optional[str] = None
) -> Dict[str, Any]:
    """
    Assert that a specific finding exists in the findings list.

    Args:
        findings: List of findings to search
        risk_level: Expected risk level
        category: Optional category filter
        issue_contains: Optional substring that must be in issue description
        resource_contains: Optional substring that must be in resource name

    Returns:
        The matching finding dict

    Raises:
        AssertionError: If no matching finding is found

    Example:
        assert_finding_exists(
            checker.findings,
            RiskLevel.HIGH,
            category="IAM Security",
            issue_contains="wildcard"
        )
    """
    matching = []

    for finding in findings:
        if finding.get('risk_level') != risk_level:
            continue
        if category and finding.get('category') != category:
            continue
        if issue_contains and issue_contains not in finding.get('issue', ''):
            continue
        if resource_contains and resource_contains not in finding.get('resource', ''):
            continue
        matching.append(finding)

    assert len(matching) > 0, (
        f"Expected finding not found: "
        f"risk_level={risk_level}, category={category}, "
        f"issue_contains={issue_contains}, resource_contains={resource_contains}"
    )

    return matching[0]


def get_findings_by_risk(
    findings: List[Dict[str, Any]],
    risk_level: RiskLevel
) -> List[Dict[str, Any]]:
    """
    Get all findings of a specific risk level.

    Args:
        findings: List of findings
        risk_level: Risk level to filter by

    Returns:
        List of findings matching the risk level

    Example:
        high_findings = get_findings_by_risk(checker.findings, RiskLevel.HIGH)
        assert len(high_findings) == 2
    """
    return [f for f in findings if f.get('risk_level') == risk_level]


def get_findings_by_category(
    findings: List[Dict[str, Any]],
    category: str
) -> List[Dict[str, Any]]:
    """
    Get all findings in a specific category.

    Args:
        findings: List of findings
        category: Category name (e.g., "IAM Security")

    Returns:
        List of findings in the category

    Example:
        iam_findings = get_findings_by_category(checker.findings, "IAM Security")
    """
    return [f for f in findings if f.get('category') == category]


def assert_no_findings(findings: List[Dict[str, Any]]):
    """
    Assert that no findings exist (good security posture).

    Args:
        findings: List of findings

    Raises:
        AssertionError: If any findings exist

    Example:
        assert_no_findings(checker.findings)
    """
    assert len(findings) == 0, f"Expected no findings but found {len(findings)}"


def assert_finding_count(
    findings: List[Dict[str, Any]],
    expected_count: int,
    risk_level: Optional[RiskLevel] = None
):
    """
    Assert exact count of findings.

    Args:
        findings: List of findings
        expected_count: Expected number of findings
        risk_level: Optional risk level filter

    Raises:
        AssertionError: If count doesn't match

    Example:
        assert_finding_count(checker.findings, 3, RiskLevel.HIGH)
    """
    if risk_level:
        findings = get_findings_by_risk(findings, risk_level)

    assert len(findings) == expected_count, (
        f"Expected {expected_count} findings but found {len(findings)}"
    )


def assert_finding_has_remediation(finding: Dict[str, Any]):
    """
    Assert that a finding includes remediation information.

    Args:
        finding: Single finding dict

    Raises:
        AssertionError: If finding lacks remediation info

    Example:
        finding = assert_finding_exists(findings, RiskLevel.HIGH)
        assert_finding_has_remediation(finding)
    """
    assert 'recommendation' in finding, "Finding missing recommendation key"
    assert finding['recommendation'], "Finding has empty recommendation"
    assert 'fix_command' in finding or 'learn_more' in finding, \
        "Finding missing remediation guidance"


def get_findings_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Get summary statistics of findings by risk level.

    Args:
        findings: List of findings

    Returns:
        Dict with counts per risk level

    Example:
        summary = get_findings_summary(checker.findings)
        assert summary[RiskLevel.CRITICAL] == 0
    """
    summary = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.LOW: 0,
    }

    for finding in findings:
        risk = finding.get('risk_level')
        if risk in summary:
            summary[risk] += 1

    return summary
