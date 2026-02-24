from wilma.audit import Finding, score_findings


def test_score_findings_all_pass():
    findings = [
        Finding("BR-001", "x", "low", "pass", "", ""),
        Finding("BR-002", "x", "high", "pass", "", ""),
    ]
    score, grade = score_findings(findings)
    assert score == 100
    assert grade == "A"


def test_score_findings_failures_and_warnings():
    findings = [
        Finding("BR-001", "x", "critical", "fail", "", ""),
        Finding("BR-002", "x", "high", "warn", "", ""),
        Finding("BR-003", "x", "medium", "fail", "", ""),
    ]
    score, grade = score_findings(findings)
    assert score == 42
    assert grade == "D"
