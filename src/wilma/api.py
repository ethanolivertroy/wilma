"""Embeddable library API for Wilma scans."""

from dataclasses import dataclass
from typing import Optional

from wilma.assessment import AssessmentBuilder
from wilma.checker import BedrockSecurityChecker
from wilma.config import WilmaConfig
from wilma.enums import SecurityMode


@dataclass
class ScanResult:
    """Structured result returned by the library scanner."""

    assessment: dict
    findings: list[dict]
    checker: BedrockSecurityChecker


class WilmaScanner:
    """Programmatic scanner for security tools that embed Wilma."""

    def __init__(
        self,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        config: Optional[WilmaConfig] = None,
        mode: SecurityMode = SecurityMode.STANDARD,
    ):
        self.profile = profile
        self.region = region
        self.config = config
        self.mode = mode

    def scan(self) -> ScanResult:
        """Run a Bedrock posture assessment and return the structured assessment."""
        checker = BedrockSecurityChecker(
            profile_name=self.profile,
            region=self.region,
            mode=self.mode,
            config=self.config,
            exit_on_error=False,
        )
        checker.run_all_checks()
        assessment = AssessmentBuilder(checker).build()
        return ScanResult(
            assessment=assessment,
            findings=assessment["findings"],
            checker=checker,
        )
