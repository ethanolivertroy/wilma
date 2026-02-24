"""Wilma: lightweight AWS Bedrock security posture checker."""

from wilma.audit import BedrockAuditor, Finding, score_findings

__all__ = ["BedrockAuditor", "Finding", "score_findings"]
__version__ = "2.0.0"
