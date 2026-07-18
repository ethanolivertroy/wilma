"""
Wilma - AWS Bedrock Security Posture Assessment
Main orchestration class that coordinates all security checks

Architecture:
- BedrockSecurityChecker: Central orchestrator
- Check Modules: Specialized security validators (IAM, Network, GenAI, KB, etc.)
- Findings: Structured security issues with risk levels and remediation steps

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import sys
from datetime import datetime, timezone

import boto3

from wilma.assessment import risk_level_label
from wilma.checks import (
    AgentSecurityChecks,
    FineTuningSecurityChecks,
    GenAISecurityChecks,
    GuardrailSecurityChecks,
    IAMSecurityChecks,
    KnowledgeBaseSecurityChecks,
    LoggingSecurityChecks,
    NetworkSecurityChecks,
    TaggingSecurityChecks,
)
from wilma.config import AVAILABLE_CHECKS, WilmaConfig
from wilma.enums import RiskLevel, SecurityMode
from wilma.exceptions import WilmaCredentialsError


class BedrockSecurityChecker:
    """
    AWS Bedrock Security Posture Assessment - Main Orchestrator

    Coordinates security checks across:
    - Agents Security (10 comprehensive checks) - OWASP LLM08, LLM01
    - Fine-Tuning Security (11 comprehensive checks) - OWASP LLM03, LLM04, LLM06
    - Traditional AWS security (IAM, network, logging)
    - GenAI-specific threats (OWASP LLM Top 10, MITRE ATLAS)
    - Guardrails Security (11 comprehensive checks) - OWASP LLM01, LLM02, LLM09
    - Knowledge Base (RAG) security (12 comprehensive checks) - OWASP LLM03, LLM06, LLM07

    Each check module inherits this checker instance for AWS client access.
    """

    CHECK_INDICATORS = {
        "agents": {
            "identity_access_agency",
            "data_protection_privacy",
            "ai_safety_guardrails",
            "rag_model_integrity",
            "monitoring_logging_detection",
        },
        "guardrails": {
            "governance_inventory",
            "data_protection_privacy",
            "ai_safety_guardrails",
        },
        "knowledge_bases": {
            "governance_inventory",
            "identity_access_agency",
            "data_protection_privacy",
            "rag_model_integrity",
            "monitoring_logging_detection",
        },
        "fine_tuning": {
            "governance_inventory",
            "identity_access_agency",
            "data_protection_privacy",
            "rag_model_integrity",
            "monitoring_logging_detection",
            "network_runtime_isolation",
        },
        "iam": {"identity_access_agency"},
        "logging": {"monitoring_logging_detection"},
        "network": {"network_runtime_isolation"},
        "tagging": {"governance_inventory"},
        "genai": {
            "ai_safety_guardrails",
            "data_protection_privacy",
            "resilience_consumption_controls",
        },
    }

    def __init__(self, profile_name: str = None, region: str = None,
                 mode: SecurityMode = SecurityMode.STANDARD,
                 config: WilmaConfig = None,
                 exit_on_error: bool = True):
        """
        Initialize checker with AWS credentials and check modules.

        Args:
            profile_name: AWS CLI profile name (uses default if None)
            region: AWS region to scan (uses session default if None)
            mode: SecurityMode.STANDARD or SecurityMode.LEARN
            config: WilmaConfig instance (creates default if None)

        Exits with code 3 if AWS credentials are invalid or missing.
        """
        self.mode = mode
        self.config = config if config is not None else WilmaConfig()

        session_params = {}
        if profile_name:
            session_params['profile_name'] = profile_name
        if region:
            session_params['region_name'] = region

        # Initialize AWS clients for all security checks
        # Note: bedrock-agent client is required for Knowledge Base API access
        try:
            self.session = boto3.Session(**session_params)
            self.bedrock = self.session.client('bedrock')
            self.bedrock_runtime = self.session.client('bedrock-runtime')
            self.bedrock_agent = self.session.client('bedrock-agent')
            self.iam = self.session.client('iam')
            self.cloudtrail = self.session.client('cloudtrail')
            self.cloudwatch = self.session.client('logs')
            self.ec2 = self.session.client('ec2')
            self.s3 = self.session.client('s3')

            self.region = self.session.region_name
            self.account_id = self.session.client('sts').get_caller_identity()['Account']
        except Exception as e:
            if not exit_on_error:
                raise WilmaCredentialsError(str(e)) from e
            print(f"[ERROR] Error initializing AWS session: {str(e)}")
            print("\n[TIP] Make sure you have AWS credentials configured.")
            print("      Run 'aws configure' or set AWS_PROFILE environment variable.")
            sys.exit(3)

        # Storage for findings and good practices discovered during checks
        self.findings = []
        self.good_practices = []
        self.available_models = []
        self.assessed_indicators = set()
        self.visibility_gaps = []

        # Initialize specialized check modules (each receives this checker instance)
        self.agent_checks = AgentSecurityChecks(self)
        self.fine_tuning_checks = FineTuningSecurityChecks(self)
        self.genai_checks = GenAISecurityChecks(self)
        self.guardrail_checks = GuardrailSecurityChecks(self)
        self.iam_checks = IAMSecurityChecks(self)
        self.kb_checks = KnowledgeBaseSecurityChecks(self)
        self.logging_checks = LoggingSecurityChecks(self)
        self.network_checks = NetworkSecurityChecks(self)
        self.tagging_checks = TaggingSecurityChecks(self)

    def record_visibility_gap(self, service: str, operation: str, reason: str) -> None:
        """Record an AWS API blind spot that should reduce assessment confidence."""
        if any(
            gap["service"] == service and gap["operation"] == operation and gap["reason"] == reason
            for gap in self.visibility_gaps
        ):
            return
        gap = {
            "service": service,
            "operation": operation,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if gap not in self.visibility_gaps:
            self.visibility_gaps.append(gap)

    def filtered_findings(self) -> list[dict]:
        """Return findings that meet the configured minimum risk threshold."""
        filtered = []
        for finding in self.findings:
            severity = risk_level_label(finding.get('risk_level'))
            try:
                risk_level = RiskLevel[severity]
            except KeyError:
                risk_level = RiskLevel.INFO
            if self.config.should_include_finding(risk_level):
                filtered.append(finding)
        return filtered

    def add_finding(self, risk_level: RiskLevel, category: str, resource: str,
                   issue: str, recommendation: str, fix_command: str = None,
                   learn_more: str = None, technical_details: str = None):
        """
        Record a security finding with context and remediation guidance.

        Called by check modules to report issues. Findings include:
        - Risk level (CRITICAL/HIGH/MEDIUM/LOW) with numeric scores
        - Simple explanation + technical details
        - Actionable AWS CLI fix commands
        - Educational context (OWASP/MITRE references)

        Args:
            risk_level: RiskLevel enum determining severity
            category: Check category (e.g., "Knowledge Base Security")
            resource: Specific AWS resource affected
            issue: Simple explanation of the problem
            recommendation: How to fix it
            fix_command: Optional AWS CLI command to remediate
            learn_more: Optional educational context
            technical_details: Optional technical depth for experts
        """
        finding = {
            'risk_level': risk_level,
            'risk_score': risk_level.score,
            'category': category,
            'resource': resource,
            'issue': issue,
            'recommendation': recommendation,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        if fix_command:
            finding['fix_command'] = fix_command
        if learn_more:
            finding['learn_more'] = learn_more
        if technical_details:
            finding['technical_details'] = technical_details

        self.findings.append(finding)

    def add_good_practice(self, category: str, practice: str):
        """
        Track properly configured security controls.

        Used by check modules to acknowledge good security practices.
        Helps provide balanced feedback showing what's working well.
        """
        self.good_practices.append({
            'category': category,
            'practice': practice
        })

    def _print_banner(self):
        """Display ASCII art banner with branding."""
        banner = """
    ██╗    ██╗██╗██╗     ███╗   ███╗ █████╗
    ██║    ██║██║██║     ████╗ ████║██╔══██╗
    ██║ █╗ ██║██║██║     ██╔████╔██║███████║
    ██║███╗██║██║██║     ██║╚██╔╝██║██╔══██║
    ╚███╔███╔╝██║███████╗██║ ╚═╝ ██║██║  ██║
     ╚══╝╚══╝ ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝
        """
        print(banner)
        print("    ~*~ Bedrock Security Posture Assessment ~*~")
        print()

    def _finding_key(self, finding: dict) -> tuple:
        """Build a stable key for deduplicating legacy and rich findings."""
        return (
            risk_level_label(finding.get('risk_level')),
            finding.get('title') or finding.get('issue') or '',
            finding.get('resource') or finding.get('location') or '',
        )

    def _merge_module_findings(self, findings: list[dict]) -> None:
        """Merge findings returned by newer modules into the central report list."""
        existing = {self._finding_key(finding) for finding in self.findings}
        for finding in findings:
            key = self._finding_key(finding)
            if key not in existing:
                self.findings.append(finding)
                existing.add(key)

    def _run_genai_checks(self) -> None:
        """Run the GenAI threat checks (OWASP LLM Top 10)."""
        self.genai_checks.check_prompt_injection_vulnerabilities()
        self.genai_checks.check_data_privacy_compliance()
        self.genai_checks.check_cost_anomaly_detection()

    def _check_runners(self) -> dict:
        """
        Map check-module names to runner callables.

        Rich modules return module-local findings that must be merged into
        checker.findings; legacy modules report through add_finding() directly.
        """
        return {
            "agents": lambda: self._merge_module_findings(self.agent_checks.run_all_checks()),
            "guardrails": lambda: self._merge_module_findings(self.guardrail_checks.run_all_checks()),
            "knowledge_bases": lambda: self._merge_module_findings(self.kb_checks.run_all_checks()),
            "fine_tuning": lambda: self._merge_module_findings(self.fine_tuning_checks.run_all_checks()),
            "iam": self.iam_checks.check_model_access_audit,
            "logging": self.logging_checks.check_logging_monitoring,
            "network": self.network_checks.check_vpc_endpoints,
            "tagging": self.tagging_checks.check_resource_tagging,
            "genai": self._run_genai_checks,
        }

    def run_all_checks(self) -> list[dict]:
        """
        Execute all enabled security checks in AVAILABLE_CHECKS order.

        Order matters: agents, guardrails, knowledge bases, and fine-tuning run
        first because they provide the richest GenAI-specific context, followed
        by the foundational IAM, logging, network, tagging, and GenAI threat
        checks.

        Returns:
            List of finding dictionaries with risk levels and remediation steps
        """
        self._print_banner()
        print(f"[START] Running {self.mode.value} mode Bedrock posture assessment...")
        print("Let me take a look at your Bedrock security configuration...")
        print(f"Account: {self.account_id} | Region: {self.region}")
        print("=" * 60)

        runners = self._check_runners()
        for check_name in AVAILABLE_CHECKS:
            if check_name in self.config.enabled_checks:
                runners[check_name]()
                self.assessed_indicators.update(self.CHECK_INDICATORS[check_name])

        return self.findings
