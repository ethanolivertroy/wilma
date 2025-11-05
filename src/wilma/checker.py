"""
Wilma - AWS Bedrock Security Checker
Main orchestration class that coordinates all security checks

Architecture:
- BedrockSecurityChecker: Central orchestrator
- Check Modules: Specialized security validators (IAM, Network, GenAI, KB, etc.)
- Findings: Structured security issues with risk levels and remediation steps

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import boto3
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

from wilma.enums import SecurityMode, RiskLevel
from wilma.checks import (
    GenAISecurityChecks,
    IAMSecurityChecks,
    LoggingSecurityChecks,
    NetworkSecurityChecks,
    TaggingSecurityChecks,
    KnowledgeBaseSecurityChecks,
)


class BedrockSecurityChecker:
    """
    AWS Bedrock Security Checker - Main Orchestrator

    Coordinates security checks across:
    - Traditional AWS security (IAM, network, logging)
    - GenAI-specific threats (OWASP LLM Top 10, MITRE ATLAS)
    - Knowledge Base (RAG) security (12 comprehensive checks)

    Each check module inherits this checker instance for AWS client access.
    """

    def __init__(self, profile_name: str = None, region: str = None,
                 mode: SecurityMode = SecurityMode.STANDARD):
        """
        Initialize checker with AWS credentials and check modules.

        Args:
            profile_name: AWS CLI profile name (uses default if None)
            region: AWS region to scan (uses session default if None)
            mode: SecurityMode.STANDARD or SecurityMode.LEARN

        Exits with code 3 if AWS credentials are invalid or missing.
        """
        self.mode = mode

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
            print(f"[ERROR] Error initializing AWS session: {str(e)}")
            print("\n[TIP] Make sure you have AWS credentials configured.")
            print("      Run 'aws configure' or set AWS_PROFILE environment variable.")
            sys.exit(3)

        # Storage for findings and good practices discovered during checks
        self.findings = []
        self.good_practices = []
        self.available_models = []

        # Initialize specialized check modules (each receives this checker instance)
        self.genai_checks = GenAISecurityChecks(self)
        self.iam_checks = IAMSecurityChecks(self)
        self.logging_checks = LoggingSecurityChecks(self)
        self.network_checks = NetworkSecurityChecks(self)
        self.tagging_checks = TaggingSecurityChecks(self)
        self.kb_checks = KnowledgeBaseSecurityChecks(self)

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
            'timestamp': datetime.utcnow().isoformat()
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
        print("    ~*~ Bedrock Security Check ~*~")
        print()

    def run_all_checks(self) -> List[Dict]:
        """
        Execute all security checks in order.

        Runs comprehensive security audit covering:
        1. IAM & Access Control - Who can use Bedrock and how
        2. Logging & Monitoring - Audit trails and anomaly detection
        3. Network Security - VPC endpoints and private connectivity
        4. Resource Tagging - Organization and compliance tracking
        5. GenAI Threats - OWASP LLM01 (prompt injection), PII leaks, cost abuse
        6. Knowledge Bases - All 12 RAG security checks

        Returns:
            List of finding dictionaries with risk levels and remediation steps
        """
        self._print_banner()
        print(f"[START] Running {self.mode.value} mode security check...")
        print("Let me take a look at your Bedrock security configuration...")
        print(f"Account: {self.account_id} | Region: {self.region}")
        print("=" * 60)

        # Foundation: Identity and access control
        self.iam_checks.check_model_access_audit()

        # Visibility: Logging and monitoring
        self.logging_checks.check_logging_monitoring()

        # Network: Private connectivity
        self.network_checks.check_vpc_endpoints()

        # Organization: Resource management
        self.tagging_checks.check_resource_tagging()

        # GenAI threats: OWASP LLM Top 10
        self.genai_checks.check_prompt_injection_vulnerabilities()
        self.genai_checks.check_data_privacy_compliance()
        self.genai_checks.check_cost_anomaly_detection()

        # Knowledge Bases: RAG-specific security (12 checks)
        self.kb_checks.run_all_checks()

        return self.findings
