"""
Main security checker class for Wilma

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
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
    """Enhanced AWS Bedrock Security Checker with GenAI focus."""

    def __init__(self, profile_name: str = None, region: str = None,
                 mode: SecurityMode = SecurityMode.STANDARD):
        """Initialize the enhanced security checker."""
        self.mode = mode

        session_params = {}
        if profile_name:
            session_params['profile_name'] = profile_name
        if region:
            session_params['region_name'] = region

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

        self.findings = []
        self.good_practices = []
        self.available_models = []

        # Initialize check modules
        self.genai_checks = GenAISecurityChecks(self)
        self.iam_checks = IAMSecurityChecks(self)
        self.logging_checks = LoggingSecurityChecks(self)
        self.network_checks = NetworkSecurityChecks(self)
        self.tagging_checks = TaggingSecurityChecks(self)
        self.kb_checks = KnowledgeBaseSecurityChecks(self)

    def add_finding(self, risk_level: RiskLevel, category: str, resource: str,
                   issue: str, recommendation: str, fix_command: str = None,
                   learn_more: str = None, technical_details: str = None):
        """Add an enhanced security finding with risk scores and remediation."""
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
        """Track properly configured security practices."""
        self.good_practices.append({
            'category': category,
            'practice': practice
        })

    def _print_banner(self):
        """Display the Wilma ASCII art banner."""
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
        """Run all security checks based on the selected mode."""
        self._print_banner()
        print(f"[START] Running {self.mode.value} mode security check...")
        print("Let me take a look at your Bedrock security configuration...")
        print(f"Account: {self.account_id} | Region: {self.region}")
        print("=" * 60)

        # IAM and model access checks
        self.iam_checks.check_model_access_audit()

        # Logging and monitoring
        self.logging_checks.check_logging_monitoring()

        # Network security
        self.network_checks.check_vpc_endpoints()

        # Resource tagging
        self.tagging_checks.check_resource_tagging()

        # GenAI-specific checks
        self.genai_checks.check_prompt_injection_vulnerabilities()
        self.genai_checks.check_data_privacy_compliance()
        self.genai_checks.check_cost_anomaly_detection()

        # Knowledge Base (RAG) security checks
        self.kb_checks.run_all_checks()

        return self.findings
