"""
Tests for IAM security checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import json

from wilma.checks.iam import IAMSecurityChecks
from wilma.enums import RiskLevel


class TestOverlyPermissivePolicies:
    """Test overly permissive IAM policy checks."""

    def test_wildcard_permissions_detected(self, mock_checker):
        """Test detection of wildcard Bedrock permissions."""
        # Create an overly permissive IAM policy using Moto
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': 'bedrock:*',
                    'Resource': '*'
                }
            ]
        }

        mock_checker.iam.create_policy(
            PolicyName='BedrockFullAccess',
            PolicyDocument=json.dumps(policy_document)
        )

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        iam_checks.check_overly_permissive_policies()

        # Verify CRITICAL finding was created
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) > 0

    def test_least_privilege_policy(self, mock_checker):
        """Test that least-privilege policies pass validation."""
        # Create a least-privilege IAM policy using Moto
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': ['bedrock:GetFoundationModel', 'bedrock:ListFoundationModels'],
                    'Resource': 'arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2'
                }
            ]
        }

        mock_checker.iam.create_policy(
            PolicyName='BedrockReadOnly',
            PolicyDocument=json.dumps(policy_document)
        )

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        iam_checks.check_overly_permissive_policies()

        # Verify no CRITICAL findings (good practice recorded instead)
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) == 0


class TestAWSManagedPolicies:
    """Test AWS-managed policy checks."""

    def test_administrator_access_detected(self, mock_checker):
        """Test detection of AdministratorAccess policy."""
        # Create IAM role and attach AdministratorAccess using Moto
        trust_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'bedrock.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }]
        }

        mock_checker.iam.create_role(
            RoleName='BedrockExecutionRole',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )

        mock_checker.iam.attach_role_policy(
            RoleName='BedrockExecutionRole',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        iam_checks.check_overly_permissive_policies()

        # Verify CRITICAL finding for AdministratorAccess
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) > 0
        assert any('AdministratorAccess' in f.get('title', '') for f in critical_findings)

    def test_power_user_access_detected(self, mock_checker):
        """Test detection of PowerUserAccess policy."""
        # Create IAM role and attach PowerUserAccess using Moto
        trust_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'bedrock.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }]
        }

        mock_checker.iam.create_role(
            RoleName='BedrockRole',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )

        mock_checker.iam.attach_role_policy(
            RoleName='BedrockRole',
            PolicyArn='arn:aws:iam::aws:policy/PowerUserAccess'
        )

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        iam_checks.check_overly_permissive_policies()

        # Verify HIGH risk finding for PowerUserAccess
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0


class TestCrossAccountAccess:
    """Test cross-account access checks."""

    def test_external_account_access_detected(self, mock_checker):
        """Test detection of cross-account trust relationships."""
        # Create IAM role with cross-account trust policy using Moto
        trust_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
                'Action': 'sts:AssumeRole'
            }]
        }

        mock_checker.iam.create_role(
            RoleName='BedrockRole',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        iam_checks.check_cross_account_access()

        # Verify finding was created for external account
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_same_account_access_allowed(self, mock_checker):
        """Test that same-account access passes validation."""
        # Create IAM role with service principal trust policy using Moto
        trust_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'bedrock.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }]
        }

        mock_checker.iam.create_role(
            RoleName='BedrockRole',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        iam_checks.check_cross_account_access()

        # Verify no MEDIUM findings (service principal is okay)
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0


class TestRoleSessionDuration:
    """Test role session duration checks."""

    def test_excessive_session_duration(self, mock_checker):
        """Test detection of excessive session duration."""
        # Create IAM role with excessive session duration using Moto
        trust_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'bedrock.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }]
        }

        mock_checker.iam.create_role(
            RoleName='BedrockRole',
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            MaxSessionDuration=43200  # 12 hours
        )

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        iam_checks.check_role_session_duration()

        # Verify MEDIUM finding for excessive duration
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_acceptable_session_duration(self, mock_checker):
        """Test that short session durations pass validation."""
        # Create IAM role with acceptable session duration using Moto
        trust_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'bedrock.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }]
        }

        mock_checker.iam.create_role(
            RoleName='BedrockRole',
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            MaxSessionDuration=3600  # 1 hour
        )

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        iam_checks.check_role_session_duration()

        # Verify no MEDIUM findings (1 hour is acceptable)
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0
