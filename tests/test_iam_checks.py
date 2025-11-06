"""
Tests for IAM security checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import pytest
from unittest.mock import Mock, patch
from wilma.checks.iam import IAMSecurityChecks
from wilma.enums import RiskLevel


class TestOverlyPermissivePolicies:
    """Test overly permissive IAM policy checks."""

    def test_wildcard_permissions_detected(self, mock_checker):
        """Test detection of wildcard Bedrock permissions."""
        # Setup mock responses
        mock_checker.iam.list_policies.return_value = {
            'Policies': [
                {
                    'PolicyName': 'BedrockFullAccess',
                    'Arn': 'arn:aws:iam::123456789012:policy/BedrockFullAccess',
                    'DefaultVersionId': 'v1'
                }
            ]
        }
        mock_checker.iam.get_policy_version.return_value = {
            'PolicyVersion': {
                'Document': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': 'bedrock:*',
                            'Resource': '*'
                        }
                    ]
                }
            }
        }

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        findings = iam_checks.check_overly_permissive_policies()

        # Verify CRITICAL finding was created
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) > 0

    def test_least_privilege_policy(self, mock_checker):
        """Test that least-privilege policies pass validation."""
        # Setup mock responses
        mock_checker.iam.list_policies.return_value = {
            'Policies': [
                {
                    'PolicyName': 'BedrockReadOnly',
                    'Arn': 'arn:aws:iam::123456789012:policy/BedrockReadOnly',
                    'DefaultVersionId': 'v1'
                }
            ]
        }
        mock_checker.iam.get_policy_version.return_value = {
            'PolicyVersion': {
                'Document': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': ['bedrock:GetFoundationModel', 'bedrock:ListFoundationModels'],
                            'Resource': 'arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2'
                        }
                    ]
                }
            }
        }

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        findings = iam_checks.check_overly_permissive_policies()

        # Verify no CRITICAL findings (good practice recorded instead)
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) == 0


class TestAWSManagedPolicies:
    """Test AWS-managed policy checks."""

    def test_administrator_access_detected(self, mock_checker):
        """Test detection of AdministratorAccess policy."""
        # Setup mock responses
        mock_checker.iam.list_roles.return_value = {
            'Roles': [
                {
                    'RoleName': 'BedrockExecutionRole',
                    'Arn': 'arn:aws:iam::123456789012:role/BedrockExecutionRole'
                }
            ]
        }
        mock_checker.iam.list_attached_role_policies.return_value = {
            'AttachedPolicies': [
                {
                    'PolicyName': 'AdministratorAccess',
                    'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
                }
            ]
        }

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        findings = iam_checks.check_overly_permissive_policies()

        # Verify CRITICAL finding for AdministratorAccess
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) > 0
        assert any('AdministratorAccess' in f.get('title', '') for f in critical_findings)

    def test_power_user_access_detected(self, mock_checker):
        """Test detection of PowerUserAccess policy."""
        # Setup mock responses
        mock_checker.iam.list_roles.return_value = {
            'Roles': [
                {
                    'RoleName': 'BedrockRole',
                    'Arn': 'arn:aws:iam::123456789012:role/BedrockRole'
                }
            ]
        }
        mock_checker.iam.list_attached_role_policies.return_value = {
            'AttachedPolicies': [
                {
                    'PolicyName': 'PowerUserAccess',
                    'PolicyArn': 'arn:aws:iam::aws:policy/PowerUserAccess'
                }
            ]
        }

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        findings = iam_checks.check_overly_permissive_policies()

        # Verify HIGH risk finding for PowerUserAccess
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0


class TestCrossAccountAccess:
    """Test cross-account access checks."""

    def test_external_account_access_detected(self, mock_checker):
        """Test detection of cross-account trust relationships."""
        # Setup mock responses
        mock_checker.iam.list_roles.return_value = {
            'Roles': [
                {
                    'RoleName': 'BedrockRole',
                    'Arn': 'arn:aws:iam::123456789012:role/BedrockRole',
                    'AssumeRolePolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [
                            {
                                'Effect': 'Allow',
                                'Principal': {
                                    'AWS': 'arn:aws:iam::999999999999:root'
                                },
                                'Action': 'sts:AssumeRole'
                            }
                        ]
                    }
                }
            ]
        }

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        findings = iam_checks.check_cross_account_access()

        # Verify finding was created for external account
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_same_account_access_allowed(self, mock_checker):
        """Test that same-account access passes validation."""
        # Setup mock responses
        mock_checker.iam.list_roles.return_value = {
            'Roles': [
                {
                    'RoleName': 'BedrockRole',
                    'Arn': 'arn:aws:iam::123456789012:role/BedrockRole',
                    'AssumeRolePolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [
                            {
                                'Effect': 'Allow',
                                'Principal': {
                                    'Service': 'bedrock.amazonaws.com'
                                },
                                'Action': 'sts:AssumeRole'
                            }
                        ]
                    }
                }
            ]
        }

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        findings = iam_checks.check_cross_account_access()

        # Verify no MEDIUM findings (service principal is okay)
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0


class TestRoleSessionDuration:
    """Test role session duration checks."""

    def test_excessive_session_duration(self, mock_checker):
        """Test detection of excessive session duration."""
        # Setup mock responses
        mock_checker.iam.list_roles.return_value = {
            'Roles': [
                {
                    'RoleName': 'BedrockRole',
                    'Arn': 'arn:aws:iam::123456789012:role/BedrockRole',
                    'MaxSessionDuration': 43200  # 12 hours
                }
            ]
        }

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        findings = iam_checks.check_role_session_duration()

        # Verify MEDIUM finding for excessive duration
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_acceptable_session_duration(self, mock_checker):
        """Test that short session durations pass validation."""
        # Setup mock responses
        mock_checker.iam.list_roles.return_value = {
            'Roles': [
                {
                    'RoleName': 'BedrockRole',
                    'Arn': 'arn:aws:iam::123456789012:role/BedrockRole',
                    'MaxSessionDuration': 3600  # 1 hour
                }
            ]
        }

        # Run check
        iam_checks = IAMSecurityChecks(mock_checker)
        findings = iam_checks.check_role_session_duration()

        # Verify no MEDIUM findings (1 hour is acceptable)
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0
