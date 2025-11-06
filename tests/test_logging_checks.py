"""
Tests for Logging and Monitoring security checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import pytest
from unittest.mock import Mock, patch
from wilma.checks.logging import LoggingSecurityChecks
from wilma.enums import RiskLevel


class TestModelInvocationLogging:
    """Test model invocation logging checks."""

    def test_logging_disabled(self, mock_checker):
        """Test detection when model invocation logging is disabled."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': None
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        findings = logging_checks.check_model_invocation_logging()

        # Verify MEDIUM finding for disabled logging
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_logging_enabled_s3_only(self, mock_checker):
        """Test that S3-only logging passes validation."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'bedrock-logs-bucket'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        findings = logging_checks.check_model_invocation_logging()

        # Verify no MEDIUM findings (logging is enabled)
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'disabled' in f.get('title', '').lower()]
        assert len(medium_findings) == 0

    def test_logging_enabled_cloudwatch_only(self, mock_checker):
        """Test that CloudWatch-only logging passes validation."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        findings = logging_checks.check_model_invocation_logging()

        # Verify no MEDIUM findings (logging is enabled)
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'disabled' in f.get('title', '').lower()]
        assert len(medium_findings) == 0

    def test_logging_enabled_both_targets(self, mock_checker):
        """Test that dual logging (S3 + CloudWatch) passes validation."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'bedrock-logs-bucket'
                },
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        findings = logging_checks.check_model_invocation_logging()

        # Verify no MEDIUM findings
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'disabled' in f.get('title', '').lower()]
        assert len(medium_findings) == 0


class TestLogRetention:
    """Test log retention policy checks."""

    def test_insufficient_retention(self, mock_checker):
        """Test detection of insufficient log retention."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }
        mock_checker.logs.describe_log_groups.return_value = {
            'logGroups': [
                {
                    'logGroupName': '/aws/bedrock/modelinvocations',
                    'retentionInDays': 7  # Too short
                }
            ]
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        findings = logging_checks.check_log_retention()

        # Verify MEDIUM finding for insufficient retention
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_adequate_retention(self, mock_checker):
        """Test that adequate retention passes validation."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }
        mock_checker.logs.describe_log_groups.return_value = {
            'logGroups': [
                {
                    'logGroupName': '/aws/bedrock/modelinvocations',
                    'retentionInDays': 365  # Adequate
                }
            ]
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        findings = logging_checks.check_log_retention()

        # Verify no MEDIUM findings (retention is adequate)
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0

    def test_no_retention_policy(self, mock_checker):
        """Test detection when no retention policy is set (indefinite retention)."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }
        mock_checker.logs.describe_log_groups.return_value = {
            'logGroups': [
                {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                    # No retentionInDays key = indefinite retention
                }
            ]
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        findings = logging_checks.check_log_retention()

        # Indefinite retention is acceptable for compliance
        # Should not create MEDIUM findings
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0


class TestLogEncryption:
    """Test log encryption checks."""

    def test_unencrypted_cloudwatch_logs(self, mock_checker):
        """Test detection of unencrypted CloudWatch logs."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Mock CloudWatch encryption check to return unencrypted
        with patch('wilma.checks.logging.check_log_group_encryption') as mock_check:
            mock_check.return_value = {'exists': True, 'encrypted': False}

            # Run check
            logging_checks = LoggingSecurityChecks(mock_checker)
            findings = logging_checks.check_log_encryption()

            # Verify HIGH finding for unencrypted logs
            high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
            assert len(high_findings) > 0

    def test_encrypted_cloudwatch_logs(self, mock_checker):
        """Test that encrypted CloudWatch logs pass validation."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Mock CloudWatch encryption check to return encrypted
        with patch('wilma.checks.logging.check_log_group_encryption') as mock_check:
            mock_check.return_value = {'exists': True, 'encrypted': True, 'kms_key_id': 'arn:aws:kms:us-east-1:123456789012:key/12345'}

            # Run check
            logging_checks = LoggingSecurityChecks(mock_checker)
            findings = logging_checks.check_log_encryption()

            # Verify no HIGH findings (logs are encrypted)
            high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
            assert len(high_findings) == 0

    def test_unencrypted_s3_logs(self, mock_checker):
        """Test detection of unencrypted S3 log storage."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'bedrock-logs-bucket'
                }
            }
        }

        # Mock S3 encryption check to return unencrypted
        with patch('wilma.checks.logging.check_s3_bucket_encryption') as mock_check:
            mock_check.return_value = {'encrypted': False}

            # Run check
            logging_checks = LoggingSecurityChecks(mock_checker)
            findings = logging_checks.check_log_encryption()

            # Verify HIGH finding for unencrypted S3
            high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
            assert len(high_findings) > 0

    def test_encrypted_s3_logs(self, mock_checker):
        """Test that encrypted S3 log storage passes validation."""
        # Setup mock responses
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'bedrock-logs-bucket'
                }
            }
        }

        # Mock S3 encryption check to return encrypted
        with patch('wilma.checks.logging.check_s3_bucket_encryption') as mock_check:
            mock_check.return_value = {'encrypted': True, 'uses_customer_key': True}

            # Run check
            logging_checks = LoggingSecurityChecks(mock_checker)
            findings = logging_checks.check_log_encryption()

            # Verify no HIGH findings (S3 is encrypted)
            high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
            assert len(high_findings) == 0
