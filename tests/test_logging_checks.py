"""
Tests for Logging and Monitoring security checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

from wilma.checks.logging import LoggingSecurityChecks
from wilma.enums import RiskLevel


class TestModelInvocationLogging:
    """Test model invocation logging checks."""

    def test_logging_disabled(self, mock_checker):
        """Test detection when model invocation logging is disabled."""
        # Configure Bedrock mock to return no logging config
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': None
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_model_invocation_logging()

        # Verify HIGH finding for disabled logging
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

    def test_logging_enabled_s3_only(self, mock_checker):
        """Test that S3-only logging passes validation."""
        # Configure Bedrock mock to return S3 logging config
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'bedrock-logs-bucket'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_model_invocation_logging()

        # Verify no MEDIUM findings (logging is enabled)
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'disabled' in f.get('title', '').lower()]
        assert len(medium_findings) == 0

    def test_logging_enabled_cloudwatch_only(self, mock_checker):
        """Test that CloudWatch-only logging passes validation."""
        # Configure Bedrock mock to return CloudWatch logging config
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_model_invocation_logging()

        # Verify no MEDIUM findings (logging is enabled)
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'disabled' in f.get('title', '').lower()]
        assert len(medium_findings) == 0

    def test_logging_enabled_both_targets(self, mock_checker):
        """Test that dual logging (S3 + CloudWatch) passes validation."""
        # Configure Bedrock mock to return both logging targets
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
        logging_checks.check_model_invocation_logging()

        # Verify no MEDIUM findings
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'disabled' in f.get('title', '').lower()]
        assert len(medium_findings) == 0


class TestLogRetention:
    """Test log retention policy checks."""

    def test_insufficient_retention(self, mock_checker):
        """Test detection of insufficient log retention."""
        # Create log group with insufficient retention using Moto
        mock_checker.cloudwatch.create_log_group(
            logGroupName='/aws/bedrock/modelinvocations'
        )
        mock_checker.cloudwatch.put_retention_policy(
            logGroupName='/aws/bedrock/modelinvocations',
            retentionInDays=7  # Too short
        )

        # Configure Bedrock mock
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_log_retention()

        # Verify MEDIUM finding for insufficient retention
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_adequate_retention(self, mock_checker):
        """Test that adequate retention passes validation."""
        # Create log group with adequate retention using Moto
        mock_checker.cloudwatch.create_log_group(
            logGroupName='/aws/bedrock/modelinvocations'
        )
        mock_checker.cloudwatch.put_retention_policy(
            logGroupName='/aws/bedrock/modelinvocations',
            retentionInDays=365  # Adequate
        )

        # Configure Bedrock mock
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_log_retention()

        # Verify no MEDIUM findings (retention is adequate)
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0

    def test_no_retention_policy(self, mock_checker):
        """Test detection when no retention policy is set (indefinite retention)."""
        # Create log group without retention policy using Moto
        mock_checker.cloudwatch.create_log_group(
            logGroupName='/aws/bedrock/modelinvocations'
        )
        # Don't set retention policy - defaults to indefinite

        # Configure Bedrock mock
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_log_retention()

        # Indefinite retention is acceptable for compliance
        # Should not create MEDIUM findings
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0


class TestLogEncryption:
    """Test log encryption checks."""

    def test_unencrypted_cloudwatch_logs(self, mock_checker):
        """Test detection of unencrypted CloudWatch logs."""
        # Create unencrypted log group using Moto
        mock_checker.cloudwatch.create_log_group(
            logGroupName='/aws/bedrock/modelinvocations'
        )

        # Configure Bedrock mock
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_log_encryption()

        # Verify HIGH finding for unencrypted logs
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

    def test_encrypted_cloudwatch_logs(self, mock_checker):
        """Test that encrypted CloudWatch logs pass validation."""
        # Create encrypted log group using Moto
        mock_checker.cloudwatch.create_log_group(
            logGroupName='/aws/bedrock/modelinvocations',
            kmsKeyId='arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
        )

        # Configure Bedrock mock
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/modelinvocations'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_log_encryption()

        # Verify no HIGH findings (logs are encrypted)
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) == 0

    def test_unencrypted_s3_logs(self, mock_checker):
        """Test detection of unencrypted S3 log storage."""
        # Create unencrypted S3 bucket using Moto
        mock_checker.s3.create_bucket(Bucket='bedrock-logs-bucket')

        # Configure Bedrock mock
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'bedrock-logs-bucket'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_log_encryption()

        # Verify HIGH finding for unencrypted S3
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

    def test_encrypted_s3_logs(self, mock_checker):
        """Test that encrypted S3 log storage passes validation."""
        # Create encrypted S3 bucket using Moto
        mock_checker.s3.create_bucket(Bucket='bedrock-logs-bucket')
        mock_checker.s3.put_bucket_encryption(
            Bucket='bedrock-logs-bucket',
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
                        }
                    }
                ]
            }
        )

        # Configure Bedrock mock
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'bedrock-logs-bucket'
                }
            }
        }

        # Run check
        logging_checks = LoggingSecurityChecks(mock_checker)
        logging_checks.check_log_encryption()

        # Verify no HIGH findings (S3 is encrypted)
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) == 0
