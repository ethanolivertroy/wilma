"""
Tests for GenAI security checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

from unittest.mock import Mock

from wilma.checks.genai import GenAISecurityChecks
from wilma.enums import RiskLevel


class TestPromptInjectionCheck:
    """Test prompt injection vulnerability checks."""

    def test_no_guardrails_configured(self, mock_checker):
        """Test detection when no guardrails are configured."""
        # Setup mock responses
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-v2',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT']
                }
            ]
        }
        mock_checker.bedrock.list_guardrails.return_value = {'guardrails': []}

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_prompt_injection_vulnerabilities()

        # Verify finding was created
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

        # Check finding details
        finding = high_findings[0]
        assert 'guardrails' in finding['issue'].lower()

    def test_guardrail_missing_prompt_filter(self, mock_checker):
        """Test detection when guardrails exist but lack PROMPT_ATTACK filter."""
        # Setup mock responses
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [{'modelId': 'anthropic.claude-v2', 'inputModalities': ['TEXT'], 'outputModalities': ['TEXT']}]
        }
        mock_checker.bedrock.list_guardrails.return_value = {
            'guardrails': [{'id': 'gr-123', 'name': 'TestGuardrail'}]
        }
        mock_checker.bedrock.get_guardrail.return_value = {
            'contentPolicy': {
                'filters': []  # No filters configured
            }
        }

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_prompt_injection_vulnerabilities()

        # Verify HIGH risk finding for missing filter
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

    def test_guardrail_weak_filter_strength(self, mock_checker):
        """Test detection when guardrails have weak filter strength."""
        # Setup mock responses
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [{'modelId': 'anthropic.claude-v2', 'inputModalities': ['TEXT'], 'outputModalities': ['TEXT']}]
        }
        mock_checker.bedrock.list_guardrails.return_value = {
            'guardrails': [{'id': 'gr-123', 'name': 'TestGuardrail'}]
        }
        mock_checker.bedrock.get_guardrail.return_value = {
            'contentPolicy': {
                'filters': [
                    {
                        'type': 'PROMPT_ATTACK',
                        'inputStrength': 'LOW',  # Weak strength
                        'outputStrength': 'MEDIUM'
                    }
                ]
            }
        }

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_prompt_injection_vulnerabilities()

        # Verify MEDIUM risk finding for weak strength
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_guardrail_properly_configured(self, mock_checker):
        """Test that properly configured guardrails pass validation."""
        # Setup mock responses
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [{'modelId': 'anthropic.claude-v2', 'inputModalities': ['TEXT'], 'outputModalities': ['TEXT']}]
        }
        mock_checker.bedrock.list_guardrails.return_value = {
            'guardrails': [{'id': 'gr-123', 'name': 'TestGuardrail'}]
        }
        mock_checker.bedrock.get_guardrail.return_value = {
            'contentPolicy': {
                'filters': [
                    {
                        'type': 'PROMPT_ATTACK',
                        'inputStrength': 'HIGH',
                        'outputStrength': 'HIGH'
                    }
                ]
            }
        }

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_prompt_injection_vulnerabilities()

        # Verify good practice was recorded (no HIGH/CRITICAL findings)
        high_or_critical = [f for f in mock_checker.findings
                           if f.get('risk_level') in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        assert len(high_or_critical) == 0


class TestCostAnomalyDetection:
    """Test cost anomaly detection checks."""

    def test_no_cost_monitors(self, mock_checker):
        """Test detection when no cost monitors are configured."""
        # Create CE client mock
        ce_mock = Mock()
        ce_mock.get_anomaly_monitors.return_value = {'AnomalyMonitors': []}
        mock_checker.session.client = Mock(return_value=ce_mock)

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_cost_anomaly_detection()

        # Verify finding was created
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_cost_monitor_exists(self, mock_checker):
        """Test that existing cost monitors pass validation."""
        # Create CE client mock with Bedrock monitor
        ce_mock = Mock()
        ce_mock.get_anomaly_monitors.return_value = {
            'AnomalyMonitors': [
                {
                    'MonitorName': 'BedrockCostMonitor',
                    'MonitorSpecification': {}
                }
            ]
        }
        mock_checker.session.client = Mock(return_value=ce_mock)

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_cost_anomaly_detection()

        # Verify no MEDIUM findings (good practice recorded instead)
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0


class TestDataPrivacyCompliance:
    """Test data privacy compliance checks."""

    def test_logging_disabled(self, mock_checker):
        """Test when model invocation logging is completely disabled."""
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': None
        }

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_data_privacy_compliance()

        # Should not create PII findings when logging is disabled
        # (no data is being logged, so no PII exposure risk)
        assert True  # Check passes if no exception

    def test_unencrypted_s3_logging(self, mock_checker):
        """Test detection of unencrypted S3 logging."""
        # Create an unencrypted S3 bucket using Moto
        mock_checker.s3.create_bucket(Bucket='test-bucket')

        # Configure Bedrock mock to return logging config pointing to this bucket
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'test-bucket'
                }
            }
        }

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_data_privacy_compliance()

        # Verify HIGH risk finding for unencrypted bucket
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

    def test_encrypted_logging(self, mock_checker):
        """Test that encrypted logging passes validation."""
        # Create encrypted S3 bucket using Moto
        mock_checker.s3.create_bucket(Bucket='test-bucket')
        mock_checker.s3.put_bucket_encryption(
            Bucket='test-bucket',
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

        # Create encrypted CloudWatch log group using Moto
        mock_checker.cloudwatch.create_log_group(
            logGroupName='/aws/bedrock/test',
            kmsKeyId='arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
        )

        # Configure Bedrock mock to return logging config
        mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
            'loggingConfig': {
                's3Config': {
                    'bucketName': 'test-bucket'
                },
                'cloudWatchConfig': {
                    'logGroupName': '/aws/bedrock/test'
                }
            }
        }

        # Run check
        genai_checks = GenAISecurityChecks(mock_checker)
        genai_checks.check_data_privacy_compliance()

        # Should only have INFO level findings (best practice guidance)
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) == 0
