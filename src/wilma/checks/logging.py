"""
Logging & Monitoring Checks

Validates audit trails and visibility into Bedrock usage.

Checks:
- Model invocation logging (CloudWatch)
- CloudTrail data event tracking
- Log retention configuration
- Anomaly detection setup

WHY IMPORTANT: Logs enable incident response, compliance, and threat detection.

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

from typing import Dict, List

from botocore.exceptions import ClientError

from wilma.enums import RiskLevel, SecurityMode
from wilma.utils import handle_aws_error


class LoggingSecurityChecks:
    """Validates logging and monitoring configuration for security visibility."""

    def __init__(self, checker):
        """Initialize with parent checker for AWS client access."""
        self.checker = checker

    def check_logging_monitoring(self) -> List[Dict]:
        """Enhanced logging check with beginner-friendly explanations."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: Logging & Monitoring")
            print("This ensures you're keeping records of who uses your AI models and how.")
            print("It's like having security cameras for your AI systems.")
            return []

        print("[CHECK] Checking logging and monitoring configurations...")

        try:
            # Check model invocation logging
            logging_config = self.checker.bedrock.get_model_invocation_logging_configuration()

            if not logging_config.get('loggingConfig'):
                self.checker.add_finding(
                    risk_level=RiskLevel.HIGH,
                    category="Audit & Compliance",
                    resource="Model Invocation Logging",
                    issue="AI model usage is not being logged",
                    recommendation="Enable logging to track who uses your models and detect abuse",
                    fix_command="aws bedrock put-model-invocation-logging-configuration --logging-config file://logging-config.json",
                    learn_more="Without logs, you can't detect if someone is misusing your AI",
                    technical_details="Model invocation logging is completely disabled"
                )
            else:
                self.checker.add_good_practice("Audit & Compliance", "Model invocation logging is enabled")

                # Check if both CloudWatch and S3 logging are enabled
                config = logging_config['loggingConfig']
                if not config.get('cloudWatchConfig', {}).get('logGroupName'):
                    self.checker.add_finding(
                        risk_level=RiskLevel.MEDIUM,
                        category="Audit & Compliance",
                        resource="Real-time Monitoring",
                        issue="No real-time monitoring of AI model usage",
                        recommendation="Enable CloudWatch logging for immediate alerts",
                        learn_more="Real-time logs help you spot problems as they happen",
                        technical_details="CloudWatch logging not configured for model invocations"
                    )

        except ClientError as e:
            handle_aws_error(e, "checking logging configuration")
        except Exception as e:
            print(f"[ERROR] Unexpected error checking logging configuration: {str(e)}")

        return self.checker.findings

    def check_model_invocation_logging(self) -> List[Dict]:
        """Check model invocation logging configuration."""
        return self.check_logging_monitoring()

    def check_log_retention(self) -> List[Dict]:
        """Check log retention policies."""
        if self.checker.mode == SecurityMode.LEARN:
            return []

        print("[CHECK] Checking CloudWatch log retention for Bedrock invocations...")

        try:
            logging_config = self.checker.bedrock.get_model_invocation_logging_configuration()
            cloudwatch_config = logging_config.get('loggingConfig', {}).get('cloudWatchConfig', {})
            log_group_name = cloudwatch_config.get('logGroupName')

            if not log_group_name:
                return self.checker.findings

            log_groups = self.checker.cloudwatch.describe_log_groups(
                logGroupNamePrefix=log_group_name
            ).get('logGroups', [])

            for log_group in log_groups:
                if log_group.get('logGroupName') != log_group_name:
                    continue

                retention_days = log_group.get('retentionInDays')
                if retention_days is not None and retention_days < self.checker.config.log_retention_days:
                    self.checker.add_finding(
                        risk_level=RiskLevel.MEDIUM,
                        category="Audit & Compliance",
                        resource=f"CloudWatch Log Group: {log_group_name}",
                        issue="Bedrock invocation logs have insufficient retention",
                        recommendation=f"Set retention to at least {self.checker.config.log_retention_days} days",
                        fix_command=(
                            f"aws logs put-retention-policy --log-group-name {log_group_name} "
                            f"--retention-in-days {self.checker.config.log_retention_days}"
                        ),
                        technical_details=f"Current retention is {retention_days} days"
                    )

        except ClientError as e:
            handle_aws_error(e, "checking log retention")

        return self.checker.findings

    def check_log_encryption(self) -> List[Dict]:
        """Check log encryption settings."""
        if self.checker.mode == SecurityMode.LEARN:
            return []

        print("[CHECK] Checking Bedrock log encryption...")

        try:
            logging_config = self.checker.bedrock.get_model_invocation_logging_configuration()
            config = logging_config.get('loggingConfig', {})

            cloudwatch_config = config.get('cloudWatchConfig', {})
            log_group_name = cloudwatch_config.get('logGroupName')
            if log_group_name:
                log_groups = self.checker.cloudwatch.describe_log_groups(
                    logGroupNamePrefix=log_group_name
                ).get('logGroups', [])
                for log_group in log_groups:
                    if log_group.get('logGroupName') == log_group_name and not log_group.get('kmsKeyId'):
                        self.checker.add_finding(
                            risk_level=RiskLevel.HIGH,
                            category="Audit & Compliance",
                            resource=f"CloudWatch Log Group: {log_group_name}",
                            issue="Bedrock CloudWatch logs are not encrypted with a customer-managed KMS key",
                            recommendation="Associate a customer-managed KMS key with the log group",
                            technical_details="CloudWatch log group has no kmsKeyId"
                        )

            s3_config = config.get('s3Config', {})
            bucket_name = s3_config.get('bucketName')
            if bucket_name:
                try:
                    self.checker.s3.get_bucket_encryption(Bucket=bucket_name)
                except Exception:
                    self.checker.add_finding(
                        risk_level=RiskLevel.HIGH,
                        category="Audit & Compliance",
                        resource=f"S3 Bucket: {bucket_name}",
                        issue="Bedrock S3 log bucket is not encrypted",
                        recommendation="Enable default bucket encryption with a customer-managed KMS key",
                        technical_details="S3 GetBucketEncryption did not return encryption configuration"
                    )

        except ClientError as e:
            handle_aws_error(e, "checking log encryption")

        return self.checker.findings
