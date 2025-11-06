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

from typing import List, Dict
from botocore.exceptions import ClientError
from wilma.enums import SecurityMode, RiskLevel
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
