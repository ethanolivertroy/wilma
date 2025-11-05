"""
Logging and monitoring security checks

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from typing import List, Dict
from wilma.enums import SecurityMode, RiskLevel


class LoggingSecurityChecks:
    """Logging and monitoring security checks."""

    def __init__(self, checker):
        """Initialize with parent checker instance."""
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

        except Exception as e:
            print(f"[WARN] Could not check logging configuration: {str(e)}")

        return self.checker.findings
