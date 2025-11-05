"""
GenAI-specific security checks for AWS Bedrock

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from typing import List, Dict
from wilma.enums import SecurityMode, RiskLevel


class GenAISecurityChecks:
    """GenAI-specific security checks for Bedrock."""

    # Common PII patterns for data privacy checks
    PII_PATTERNS = {
        'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
        'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'Phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'Credit Card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'IP Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    }

    # Common prompt injection patterns
    PROMPT_INJECTION_PATTERNS = [
        "ignore previous instructions",
        "disregard all prior commands",
        "system prompt",
        "reveal your instructions",
        "what are your rules",
        "bypass security",
        "jailbreak",
        "DAN mode",
        "developer mode"
    ]

    def __init__(self, checker):
        """Initialize with parent checker instance."""
        self.checker = checker

    def check_prompt_injection_vulnerabilities(self) -> List[Dict]:
        """Check for prompt injection vulnerabilities in model configurations."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: Prompt Injection Check")
            print("This check tests if your AI models are vulnerable to prompt injection attacks.")
            print("Prompt injection is when an attacker tries to override your model's instructions.")
            return []

        print("[CHECK] Checking for prompt injection vulnerabilities...")

        try:
            # List available models
            foundation_models = self.checker.bedrock.list_foundation_models()

            # Check if any models are accessible without proper guardrails
            accessible_models = []
            for model in foundation_models.get('modelSummaries', []):
                model_id = model.get('modelId', '')
                if 'claude' in model_id.lower() or 'titan' in model_id.lower():
                    accessible_models.append(model_id)
                    self.checker.available_models.append(model_id)

            if accessible_models:
                # Check for guardrails
                try:
                    guardrails = self.checker.bedrock.list_guardrails()
                    if not guardrails.get('guardrails'):
                        self.checker.add_finding(
                            risk_level=RiskLevel.HIGH,
                            category="GenAI Security",
                            resource="Model Guardrails",
                            issue="No guardrails configured to prevent prompt injection",
                            recommendation="Set up AWS Bedrock Guardrails to filter harmful prompts",
                            fix_command="aws bedrock create-guardrail --name 'SecurityGuardrail' --topic-policy-config file://guardrail-config.json",
                            learn_more="Guardrails help prevent prompt injection, jailbreaking, and harmful content generation",
                            technical_details="Without guardrails, models are vulnerable to prompt injection attacks that could bypass safety measures"
                        )
                    else:
                        self.checker.add_good_practice("GenAI Security", "Guardrails are configured for prompt filtering")
                except:
                    # Guardrails might not be available in all regions
                    pass

        except Exception as e:
            print(f"[WARN] Note: Could not complete prompt injection check: {str(e)}")

        return self.checker.findings

    def check_data_privacy_compliance(self) -> List[Dict]:
        """Check for potential PII exposure in model configurations and logs."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: Data Privacy Check")
            print("This check looks for potential Personal Identifiable Information (PII) exposure.")
            print("PII includes SSNs, emails, credit cards, etc. that could be logged or stored.")
            return []

        print("[CHECK] Checking data privacy compliance...")

        try:
            # Check if model invocation logs might contain PII
            logging_config = self.checker.bedrock.get_model_invocation_logging_configuration()

            if logging_config.get('loggingConfig'):
                config = logging_config['loggingConfig']

                # Check if logs are encrypted
                s3_config = config.get('s3Config', {})
                if s3_config.get('bucketName'):
                    bucket_name = s3_config['bucketName']

                    # Check bucket encryption
                    try:
                        encryption = self.checker.s3.get_bucket_encryption(Bucket=bucket_name)
                        self.checker.add_good_practice("Data Privacy", f"S3 bucket {bucket_name} is encrypted for log storage")
                    except self.checker.s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                        self.checker.add_finding(
                            risk_level=RiskLevel.HIGH,
                            category="Data Privacy",
                            resource=f"S3 Bucket: {bucket_name}",
                            issue="Model invocation logs stored in unencrypted S3 bucket",
                            recommendation="Enable encryption on the S3 bucket storing sensitive logs",
                            fix_command=f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration file://encryption-config.json",
                            learn_more="Unencrypted logs may expose sensitive user data or PII",
                            technical_details="S3 bucket lacks SSE-S3 or SSE-KMS encryption"
                        )

                # Warn about PII in logs
                self.checker.add_finding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Data Privacy",
                    resource="Model Invocation Logs",
                    issue="Model logs might contain PII from user prompts",
                    recommendation="Implement PII filtering before logging or use data masking",
                    learn_more="User prompts often contain names, addresses, or other sensitive data",
                    technical_details="Consider implementing a PII detection Lambda function in the logging pipeline"
                )

        except Exception as e:
            print(f"[WARN] Note: Could not complete data privacy check: {str(e)}")

        return self.checker.findings

    def check_cost_anomaly_detection(self) -> List[Dict]:
        """Check for cost monitoring to detect potential abuse."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: Cost Anomaly Detection")
            print("This checks if you're monitoring AI usage costs to detect potential abuse.")
            print("Unexpected high costs might indicate someone is misusing your models.")
            return []

        print("[CHECK] Checking cost anomaly detection...")

        try:
            # This is a simplified check - in reality, you'd check AWS Cost Anomaly Detection
            self.checker.add_finding(
                risk_level=RiskLevel.MEDIUM,
                category="Cost Security",
                resource="Bedrock Usage Monitoring",
                issue="No automated cost alerts for unusual Bedrock usage",
                recommendation="Set up AWS Cost Anomaly Detection for Bedrock services",
                fix_command="aws ce create-anomaly-monitor --anomaly-monitor Name=BedrockMonitor,MonitorType=CUSTOM,MonitorSpecification={Tags:{Key=Service,Values=[bedrock]}}",
                learn_more="Unusual spikes in AI usage costs might indicate security breaches",
                technical_details="Enable AWS Cost Anomaly Detection with Bedrock-specific monitors"
            )

        except Exception as e:
            print(f"[WARN] Could not check cost monitoring: {str(e)}")

        return self.checker.findings
