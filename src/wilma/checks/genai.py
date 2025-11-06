"""
GenAI-Specific Security Checks

Validates threats unique to generative AI systems based on OWASP LLM Top 10 2025.

Checks:
- Prompt Injection (OWASP LLM01): Guardrail configuration
- Data Privacy (OWASP LLM06): PII pattern detection in configs
- Cost Anomaly Detection: Monitors for usage-based attacks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

from typing import Dict, List

from botocore.exceptions import ClientError

from wilma.enums import RiskLevel, SecurityMode
from wilma.utils import handle_aws_error


class GenAISecurityChecks:
    """
    GenAI threat detection for Bedrock.

    Focuses on OWASP LLM Top 10 risks specific to foundation models.
    """

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
            # Check ALL foundation models (Claude, Titan, AI21, Cohere, Meta, Mistral, Stability, etc.)
            accessible_models = []
            for model in foundation_models.get('modelSummaries', []):
                model_id = model.get('modelId', '')
                # Include all text/chat models, not just Claude and Titan
                model_modalities = model.get('inputModalities', []) + model.get('outputModalities', [])
                if 'TEXT' in model_modalities or 'EMBEDDING' in model_modalities:
                    accessible_models.append(model_id)
                    self.checker.available_models.append(model_id)

            if accessible_models:
                # Check for guardrails and validate their configuration
                try:
                    guardrails_list = self.checker.bedrock.list_guardrails()
                    guardrails = guardrails_list.get('guardrails', [])

                    if not guardrails:
                        self.checker.add_finding(
                            risk_level=RiskLevel.HIGH,
                            category="GenAI Security",
                            resource="Model Guardrails",
                            issue="No guardrails configured to prevent prompt injection",
                            recommendation="Set up AWS Bedrock Guardrails to filter harmful prompts",
                            fix_command=(
                                "aws bedrock create-guardrail --name 'SecurityGuardrail' \\\n"
                                "  --blocked-input-messaging 'Request blocked by security policy' \\\n"
                                "  --blocked-outputs-messaging 'Response blocked by security policy' \\\n"
                                "  --content-policy-config 'filtersConfig=[{type=PROMPT_ATTACK,inputStrength=HIGH,outputStrength=HIGH}]'"
                            ),
                            learn_more="Guardrails help prevent prompt injection, jailbreaking, and harmful content generation",
                            technical_details="Without guardrails, models are vulnerable to prompt injection attacks that could bypass safety measures"
                        )
                    else:
                        # Guardrails exist - validate their configuration
                        weak_guardrails = []
                        missing_prompt_filter = []
                        properly_configured = []

                        for guardrail_summary in guardrails:
                            guardrail_id = guardrail_summary['id']
                            guardrail_name = guardrail_summary.get('name', guardrail_id)

                            try:
                                # Get detailed guardrail configuration
                                guardrail_details = self.checker.bedrock.get_guardrail(
                                    guardrailIdentifier=guardrail_id
                                )

                                content_policy = guardrail_details.get('contentPolicy', {})
                                filters = content_policy.get('filters', [])

                                # Check for PROMPT_ATTACK filter
                                has_prompt_filter = False
                                prompt_filter_weak = False

                                for filter_config in filters:
                                    filter_type = filter_config.get('type')
                                    if filter_type == 'PROMPT_ATTACK':
                                        has_prompt_filter = True

                                        # Check filter strength
                                        input_strength = filter_config.get('inputStrength', 'NONE')
                                        output_strength = filter_config.get('outputStrength', 'NONE')

                                        if input_strength in ['LOW', 'MEDIUM'] or output_strength in ['LOW', 'MEDIUM']:
                                            prompt_filter_weak = True
                                            weak_guardrails.append((guardrail_name, input_strength, output_strength))

                                if not has_prompt_filter:
                                    missing_prompt_filter.append(guardrail_name)
                                elif not prompt_filter_weak:
                                    properly_configured.append(guardrail_name)

                            except ClientError as e:
                                if e.response['Error']['Code'] not in ['AccessDenied', 'ResourceNotFoundException']:
                                    raise

                        # Report findings
                        if missing_prompt_filter:
                            self.checker.add_finding(
                                risk_level=RiskLevel.HIGH,
                                category="GenAI Security",
                                resource=f"Guardrails: {', '.join(missing_prompt_filter)}",
                                issue="Guardrails exist but lack PROMPT_ATTACK filter",
                                recommendation="Add PROMPT_ATTACK content filter to guardrails",
                                fix_command=(
                                    "aws bedrock update-guardrail --guardrail-identifier GUARDRAIL_ID \\\n"
                                    "  --content-policy-config 'filtersConfig=[{type=PROMPT_ATTACK,inputStrength=HIGH,outputStrength=HIGH}]'"
                                ),
                                learn_more="PROMPT_ATTACK filters detect and block prompt injection attempts",
                                technical_details=f"Guardrails missing prompt injection protection: {', '.join(missing_prompt_filter)}"
                            )

                        if weak_guardrails:
                            for name, input_str, output_str in weak_guardrails:
                                self.checker.add_finding(
                                    risk_level=RiskLevel.MEDIUM,
                                    category="GenAI Security",
                                    resource=f"Guardrail: {name}",
                                    issue=f"Guardrail has weak prompt filter strength (input:{input_str}, output:{output_str})",
                                    recommendation="Increase PROMPT_ATTACK filter strength to HIGH for better protection",
                                    fix_command=(
                                        f"aws bedrock update-guardrail --guardrail-identifier {name} \\\n"
                                        f"  --content-policy-config 'filtersConfig=[{{type=PROMPT_ATTACK,inputStrength=HIGH,outputStrength=HIGH}}]'"
                                    ),
                                    learn_more="LOW/MEDIUM strength allows more prompt injection attempts to pass through",
                                    technical_details="Filter strength should be HIGH for maximum protection against sophisticated attacks"
                                )

                        if properly_configured:
                            self.checker.add_good_practice(
                                "GenAI Security",
                                f"Guardrails properly configured with HIGH strength prompt filters: {', '.join(properly_configured)}"
                            )

                except ClientError as e:
                    if e.response['Error']['Code'] == 'ValidationException':
                        # Guardrails not available in this region
                        print("[INFO] Guardrails feature not available in this region - skipping prompt injection check")
                    else:
                        handle_aws_error(e, "checking guardrails configuration")
                except Exception as e:
                    print(f"[WARN] Could not validate guardrail configuration: {str(e)}")

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

                # Check S3 and CloudWatch encryption status
                has_encryption_issues = False
                s3_config = config.get('s3Config', {})
                cloudwatch_config = config.get('cloudWatchConfig', {})

                # Check S3 bucket encryption if configured
                if s3_config.get('bucketName'):
                    bucket_name = s3_config['bucketName']

                    try:
                        from wilma.utils import check_s3_bucket_encryption
                        encryption_status = check_s3_bucket_encryption(self.checker.s3, bucket_name)

                        if encryption_status['encrypted']:
                            if encryption_status['uses_customer_key']:
                                self.checker.add_good_practice(
                                    "Data Privacy",
                                    f"S3 bucket {bucket_name} encrypted with customer-managed KMS key"
                                )
                            else:
                                self.checker.add_good_practice(
                                    "Data Privacy",
                                    f"S3 bucket {bucket_name} is encrypted for log storage"
                                )
                        else:
                            has_encryption_issues = True
                            self.checker.add_finding(
                                risk_level=RiskLevel.HIGH,
                                category="Data Privacy",
                                resource=f"S3 Bucket: {bucket_name}",
                                issue="Model invocation logs stored in unencrypted S3 bucket",
                                recommendation="Enable encryption on the S3 bucket storing sensitive logs",
                                fix_command=(
                                    f"aws s3api put-bucket-encryption --bucket {bucket_name} \\\n"
                                    f"  --server-side-encryption-configuration '{{\n"
                                    f"    \"Rules\": [{{\n"
                                    f"      \"ApplyServerSideEncryptionByDefault\": {{\n"
                                    f"        \"SSEAlgorithm\": \"aws:kms\",\n"
                                    f"        \"KMSMasterKeyID\": \"your-kms-key-id\"\n"
                                    f"      }}\n"
                                    f"    }}]\n"
                                    f"  }}'"
                                ),
                                learn_more="Unencrypted logs may expose sensitive user data or PII",
                                technical_details="S3 bucket lacks server-side encryption"
                            )
                    except Exception as e:
                        print(f"[WARN] Could not check S3 bucket encryption: {str(e)}")

                # Check CloudWatch log encryption if configured
                if cloudwatch_config.get('logGroupName'):
                    log_group_name = cloudwatch_config['logGroupName']

                    try:
                        from wilma.utils import check_log_group_encryption
                        log_status = check_log_group_encryption(self.checker.cloudwatch, log_group_name)

                        if log_status['exists']:
                            if log_status['encrypted']:
                                self.checker.add_good_practice(
                                    "Data Privacy",
                                    f"CloudWatch log group {log_group_name} is encrypted"
                                )
                            else:
                                has_encryption_issues = True
                                self.checker.add_finding(
                                    risk_level=RiskLevel.MEDIUM,
                                    category="Data Privacy",
                                    resource=f"CloudWatch Logs: {log_group_name}",
                                    issue="Model invocation logs in CloudWatch are not encrypted",
                                    recommendation="Enable KMS encryption for CloudWatch log group",
                                    fix_command=(
                                        f"aws logs associate-kms-key \\\n"
                                        f"  --log-group-name {log_group_name} \\\n"
                                        f"  --kms-key-id your-kms-key-id"
                                    ),
                                    learn_more="Unencrypted CloudWatch logs may expose sensitive data",
                                    technical_details="Log group not encrypted with customer-managed KMS key"
                                )
                    except Exception as e:
                        print(f"[WARN] Could not check CloudWatch log encryption: {str(e)}")

                # Only warn about PII if there are actual encryption issues
                # Otherwise, it's just informational
                if has_encryption_issues:
                    self.checker.add_finding(
                        risk_level=RiskLevel.MEDIUM,
                        category="Data Privacy",
                        resource="Model Invocation Logs",
                        issue="Unencrypted logs increase PII exposure risk",
                        recommendation="Implement PII filtering and ensure all logs are encrypted",
                        learn_more="User prompts may contain names, addresses, or other sensitive data",
                        technical_details="Consider: 1) PII detection Lambda in logging pipeline, 2) AWS Comprehend for PII detection, 3) Data masking"
                    )
                else:
                    # Logs are encrypted - just provide informational guidance
                    self.checker.add_finding(
                        risk_level=RiskLevel.INFO,
                        category="Data Privacy",
                        resource="Model Invocation Logs",
                        issue="Consider implementing PII filtering for additional protection",
                        recommendation="Add PII detection and masking to logging pipeline",
                        learn_more="Even encrypted logs benefit from PII filtering for defense in depth",
                        technical_details="Options: Lambda preprocessing, AWS Comprehend PII detection, or guardrail-based filtering"
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
            # Create Cost Explorer client
            ce_client = self.checker.session.client('ce')

            # List all anomaly monitors
            monitors_response = ce_client.get_anomaly_monitors()
            monitors = monitors_response.get('AnomalyMonitors', [])

            # Check if any monitor is tracking Bedrock usage
            bedrock_monitors = []
            for monitor in monitors:
                monitor_name = monitor.get('MonitorName', '')
                monitor_spec = monitor.get('MonitorSpecification', {})

                # Check if monitor filters for Bedrock service
                # MonitorSpecification is a Cost Category Expression
                if 'bedrock' in monitor_name.lower():
                    bedrock_monitors.append(monitor_name)
                    continue

                # Check dimensions/tags in monitor specification
                dimensions = monitor_spec.get('Dimensions', {})
                if dimensions:
                    service = dimensions.get('Key')
                    values = dimensions.get('Values', [])
                    if service == 'SERVICE' and any('Bedrock' in v or 'bedrock' in v for v in values):
                        bedrock_monitors.append(monitor_name)

            if not bedrock_monitors:
                self.checker.add_finding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Cost Security",
                    resource="Bedrock Usage Monitoring",
                    issue="No automated cost alerts for unusual Bedrock usage",
                    recommendation="Set up AWS Cost Anomaly Detection for Bedrock services",
                    fix_command=(
                        "aws ce create-anomaly-monitor --anomaly-monitor "
                        "'Name=BedrockMonitor,MonitorType=DIMENSIONAL,MonitorDimension=SERVICE' && "
                        "aws ce create-anomaly-subscription --subscription "
                        "'SubscriptionName=BedrockAlerts,MonitorArnList=[MONITOR_ARN],Threshold=100,Frequency=DAILY,"
                        "Subscribers=[{Address=your-email@example.com,Type=EMAIL}]'"
                    ),
                    learn_more="Unusual spikes in AI usage costs might indicate security breaches or abuse",
                    technical_details="No AWS Cost Anomaly Detection monitors found monitoring Bedrock service usage"
                )
            else:
                self.checker.add_good_practice(
                    "Cost Security",
                    f"Cost anomaly detection configured: {', '.join(bedrock_monitors)}"
                )

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UnrecognizedClientException':
                # Cost Explorer not available in this region
                print("[INFO] Cost Explorer API not available in this region - skipping cost anomaly check")
            elif error_code in ['AccessDeniedException', 'UnauthorizedOperation']:
                print("[WARN] Permission denied for Cost Explorer - skipping cost anomaly check")
                print("[TIP] Add 'ce:GetAnomalyMonitors' permission to check cost monitoring")
            else:
                handle_aws_error(e, "checking cost anomaly detection")

        except Exception as e:
            print(f"[WARN] Could not check cost monitoring: {str(e)}")

        return self.checker.findings
