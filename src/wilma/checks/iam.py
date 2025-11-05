"""
IAM & Access Control Checks

Validates who can access Bedrock resources and with what permissions.

Checks:
- Custom model access controls
- IAM policy over-permissiveness (wildcard actions)
- Model encryption configuration
- Resource-based policies

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

from typing import List, Dict
from wilma.enums import SecurityMode, RiskLevel


class IAMSecurityChecks:
    """Validates IAM policies and access controls for Bedrock resources."""

    def __init__(self, checker):
        """Initialize with parent checker for AWS client access."""
        self.checker = checker

    def check_model_access_audit(self) -> List[Dict]:
        """Enhanced model access audit with beginner-friendly explanations."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: Model Access Audit")
            print("This check ensures only authorized users can invoke your AI models.")
            print("Think of it like checking who has keys to your house.")
            return []

        print("[CHECK] Auditing model access permissions...")

        try:
            # Check custom models
            custom_models = self.checker.bedrock.list_custom_models()

            if not custom_models.get('modelSummaries'):
                print("[INFO] No custom models found. Checking IAM policies for foundation model access...")
            else:
                for model in custom_models.get('modelSummaries', []):
                    model_name = model['modelName']
                    model_arn = model['modelArn']

                    # Check if model has proper access controls
                    try:
                        model_details = self.checker.bedrock.get_custom_model(modelIdentifier=model_name)

                        # Check for encryption
                        if 'modelKmsKeyId' not in model_details:
                            self.checker.add_finding(
                                risk_level=RiskLevel.HIGH,
                                category="Model Security",
                                resource=f"Model: {model_name}",
                                issue="Custom model not encrypted with your own encryption key",
                                recommendation="Use your own KMS key for better control over model encryption",
                                fix_command="aws bedrock create-custom-model --model-name <name> --model-kms-key-id <your-kms-key>",
                                learn_more="Using your own encryption key ensures only you can access the model",
                                technical_details="Model uses default AWS managed key instead of customer managed KMS key"
                            )
                        else:
                            self.checker.add_good_practice("Model Security", f"Model {model_name} uses customer-managed encryption")

                    except Exception as e:
                        print(f"[WARN] Could not check model {model_name}: {str(e)}")

            # Check IAM policies for overly permissive access
            self._check_bedrock_iam_permissions()

        except Exception as e:
            print(f"[WARN] Note: Could not complete model access audit: {str(e)}")

        return self.checker.findings

    def _check_bedrock_iam_permissions(self):
        """Check IAM permissions with focus on Bedrock access."""
        try:
            # Check for overly permissive policies
            policies = self.checker.iam.list_policies(Scope='Local', MaxItems=100)

            dangerous_count = 0
            for policy in policies.get('Policies', []):
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']

                try:
                    policy_version = self.checker.iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )

                    policy_doc = policy_version['PolicyVersion']['Document']

                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]

                            # Check for dangerous Bedrock permissions
                            if any('bedrock:*' in action or action == '*' for action in actions):
                                dangerous_count += 1
                                self.checker.add_finding(
                                    risk_level=RiskLevel.CRITICAL,
                                    category="Access Control",
                                    resource=f"IAM Policy: {policy_name}",
                                    issue="Policy allows unrestricted access to ALL Bedrock operations",
                                    recommendation="Limit permissions to only necessary Bedrock actions",
                                    fix_command=f"aws iam create-policy-version --policy-arn {policy_arn} --policy-document file://restricted-policy.json --set-as-default",
                                    learn_more="This is like giving someone admin access to all your AI models",
                                    technical_details=f"Policy contains wildcard action: {actions}"
                                )

                except Exception as e:
                    continue

            if dangerous_count == 0:
                self.checker.add_good_practice("Access Control", "No overly permissive Bedrock IAM policies found")

        except Exception as e:
            print(f"[WARN] Could not check IAM policies: {str(e)}")
