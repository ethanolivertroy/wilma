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

from typing import Dict, List

from botocore.exceptions import ClientError

from wilma.enums import RiskLevel, SecurityMode
from wilma.utils import handle_aws_error, paginate_iam_results


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
                    model['modelArn']

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
            self._check_aws_managed_policies_on_roles()

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

                except Exception:
                    continue

            if dangerous_count == 0:
                self.checker.add_good_practice("Access Control", "No overly permissive Bedrock IAM policies found")

        except Exception as e:
            print(f"[WARN] Could not check IAM policies: {str(e)}")

    def _check_aws_managed_policies_on_roles(self):
        """Check for AWS-managed policies with Bedrock access attached to roles."""
        try:
            # Dangerous AWS-managed policies that grant broad permissions
            dangerous_managed_policies = {
                'AdministratorAccess': RiskLevel.CRITICAL,
                'PowerUserAccess': RiskLevel.HIGH,
                'ReadOnlyAccess': RiskLevel.LOW,  # Can still read model configurations
            }

            risky_roles = []

            # List all IAM roles
            for role in paginate_iam_results(self.checker.iam.list_roles, 'Roles', MaxItems=100):
                role_name = role['RoleName']

                try:
                    # Get attached managed policies for this role
                    attached_policies = self.checker.iam.list_attached_role_policies(RoleName=role_name)

                    for policy in attached_policies.get('AttachedPolicies', []):
                        policy_name = policy['PolicyName']
                        policy_arn = policy['PolicyArn']

                        # Check if it's a dangerous AWS-managed policy
                        if policy_name in dangerous_managed_policies:
                            risk_level = dangerous_managed_policies[policy_name]
                            risky_roles.append((role_name, policy_name, risk_level))

                            self.checker.add_finding(
                                risk_level=risk_level,
                                category="Access Control",
                                resource=f"IAM Role: {role_name}",
                                issue=f"Role has '{policy_name}' policy with unrestricted Bedrock access",
                                recommendation=f"Replace '{policy_name}' with least-privilege custom policy",
                                fix_command=(
                                    f"# Create a restricted policy first, then:\n"
                                    f"aws iam detach-role-policy --role-name {role_name} --policy-arn {policy_arn} && \n"
                                    f"aws iam attach-role-policy --role-name {role_name} --policy-arn arn:aws:iam::YOUR_ACCOUNT:policy/RestrictedBedrockPolicy"
                                ),
                                learn_more=f"'{policy_name}' grants full or broad AWS access including all Bedrock operations",
                                technical_details=f"Role '{role_name}' has AWS-managed policy '{policy_name}' attached"
                            )

                        # Check for bedrock-specific AWS-managed policies (if any exist in the future)
                        elif 'bedrock' in policy_name.lower() or 'Bedrock' in policy_name:
                            # Get policy details to check for wildcards
                            try:
                                policy_details = self.checker.iam.get_policy(PolicyArn=policy_arn)
                                default_version = policy_details['Policy']['DefaultVersionId']

                                policy_version = self.checker.iam.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=default_version
                                )

                                policy_doc = policy_version['PolicyVersion']['Document']

                                # Check for wildcard actions
                                for statement in policy_doc.get('Statement', []):
                                    if statement.get('Effect') == 'Allow':
                                        actions = statement.get('Action', [])
                                        if isinstance(actions, str):
                                            actions = [actions]

                                        if any('bedrock:*' in action or action == '*' for action in actions):
                                            self.checker.add_finding(
                                                risk_level=RiskLevel.HIGH,
                                                category="Access Control",
                                                resource=f"IAM Role: {role_name}",
                                                issue=f"Role has Bedrock policy '{policy_name}' with wildcard permissions",
                                                recommendation="Use specific Bedrock actions instead of wildcards",
                                                fix_command=f"Review and replace policy on role: {role_name}",
                                                technical_details=f"Policy '{policy_name}' contains wildcard Bedrock actions"
                                            )

                            except ClientError as e:
                                # Permission denied to read policy details - skip
                                if e.response['Error']['Code'] not in ['AccessDenied', 'NoSuchEntity']:
                                    raise

                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code not in ['AccessDenied', 'NoSuchEntity']:
                        handle_aws_error(e, f"checking role {role_name}", log_access_denied=False)

            if risky_roles:
                print(f"[INFO] Found {len(risky_roles)} roles with overly permissive AWS-managed policies")
            else:
                self.checker.add_good_practice("Access Control", "No roles with dangerous AWS-managed policies found")

        except ClientError as e:
            handle_aws_error(e, "checking AWS-managed policies on roles")
        except Exception as e:
            print(f"[WARN] Could not check AWS-managed policies: {str(e)}")
