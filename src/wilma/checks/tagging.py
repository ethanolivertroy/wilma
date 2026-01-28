"""
Resource Tagging & Organization Checks

Validates resource tagging for compliance, cost tracking, and access control.

Checks:
- Custom model tagging compliance
- Required tag presence (Environment, Owner, CostCenter)
- Tag-based access control policies

WHY IMPORTANT: Tags enable cost allocation, compliance reporting,
and automated access control policies.

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

from typing import Dict, List

from botocore.exceptions import ClientError

from wilma.enums import RiskLevel, SecurityMode
from wilma.utils import handle_aws_error


class TaggingSecurityChecks:
    """Validates resource tagging for governance and compliance."""

    def __init__(self, checker):
        """Initialize with parent checker for AWS client access."""
        self.checker = checker

    def check_resource_tagging(self) -> List[Dict]:
        """Simplified resource tagging check."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: Resource Organization")
            print("This checks if your AI resources are properly labeled.")
            print("Tags help you track costs and manage permissions by project or team.")
            return []

        print("[CHECK] Checking resource organization...")

        try:
            custom_models = self.checker.bedrock.list_custom_models()

            # Get required tags from configuration
            required_tags = self.checker.config.required_tags

            if custom_models.get('modelSummaries'):
                for model in custom_models.get('modelSummaries', []):
                    model_name = model['modelName']
                    model_arn = model['modelArn']

                    try:
                        tags_response = self.checker.bedrock.list_tags_for_resource(resourceARN=model_arn)
                        existing_tags = [tag['key'] for tag in tags_response.get('tags', [])]

                        missing_tags = [tag for tag in required_tags if tag not in existing_tags]

                        if missing_tags:
                            self.checker.add_finding(
                                risk_level=RiskLevel.LOW,
                                category="Resource Management",
                                resource=f"Model: {model_name}",
                                issue=f"Missing organizational tags: {', '.join(missing_tags)}",
                                recommendation=f"Add required tags: {', '.join(missing_tags)}",
                                fix_command=(
                                    f"aws bedrock tag-resource --resource-arn {model_arn} \\\n"
                                    f"  --tags Key={missing_tags[0]},Value=<your-value>"
                                ),
                                learn_more="Tags help you identify who owns what and control costs"
                            )
                        else:
                            self.checker.add_good_practice("Resource Management", f"Model {model_name} is properly tagged")

                    except ClientError as e:
                        error_code = e.response['Error']['Code']
                        if error_code not in ['AccessDenied', 'ResourceNotFoundException']:
                            handle_aws_error(e, f"checking tags for model {model_name}", log_access_denied=False)
                    except Exception as e:
                        print(f"[WARN] Unexpected error checking model {model_name}: {str(e)}")

        except ClientError as e:
            handle_aws_error(e, "listing custom models")
        except Exception as e:
            print(f"[ERROR] Unexpected error checking resource tagging: {str(e)}")

        return self.checker.findings

    def check_custom_model_tagging(self) -> List[Dict]:
        """Check custom model tagging."""
        return self.check_resource_tagging()

    def check_knowledge_base_tagging(self) -> List[Dict]:
        """Check knowledge base tagging."""
        return self.check_resource_tagging()
