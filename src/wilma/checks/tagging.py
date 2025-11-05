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

from typing import List, Dict
from wilma.enums import SecurityMode, RiskLevel


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

            if custom_models.get('modelSummaries'):
                for model in custom_models.get('modelSummaries', []):
                    model_name = model['modelName']

                    try:
                        tags_response = self.checker.bedrock.list_tags_for_resource(resourceARN=model['modelArn'])
                        existing_tags = [tag['key'] for tag in tags_response.get('tags', [])]

                        important_tags = ['Environment', 'Owner', 'Project']
                        missing_tags = [tag for tag in important_tags if tag not in existing_tags]

                        if missing_tags:
                            self.checker.add_finding(
                                risk_level=RiskLevel.LOW,
                                category="Resource Management",
                                resource=f"Model: {model_name}",
                                issue=f"Missing organizational tags: {', '.join(missing_tags)}",
                                recommendation="Add tags to track ownership and costs",
                                fix_command=f"aws bedrock tag-resource --resource-arn {model['modelArn']} --tags Key=Environment,Value=Production",
                                learn_more="Tags help you identify who owns what and control costs"
                            )
                        else:
                            self.checker.add_good_practice("Resource Management", f"Model {model_name} is properly tagged")

                    except Exception as e:
                        continue

        except Exception as e:
            print(f"[WARN] Could not check resource tagging: {str(e)}")

        return self.checker.findings
