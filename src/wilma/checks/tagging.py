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

    def _normalize_tags(self, tags):
        if isinstance(tags, dict):
            return tags

        normalized = {}
        for tag in tags or []:
            key = tag.get('Key') or tag.get('key')
            value = tag.get('Value') or tag.get('value')
            if key:
                normalized[key] = value
        return normalized

    def _check_required_tags(self, resource_name, resource_arn, tags_response):
        required_tags = self.checker.config.required_tags
        existing_tags = self._normalize_tags(tags_response.get('tags', {}))
        missing_tags = [tag for tag in required_tags if tag not in existing_tags]

        if missing_tags:
            self.checker.add_finding(
                risk_level=RiskLevel.LOW,
                category="Resource Management",
                resource=resource_name,
                issue=f"Missing organizational tags: {', '.join(missing_tags)}",
                recommendation=f"Add required tags: {', '.join(missing_tags)}",
                fix_command=(
                    f"aws bedrock tag-resource --resource-arn {resource_arn} "
                    f"--tags Key={missing_tags[0]},Value=<your-value>"
                ),
                learn_more="Tags help identify ownership, environment, data classification, and cost allocation"
            )
        else:
            self.checker.add_good_practice("Resource Management", f"{resource_name} is properly tagged")

    def check_resource_tagging(self) -> List[Dict]:
        """Simplified resource tagging check."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: Resource Organization")
            print("This checks if your AI resources are properly labeled.")
            print("Tags help you track costs and manage permissions by project or team.")
            return []

        print("[CHECK] Checking resource organization...")

        try:
            # Foundation models are AWS-owned resources. Their ARNs are not taggable
            # by customer accounts, and calling ListTagsForResource for them returns
            # ValidationException. Only assess taggable, account-owned resources.
            custom_models = self.checker.bedrock.list_custom_models()
            for model in custom_models.get('modelSummaries', []):
                model_name = model['modelName']
                model_arn = model['modelArn']

                try:
                    tags_response = self.checker.bedrock.list_tags_for_resource(resourceARN=model_arn)
                    self._check_required_tags(f"Model: {model_name}", model_arn, tags_response)

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
        if self.checker.mode == SecurityMode.LEARN:
            return []

        print("[CHECK] Checking Knowledge Base tagging...")

        try:
            knowledge_bases = self.checker.bedrock_agent.list_knowledge_bases().get('knowledgeBaseSummaries', [])
            for kb in knowledge_bases:
                kb_id = kb.get('knowledgeBaseId')
                kb_name = kb.get('name', kb_id)
                kb_arn = (
                    kb.get('knowledgeBaseArn')
                    or f"arn:aws:bedrock:{self.checker.region}:{self.checker.account_id}:knowledge-base/{kb_id}"
                )

                try:
                    tags_response = self.checker.bedrock_agent.list_tags_for_resource(resourceARN=kb_arn)
                    self._check_required_tags(f"Knowledge Base: {kb_name}", kb_arn, tags_response)
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code not in ['AccessDenied', 'ResourceNotFoundException']:
                        handle_aws_error(e, f"checking tags for knowledge base {kb_name}", log_access_denied=False)
                except Exception as e:
                    print(f"[WARN] Unexpected error checking knowledge base {kb_name}: {str(e)}")

        except ClientError as e:
            handle_aws_error(e, "listing knowledge bases for tagging")

        return self.checker.findings
