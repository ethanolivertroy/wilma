"""
Tests for Tagging and Resource Management checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import pytest
from unittest.mock import Mock
from wilma.checks.tagging import TaggingSecurityChecks
from wilma.enums import RiskLevel


class TestResourceTagging:
    """Test resource tagging compliance checks."""

    def test_untagged_foundation_model(self, mock_checker):
        """Test detection of foundation models without required tags."""
        # Setup mock responses
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-v2',
                    'modelArn': 'arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2'
                }
            ]
        }
        mock_checker.bedrock.list_tags_for_resource.return_value = {
            'tags': []  # No tags
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        findings = tagging_checks.check_resource_tagging()

        # Verify LOW finding for missing tags
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0

    def test_properly_tagged_model(self, mock_checker):
        """Test that properly tagged models pass validation."""
        # Setup mock responses
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-v2',
                    'modelArn': 'arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2'
                }
            ]
        }
        mock_checker.bedrock.list_tags_for_resource.return_value = {
            'tags': [
                {'key': 'Environment', 'value': 'production'},
                {'key': 'Owner', 'value': 'ml-team'},
                {'key': 'Project', 'value': 'chatbot'},
                {'key': 'DataClassification', 'value': 'confidential'}
            ]
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        findings = tagging_checks.check_resource_tagging()

        # Verify no LOW findings (all required tags present)
        low_findings = [f for f in mock_checker.findings
                       if f.get('risk_level') == RiskLevel.LOW
                       and 'missing tags' in f.get('title', '').lower()]
        assert len(low_findings) == 0

    def test_partially_tagged_model(self, mock_checker):
        """Test detection when some but not all required tags are present."""
        # Setup mock responses
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-v2',
                    'modelArn': 'arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2'
                }
            ]
        }
        mock_checker.bedrock.list_tags_for_resource.return_value = {
            'tags': [
                {'key': 'Environment', 'value': 'production'},
                {'key': 'Owner', 'value': 'ml-team'}
                # Missing Project and DataClassification
            ]
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        findings = tagging_checks.check_resource_tagging()

        # Verify LOW finding for missing tags
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0


class TestCustomModelTagging:
    """Test custom model tagging checks."""

    def test_untagged_custom_model(self, mock_checker):
        """Test detection of custom models without required tags."""
        # Setup mock responses
        mock_checker.bedrock.list_custom_models.return_value = {
            'modelSummaries': [
                {
                    'modelArn': 'arn:aws:bedrock:us-east-1:123456789012:custom-model/my-custom-model',
                    'modelName': 'my-custom-model'
                }
            ]
        }
        mock_checker.bedrock.list_tags_for_resource.return_value = {
            'tags': []  # No tags
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        findings = tagging_checks.check_resource_tagging()

        # Verify LOW finding for missing tags
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0

    def test_tagged_custom_model(self, mock_checker):
        """Test that properly tagged custom models pass validation."""
        # Setup mock responses
        mock_checker.bedrock.list_custom_models.return_value = {
            'modelSummaries': [
                {
                    'modelArn': 'arn:aws:bedrock:us-east-1:123456789012:custom-model/my-custom-model',
                    'modelName': 'my-custom-model'
                }
            ]
        }
        mock_checker.bedrock.list_tags_for_resource.return_value = {
            'tags': [
                {'key': 'Environment', 'value': 'development'},
                {'key': 'Owner', 'value': 'ml-team'},
                {'key': 'Project', 'value': 'fine-tuning'},
                {'key': 'DataClassification', 'value': 'internal'}
            ]
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        findings = tagging_checks.check_resource_tagging()

        # Verify no LOW findings (all required tags present)
        low_findings = [f for f in mock_checker.findings
                       if f.get('risk_level') == RiskLevel.LOW
                       and 'missing tags' in f.get('title', '').lower()]
        assert len(low_findings) == 0


class TestKnowledgeBaseTagging:
    """Test Knowledge Base tagging checks."""

    def test_untagged_knowledge_base(self, mock_checker):
        """Test detection of Knowledge Bases without required tags."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {
                    'knowledgeBaseId': 'kb-123',
                    'name': 'TestKB'
                }
            ]
        }
        bedrock_agent_mock.list_tags_for_resource.return_value = {
            'tags': {}  # No tags
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        findings = tagging_checks.check_resource_tagging()

        # Verify LOW finding for missing tags
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0

    def test_tagged_knowledge_base(self, mock_checker):
        """Test that properly tagged Knowledge Bases pass validation."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {
                    'knowledgeBaseId': 'kb-123',
                    'name': 'TestKB'
                }
            ]
        }
        bedrock_agent_mock.list_tags_for_resource.return_value = {
            'tags': {
                'Environment': 'production',
                'Owner': 'data-team',
                'Project': 'rag-system',
                'DataClassification': 'confidential'
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        findings = tagging_checks.check_resource_tagging()

        # Verify no LOW findings (all required tags present)
        low_findings = [f for f in mock_checker.findings
                       if f.get('risk_level') == RiskLevel.LOW
                       and 'missing tags' in f.get('title', '').lower()]
        assert len(low_findings) == 0


class TestTagNormalization:
    """Test tag normalization utilities."""

    def test_normalize_uppercase_keys(self, mock_checker):
        """Test normalization of tags with uppercase keys."""
        from wilma.utils import normalize_boto3_tags

        tags = [
            {'Key': 'Environment', 'Value': 'production'},
            {'Key': 'Owner', 'Value': 'ml-team'}
        ]
        result = normalize_boto3_tags(tags)

        assert result == {'Environment': 'production', 'Owner': 'ml-team'}

    def test_normalize_lowercase_keys(self, mock_checker):
        """Test normalization of tags with lowercase keys."""
        from wilma.utils import normalize_boto3_tags

        tags = [
            {'key': 'Environment', 'value': 'production'},
            {'key': 'Owner', 'value': 'ml-team'}
        ]
        result = normalize_boto3_tags(tags)

        assert result == {'Environment': 'production', 'Owner': 'ml-team'}

    def test_normalize_empty_tags(self, mock_checker):
        """Test normalization of empty tag list."""
        from wilma.utils import normalize_boto3_tags

        result = normalize_boto3_tags([])
        assert result == {}

    def test_normalize_none_tags(self, mock_checker):
        """Test normalization of None value."""
        from wilma.utils import normalize_boto3_tags

        result = normalize_boto3_tags(None)
        assert result == {}
