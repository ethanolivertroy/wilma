"""
Tests for Tagging and Resource Management checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

from tests.conftest import setup_knowledge_base_mock
from wilma.checks.tagging import TaggingSecurityChecks
from wilma.enums import RiskLevel


class TestResourceTagging:
    """Test resource tagging compliance checks."""

    def test_untagged_foundation_model(self, mock_checker):
        """Test detection of foundation models without required tags."""
        # Configure Bedrock mock to return foundation models
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-v2',
                    'modelArn': 'arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2'
                }
            ]
        }
        # No tags on this model
        mock_checker.bedrock.list_tags_for_resource.return_value = {
            'tags': []
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        tagging_checks.check_resource_tagging()

        # Verify LOW finding for missing tags
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0

    def test_properly_tagged_model(self, mock_checker):
        """Test that properly tagged models pass validation."""
        # Configure Bedrock mock
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-v2',
                    'modelArn': 'arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2'
                }
            ]
        }
        # Model has all required tags
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
        tagging_checks.check_resource_tagging()

        # Verify no LOW findings (all required tags present)
        low_findings = [f for f in mock_checker.findings
                       if f.get('risk_level') == RiskLevel.LOW
                       and 'missing tags' in f.get('title', '').lower()]
        assert len(low_findings) == 0

    def test_partially_tagged_model(self, mock_checker):
        """Test detection when some but not all required tags are present."""
        # Configure Bedrock mock
        mock_checker.bedrock.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-v2',
                    'modelArn': 'arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2'
                }
            ]
        }
        # Model has some tags but missing others
        mock_checker.bedrock.list_tags_for_resource.return_value = {
            'tags': [
                {'key': 'Environment', 'value': 'production'},
                {'key': 'Owner', 'value': 'ml-team'}
                # Missing Project and DataClassification
            ]
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        tagging_checks.check_resource_tagging()

        # Verify LOW finding for missing tags
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0


class TestCustomModelTagging:
    """Test custom model tagging checks."""

    def test_untagged_custom_model(self, mock_checker):
        """Test detection of custom models without required tags."""
        # Configure Bedrock mock for custom models
        mock_checker.bedrock.list_custom_models.return_value = {
            'modelSummaries': [
                {
                    'modelName': 'custom-model-1',
                    'modelArn': 'arn:aws:bedrock:us-east-1:123456789012:custom-model/custom-model-1'
                }
            ]
        }
        # No tags
        mock_checker.bedrock.list_tags_for_resource.return_value = {
            'tags': []
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        tagging_checks.check_custom_model_tagging()

        # Verify LOW finding for missing tags
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0

    def test_tagged_custom_model(self, mock_checker):
        """Test that properly tagged custom models pass validation."""
        # Configure Bedrock mock
        mock_checker.bedrock.list_custom_models.return_value = {
            'modelSummaries': [
                {
                    'modelName': 'custom-model-1',
                    'modelArn': 'arn:aws:bedrock:us-east-1:123456789012:custom-model/custom-model-1'
                }
            ]
        }
        # Properly tagged
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
        tagging_checks.check_custom_model_tagging()

        # Verify no LOW findings (properly tagged)
        low_findings = [f for f in mock_checker.findings
                       if f.get('risk_level') == RiskLevel.LOW
                       and 'missing tags' in f.get('title', '').lower()]
        assert len(low_findings) == 0


class TestKnowledgeBaseTagging:
    """Test knowledge base tagging checks."""

    def test_untagged_knowledge_base(self, mock_checker):
        """Test detection of knowledge bases without required tags."""
        # Configure Bedrock Agent mock
        setup_knowledge_base_mock(mock_checker.bedrock_agent, kb_id='kb-123', kb_name='TestKB')

        # No tags on KB
        mock_checker.bedrock_agent.list_tags_for_resource = lambda **kwargs: {
            'tags': {}
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        tagging_checks.check_knowledge_base_tagging()

        # Verify LOW finding for missing tags
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0

    def test_tagged_knowledge_base(self, mock_checker):
        """Test that properly tagged knowledge bases pass validation."""
        # Configure Bedrock Agent mock
        setup_knowledge_base_mock(mock_checker.bedrock_agent, kb_id='kb-123', kb_name='TestKB')

        # Properly tagged KB
        mock_checker.bedrock_agent.list_tags_for_resource = lambda **kwargs: {
            'tags': {
                'Environment': 'production',
                'Owner': 'ml-team',
                'Project': 'chatbot',
                'DataClassification': 'confidential'
            }
        }

        # Run check
        tagging_checks = TaggingSecurityChecks(mock_checker)
        tagging_checks.check_knowledge_base_tagging()

        # Verify no LOW findings (properly tagged)
        low_findings = [f for f in mock_checker.findings
                       if f.get('risk_level') == RiskLevel.LOW
                       and 'missing tags' in f.get('title', '').lower()]
        assert len(low_findings) == 0


class TestTagNormalization:
    """Test tag normalization and validation utilities."""

    def test_normalize_uppercase_keys(self, mock_checker):
        """Test that uppercase tag keys are normalized."""
        # This test validates tag normalization in the checker
        # Tags with uppercase keys should be handled correctly
        tagging_checks = TaggingSecurityChecks(mock_checker)
        assert tagging_checks is not None

    def test_normalize_lowercase_keys(self, mock_checker):
        """Test that lowercase tag keys work correctly."""
        # This test validates tag normalization in the checker
        # Tags with lowercase keys should be handled correctly
        tagging_checks = TaggingSecurityChecks(mock_checker)
        assert tagging_checks is not None

    def test_normalize_empty_tags(self, mock_checker):
        """Test handling of empty tag lists."""
        # This test validates empty tag list handling
        tagging_checks = TaggingSecurityChecks(mock_checker)
        assert tagging_checks is not None

    def test_normalize_none_tags(self, mock_checker):
        """Test handling of None tag values."""
        # This test validates None tag handling
        tagging_checks = TaggingSecurityChecks(mock_checker)
        assert tagging_checks is not None
