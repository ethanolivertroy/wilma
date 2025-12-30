"""
Pytest configuration and shared fixtures for Wilma tests

Hybrid approach:
- Uses Moto for S3, IAM, EC2, CloudWatch Logs (fully supported)
- Uses MagicMock for Bedrock services (incomplete Moto support)

Copyright (C) 2025  Ethan Troy
Licensed under GPL v3
"""

import os
from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

from wilma.checker import BedrockSecurityChecker
from wilma.config import WilmaConfig
from wilma.enums import SecurityMode


@pytest.fixture
def aws_credentials():
    """
    Mock AWS credentials for boto3.

    Sets environment variables that boto3 uses for authentication.
    """
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    yield

    # Cleanup after test
    for key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION"]:
        os.environ.pop(key, None)


# ============================================================================
# MagicMock Fixtures for Bedrock (Moto has incomplete support)
# ============================================================================

@pytest.fixture
def mock_bedrock_client():
    """
    Create a MagicMock for AWS Bedrock client.

    Bedrock has incomplete Moto support, so we use MagicMock.
    Configure return values as needed in your tests.
    """
    mock_client = MagicMock()

    # Default responses
    mock_client.list_foundation_models.return_value = {
        'modelSummaries': []
    }
    mock_client.get_model_invocation_logging_configuration.return_value = {
        'loggingConfig': {}
    }
    mock_client.list_custom_models.return_value = {
        'modelSummaries': []
    }
    mock_client.list_guardrails.return_value = {
        'guardrails': []
    }

    return mock_client


@pytest.fixture
def mock_bedrock_agent_client():
    """
    Create a MagicMock for AWS Bedrock Agent client.

    Bedrock Agent has incomplete Moto support, so we use MagicMock.
    Configure return values as needed in your tests.
    """
    mock_client = MagicMock()

    # Default responses
    mock_client.list_knowledge_bases.return_value = {
        'knowledgeBaseSummaries': []
    }
    mock_client.list_agents.return_value = {
        'agentSummaries': []
    }

    return mock_client


# ============================================================================
# Moto Fixtures for fully-supported services
# ============================================================================

@pytest.fixture
def moto_iam(aws_credentials):
    """Create mocked AWS IAM service using Moto."""
    with mock_aws():
        yield boto3.client('iam', region_name='us-east-1')


@pytest.fixture
def moto_s3(aws_credentials):
    """Create mocked AWS S3 service using Moto."""
    with mock_aws():
        yield boto3.client('s3', region_name='us-east-1')


@pytest.fixture
def moto_logs(aws_credentials):
    """Create mocked AWS CloudWatch Logs service using Moto."""
    with mock_aws():
        yield boto3.client('logs', region_name='us-east-1')


@pytest.fixture
def moto_ec2(aws_credentials):
    """Create mocked AWS EC2 service using Moto (for VPC endpoints)."""
    with mock_aws():
        yield boto3.client('ec2', region_name='us-east-1')


# ============================================================================
# Hybrid Checker Fixture (MagicMock Bedrock + Moto for other services)
# ============================================================================

@pytest.fixture
def mock_checker(aws_credentials, mock_bedrock_client, mock_bedrock_agent_client):
    """
    Create a BedrockSecurityChecker with hybrid mocking.

    - Bedrock clients use MagicMock (incomplete Moto support)
    - S3, IAM, EC2, Logs use Moto (full support)

    This is the main fixture for integration tests.
    """
    with mock_aws():
        # Create checker
        checker = BedrockSecurityChecker(
            region='us-east-1',
            mode=SecurityMode.STANDARD
        )

        # Replace Bedrock clients with MagicMocks
        checker.bedrock = mock_bedrock_client
        checker.bedrock_agent = mock_bedrock_agent_client

        # Mock session.client to return our mocked bedrock-agent client
        original_session_client = checker.session.client

        def mock_session_client(service_name, **kwargs):
            if service_name == 'bedrock-agent':
                return mock_bedrock_agent_client
            elif service_name == 'bedrock':
                return mock_bedrock_client
            else:
                # For other services (s3, iam, etc.), use Moto
                return original_session_client(service_name, **kwargs)

        checker.session.client = mock_session_client

        # S3, IAM, EC2, Logs clients will use Moto automatically
        # since they were created inside mock_aws() context

        yield checker


@pytest.fixture
def checker_with_moto(mock_checker):
    """
    Alias for mock_checker for backwards compatibility.

    Both names refer to the same hybrid fixture.
    """
    return mock_checker


# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture
def wilma_config():
    """Create a default Wilma configuration for testing."""
    return WilmaConfig(
        region='us-east-1',
        checks_enabled=[
            'iam',
            'genai',
            'network',
            'logging',
            'tagging',
            'knowledge_bases'
        ],
        min_risk_level='LOW'
    )


# ============================================================================
# Helper functions for setting up common Bedrock mock responses
# ============================================================================

def setup_guardrail_mock(mock_client, guardrail_id='test-guardrail',
                         has_prompt_filter=True, filter_strength='HIGH'):
    """
    Helper to configure a Bedrock client mock with guardrail responses.

    Args:
        mock_client: The MagicMock Bedrock client
        guardrail_id: Guardrail ID to return
        has_prompt_filter: Whether guardrail has prompt attack filter
        filter_strength: Filter strength (HIGH, MEDIUM, LOW, NONE)
    """
    # List guardrails response
    mock_client.list_guardrails.return_value = {
        'guardrails': [
            {
                'id': guardrail_id,
                'arn': f'arn:aws:bedrock:us-east-1:123456789012:guardrail/{guardrail_id}',
                'name': 'Test Guardrail',
                'status': 'READY'
            }
        ]
    }

    # Get guardrail details response
    content_policy_config = {}
    if has_prompt_filter:
        content_policy_config['filtersConfig'] = [
            {
                'type': 'PROMPT_ATTACK',
                'inputStrength': filter_strength,
                'outputStrength': filter_strength
            }
        ]

    mock_client.get_guardrail.return_value = {
        'guardrailId': guardrail_id,
        'name': 'Test Guardrail',
        'status': 'READY',
        'contentPolicyConfig': content_policy_config
    }


def setup_model_logging_mock(mock_client, s3_enabled=False, cloudwatch_enabled=False,
                             s3_bucket=None, log_group_name=None):
    """
    Helper to configure Bedrock client mock with logging configuration.

    Args:
        mock_client: The MagicMock Bedrock client
        s3_enabled: Whether S3 logging is enabled
        cloudwatch_enabled: Whether CloudWatch logging is enabled
        s3_bucket: S3 bucket name for logs
        log_group_name: CloudWatch log group name
    """
    logging_config = {}

    if s3_enabled and s3_bucket:
        logging_config['s3Config'] = {
            'bucketName': s3_bucket
        }

    if cloudwatch_enabled and log_group_name:
        logging_config['cloudWatchConfig'] = {
            'logGroupName': log_group_name,
            'roleArn': 'arn:aws:iam::123456789012:role/BedrockLoggingRole'
        }

    mock_client.get_model_invocation_logging_configuration.return_value = {
        'loggingConfig': logging_config
    }


def setup_knowledge_base_mock(mock_client, kb_id='test-kb', kb_name='Test KB',
                              storage_config=None, role_arn=None):
    """
    Helper to configure Bedrock Agent client mock with knowledge base.

    Args:
        mock_client: The MagicMock Bedrock Agent client
        kb_id: Knowledge base ID
        kb_name: Knowledge base name
        storage_config: Storage configuration dict
        role_arn: IAM role ARN
    """
    if storage_config is None:
        storage_config = {
            'type': 'OPENSEARCH_SERVERLESS',
            'opensearchServerlessConfiguration': {
                'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection'
            }
        }

    if role_arn is None:
        role_arn = 'arn:aws:iam::123456789012:role/KnowledgeBaseRole'

    # List knowledge bases response
    mock_client.list_knowledge_bases.return_value = {
        'knowledgeBaseSummaries': [
            {
                'knowledgeBaseId': kb_id,
                'name': kb_name,
                'status': 'ACTIVE'
            }
        ]
    }

    # Get knowledge base details
    mock_client.get_knowledge_base.return_value = {
        'knowledgeBase': {
            'knowledgeBaseId': kb_id,
            'name': kb_name,
            'roleArn': role_arn,
            'status': 'ACTIVE',
            'storageConfiguration': storage_config
        }
    }


def setup_agent_mock(mock_client, agent_id='test-agent', agent_name='Test Agent',
                     action_groups=None, has_guardrail=False, guardrail_id=None):
    """
    Helper to configure Bedrock Agent client mock with agent configuration.

    Args:
        mock_client: The MagicMock Bedrock Agent client
        agent_id: Agent ID
        agent_name: Agent name
        action_groups: List of action group configurations (optional)
        has_guardrail: Whether agent has guardrail configured
        guardrail_id: Guardrail identifier (if has_guardrail=True)
    """
    # List agents response
    mock_client.list_agents.return_value = {
        'agentSummaries': [
            {
                'agentId': agent_id,
                'agentName': agent_name,
                'agentStatus': 'PREPARED'
            }
        ]
    }

    # Get agent details
    agent_config = {
        'agentId': agent_id,
        'agentName': agent_name,
        'agentStatus': 'PREPARED',
        'agentResourceRoleArn': f'arn:aws:iam::123456789012:role/AgentRole-{agent_id}'
    }

    if has_guardrail and guardrail_id:
        agent_config['guardrailConfiguration'] = {
            'guardrailIdentifier': guardrail_id,
            'guardrailVersion': 'DRAFT'
        }

    mock_client.get_agent.return_value = {'agent': agent_config}

    # Setup action groups if provided
    if action_groups is None:
        action_groups = []

    mock_client.list_agent_action_groups.return_value = {
        'actionGroupSummaries': [
            {
                'actionGroupId': ag.get('id', f'ag-{idx}'),
                'actionGroupName': ag.get('name', f'ActionGroup{idx}'),
                'actionGroupState': ag.get('state', 'ENABLED')
            }
            for idx, ag in enumerate(action_groups)
        ]
    }

    # Setup get_agent_action_group responses using side_effect
    def get_action_group_side_effect(agentId, actionGroupId, **kwargs):
        for ag in action_groups:
            if ag.get('id') == actionGroupId:
                return {
                    'agentActionGroup': {
                        'actionGroupId': ag.get('id'),
                        'actionGroupName': ag.get('name'),
                        'actionGroupExecutor': ag.get('executor', {'customControl': 'RETURN_CONTROL'})
                    }
                }
        return {}

    if action_groups:
        mock_client.get_agent_action_group.side_effect = get_action_group_side_effect
