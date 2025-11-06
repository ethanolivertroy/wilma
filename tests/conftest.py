"""
Pytest configuration and shared fixtures for Wilma tests

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import pytest
from unittest.mock import Mock, MagicMock
from wilma.checker import BedrockSecurityChecker
from wilma.config import WilmaConfig
from wilma.enums import SecurityMode


@pytest.fixture
def mock_boto3_session():
    """Mock boto3 session for testing."""
    session = Mock()
    session.region_name = 'us-east-1'

    # Mock clients
    session.client = Mock(side_effect=lambda service: create_mock_client(service))

    return session


def create_mock_client(service_name):
    """Create a mock AWS service client."""
    client = MagicMock()
    client._service_model = MagicMock()
    client._service_model.service_name = service_name

    # Add service-specific mock responses
    if service_name == 'bedrock':
        client.list_foundation_models.return_value = {
            'modelSummaries': [
                {
                    'modelId': 'anthropic.claude-v2',
                    'modelName': 'Claude v2',
                    'inputModalities': ['TEXT'],
                    'outputModalities': ['TEXT']
                }
            ]
        }
        client.list_guardrails.return_value = {'guardrails': []}
        client.list_custom_models.return_value = {'modelSummaries': []}
        client.get_model_invocation_logging_configuration.return_value = {'loggingConfig': None}

    elif service_name == 'bedrock-agent':
        client.list_knowledge_bases.return_value = {'knowledgeBaseSummaries': []}

    elif service_name == 'iam':
        client.list_policies.return_value = {'Policies': []}
        client.list_roles.return_value = {'Roles': []}

    elif service_name == 's3':
        client.exceptions = type('Exceptions', (), {
            'ServerSideEncryptionConfigurationNotFoundError': Exception,
            'NoSuchPublicAccessBlockConfiguration': Exception
        })()

    elif service_name == 'ec2':
        client.describe_vpc_endpoints.return_value = {'VpcEndpoints': []}

    elif service_name == 'logs':
        client.describe_log_groups.return_value = {'logGroups': []}

    elif service_name == 'ce':
        client.get_anomaly_monitors.return_value = {'AnomalyMonitors': []}

    elif service_name == 'sts':
        client.get_caller_identity.return_value = {'Account': '123456789012'}

    return client


@pytest.fixture
def mock_config():
    """Mock Wilma configuration."""
    config = WilmaConfig()
    return config


@pytest.fixture
def mock_checker(monkeypatch, mock_boto3_session, mock_config):
    """Mock Bedrock Security Checker with mocked AWS clients."""
    # Patch boto3.Session to return our mock
    monkeypatch.setattr('boto3.Session', lambda **kwargs: mock_boto3_session)

    checker = BedrockSecurityChecker(mode=SecurityMode.STANDARD, config=mock_config)
    return checker


@pytest.fixture
def sample_s3_bucket_arn():
    """Sample S3 bucket ARN for testing."""
    return 'arn:aws:s3:::my-knowledge-base-bucket'


@pytest.fixture
def sample_kb_config():
    """Sample Knowledge Base configuration for testing."""
    return {
        'knowledgeBaseId': 'kb-12345',
        'name': 'Test Knowledge Base',
        'storageConfiguration': {
            'type': 'OPENSEARCH_SERVERLESS',
            'opensearchServerlessConfiguration': {
                'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection'
            }
        }
    }


@pytest.fixture
def sample_iam_policy():
    """Sample IAM policy document for testing."""
    return {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': 'bedrock:*',
                'Resource': '*'
            }
        ]
    }


@pytest.fixture
def sample_guardrail_config():
    """Sample guardrail configuration for testing."""
    return {
        'guardrailId': 'gr-12345',
        'name': 'TestGuardrail',
        'contentPolicy': {
            'filters': [
                {
                    'type': 'PROMPT_ATTACK',
                    'inputStrength': 'HIGH',
                    'outputStrength': 'HIGH'
                }
            ]
        }
    }
