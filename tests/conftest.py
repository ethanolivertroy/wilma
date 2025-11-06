"""
Pytest configuration and shared fixtures for Wilma tests

Uses Moto for realistic AWS service mocking instead of manual MagicMocks.
Moto provides stateful mocking that mimics actual AWS behavior.

Copyright (C) 2025  Ethan Troy
Licensed under GPL v3
"""

import os

import boto3
import pytest
from moto import mock_aws

from wilma.checker import BedrockSecurityChecker
from wilma.config import WilmaConfig
from wilma.enums import SecurityMode


@pytest.fixture(scope="function")
def aws_credentials():
    """
    Mock AWS credentials for Moto.

    Sets environment variables that boto3 uses for authentication.
    These are fake credentials that Moto recognizes.
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


@pytest.fixture(scope="function")
def moto_bedrock(aws_credentials):
    """
    Create mocked AWS Bedrock service using Moto.

    Returns a boto3 client for Bedrock with Moto mocking enabled.
    All Bedrock API calls will be intercepted and mocked.
    """
    with mock_aws():
        yield boto3.client('bedrock', region_name='us-east-1')


@pytest.fixture(scope="function")
def moto_bedrock_agent(aws_credentials):
    """
    Create mocked AWS Bedrock Agent service using Moto.

    Used for knowledge bases, agents, and related operations.
    """
    with mock_aws():
        yield boto3.client('bedrock-agent', region_name='us-east-1')


@pytest.fixture(scope="function")
def moto_iam(aws_credentials):
    """Create mocked AWS IAM service using Moto."""
    with mock_aws():
        yield boto3.client('iam', region_name='us-east-1')


@pytest.fixture(scope="function")
def moto_s3(aws_credentials):
    """Create mocked AWS S3 service using Moto."""
    with mock_aws():
        yield boto3.client('s3', region_name='us-east-1')


@pytest.fixture(scope="function")
def moto_logs(aws_credentials):
    """Create mocked AWS CloudWatch Logs service using Moto."""
    with mock_aws():
        yield boto3.client('logs', region_name='us-east-1')


@pytest.fixture(scope="function")
def moto_ec2(aws_credentials):
    """Create mocked AWS EC2 service using Moto (for VPC endpoints)."""
    with mock_aws():
        yield boto3.client('ec2', region_name='us-east-1')


@pytest.fixture(scope="function")
def mock_all_aws_services(aws_credentials):
    """
    Create a mock context with all AWS services available.

    Use this when tests need multiple AWS services.
    Yields a dict of service_name: client.
    """
    with mock_aws():
        yield {
            'bedrock': boto3.client('bedrock', region_name='us-east-1'),
            'bedrock-agent': boto3.client('bedrock-agent', region_name='us-east-1'),
            'iam': boto3.client('iam', region_name='us-east-1'),
            's3': boto3.client('s3', region_name='us-east-1'),
            'logs': boto3.client('logs', region_name='us-east-1'),
            'ec2': boto3.client('ec2', region_name='us-east-1'),
        }


@pytest.fixture(scope="function")
def checker_with_moto(aws_credentials):
    """
    Create a BedrockSecurityChecker with Moto-backed AWS clients.

    This is the main fixture for integration tests. The checker will use
    real boto3 clients that are intercepted by Moto for mocking.
    """
    with mock_aws():
        checker = BedrockSecurityChecker(
            region='us-east-1',
            mode=SecurityMode.STANDARD
        )
        # Moto automatically mocks all boto3 clients created inside this context
        yield checker


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


# Legacy fixture name for backwards compatibility during migration
@pytest.fixture
def mock_checker(checker_with_moto):
    """
    Alias for checker_with_moto to support existing tests during migration.

    DEPRECATED: Use checker_with_moto directly in new tests.
    This alias will be removed after all tests are migrated.
    """
    return checker_with_moto
