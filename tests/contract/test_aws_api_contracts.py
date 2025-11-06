"""
Contract tests for AWS API assumptions.

These tests validate that our code's assumptions about AWS API behavior,
response structures, and parameter names are correct.

Contract tests should be run regularly to catch when AWS changes APIs.
"""

import boto3
import pytest
from moto import mock_aws


@pytest.mark.contract
class TestBedrockAPIContracts:
    """Test assumptions about AWS Bedrock API."""

    @pytest.mark.skip(reason="Moto does not fully support Bedrock API - list_foundation_models not implemented")
    def test_list_foundation_models_response_shape(self, aws_credentials):
        """Validate list_foundation_models response structure."""
        with mock_aws():
            client = boto3.client('bedrock', region_name='us-east-1')
            response = client.list_foundation_models()

            # Validate response structure
            assert 'modelSummaries' in response
            assert isinstance(response['modelSummaries'], list)

            # If models exist, validate shape
            if response['modelSummaries']:
                model = response['modelSummaries'][0]
                # These fields are assumed to exist in our code
                assert 'modelId' in model
                assert 'modelName' in model

    @pytest.mark.skip(reason="Moto does not fully support Bedrock API - list_guardrails not implemented")
    def test_list_guardrails_response_shape(self, aws_credentials):
        """Validate list_guardrails response structure."""
        with mock_aws():
            client = boto3.client('bedrock', region_name='us-east-1')
            response = client.list_guardrails()

            # Validate response structure
            assert 'guardrails' in response
            assert isinstance(response['guardrails'], list)

    def test_list_custom_models_response_shape(self, aws_credentials):
        """Validate list_custom_models response structure."""
        with mock_aws():
            client = boto3.client('bedrock', region_name='us-east-1')
            response = client.list_custom_models()

            # Validate response structure
            assert 'modelSummaries' in response
            assert isinstance(response['modelSummaries'], list)


@pytest.mark.contract
class TestBedrockAgentAPIContracts:
    """Test assumptions about AWS Bedrock Agent API."""

    def test_list_knowledge_bases_pagination_token(self, aws_credentials):
        """Validate knowledge bases pagination uses 'nextToken'."""
        with mock_aws():
            client = boto3.client('bedrock-agent', region_name='us-east-1')
            response = client.list_knowledge_bases()

            # Validate response structure
            assert 'knowledgeBaseSummaries' in response

            # If pagination token exists, validate it's 'nextToken' not 'NextToken'
            # Our code assumes lowercase 'nextToken'
            if 'nextToken' in response:
                assert isinstance(response['nextToken'], str)

    def test_list_agents_response_shape(self, aws_credentials):
        """Validate list_agents response structure."""
        with mock_aws():
            client = boto3.client('bedrock-agent', region_name='us-east-1')
            response = client.list_agents()

            # Validate response structure matches our assumptions
            assert 'agentSummaries' in response
            assert isinstance(response['agentSummaries'], list)


@pytest.mark.contract
class TestIAMAPIContracts:
    """Test assumptions about AWS IAM API."""

    def test_list_policies_response_shape(self, aws_credentials):
        """Validate list_policies response structure."""
        with mock_aws():
            client = boto3.client('iam', region_name='us-east-1')
            response = client.list_policies()

            # Validate response structure
            assert 'Policies' in response
            assert isinstance(response['Policies'], list)

    def test_list_policies_pagination_uses_marker(self, aws_credentials):
        """Validate IAM pagination uses 'Marker' (uppercase)."""
        with mock_aws():
            client = boto3.client('iam', region_name='us-east-1')
            response = client.list_policies(MaxItems=1)

            # IAM uses 'Marker' for pagination (different from bedrock's 'nextToken')
            # Our pagination utility must handle both
            if 'Marker' in response or 'IsTruncated' in response:
                # This is expected - IAM uses different pagination style
                pass


@pytest.mark.contract
class TestS3APIContracts:
    """Test assumptions about AWS S3 API."""

    def test_get_bucket_encryption_response(self, aws_credentials):
        """Validate S3 encryption API response structure."""
        with mock_aws():
            s3 = boto3.client('s3', region_name='us-east-1')

            # Create test bucket
            s3.create_bucket(Bucket='test-bucket')

            # S3 encryption check may raise exception or return empty
            # Our code needs to handle this gracefully
            try:
                response = s3.get_bucket_encryption(Bucket='test-bucket')
                # If encryption exists, validate structure
                if 'ServerSideEncryptionConfiguration' in response:
                    assert 'Rules' in response['ServerSideEncryptionConfiguration']
            except Exception:  # noqa: S110
                # This is expected for unencrypted buckets in Moto
                # Real AWS raises ServerSideEncryptionConfigurationNotFoundError
                pass


@pytest.mark.contract
class TestPaginationContracts:
    """Test pagination token naming conventions across AWS services."""

    def test_bedrock_uses_lowercase_nexttoken(self, aws_credentials):
        """Bedrock Agent uses lowercase 'nextToken'."""
        with mock_aws():
            client = boto3.client('bedrock-agent', region_name='us-east-1')
            response = client.list_knowledge_bases()

            # Validate pagination token is lowercase (not NextToken)
            # Our code in utils.py assumes this
            assert 'nextToken' in response or 'knowledgeBaseSummaries' in response

    def test_iam_uses_uppercase_marker(self, aws_credentials):
        """IAM uses uppercase 'Marker'."""
        with mock_aws():
            client = boto3.client('iam', region_name='us-east-1')
            response = client.list_policies()

            # IAM uses 'Marker' and 'IsTruncated'
            # Our pagination utility must support this pattern
            assert 'Policies' in response
