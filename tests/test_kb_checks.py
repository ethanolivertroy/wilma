"""
Tests for Knowledge Base security checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import json

from tests.conftest import setup_knowledge_base_mock
from wilma.checks.knowledge_bases import KnowledgeBaseSecurityChecks
from wilma.enums import RiskLevel


class TestKBDataSourceEncryption:
    """Test Knowledge Base data source encryption checks."""

    def test_unencrypted_s3_data_source(self, mock_checker):
        """Test detection of unencrypted S3 data sources."""
        # Create unencrypted S3 bucket using Moto
        mock_checker.s3.create_bucket(Bucket='test-kb-bucket')

        # Configure Bedrock Agent mock for knowledge base
        setup_knowledge_base_mock(mock_checker.bedrock_agent, kb_id='kb-123', kb_name='TestKB')

        # Configure data source mock
        mock_checker.bedrock_agent.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        mock_checker.bedrock_agent.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'dataSourceConfiguration': {
                    's3Configuration': {
                        'bucketArn': 'arn:aws:s3:::test-kb-bucket'
                    }
                }
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_data_source_encryption()

        # Verify HIGH finding for unencrypted data source
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

    def test_encrypted_s3_data_source(self, mock_checker):
        """Test that encrypted S3 data sources pass validation."""
        # Create encrypted S3 bucket using Moto
        mock_checker.s3.create_bucket(Bucket='test-kb-bucket')
        mock_checker.s3.put_bucket_encryption(
            Bucket='test-kb-bucket',
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
                        }
                    }
                ]
            }
        )

        # Configure Bedrock Agent mock for knowledge base
        setup_knowledge_base_mock(mock_checker.bedrock_agent, kb_id='kb-123', kb_name='TestKB')

        # Configure data source mock
        mock_checker.bedrock_agent.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        mock_checker.bedrock_agent.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'dataSourceConfiguration': {
                    's3Configuration': {
                        'bucketArn': 'arn:aws:s3:::test-kb-bucket'
                    }
                }
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_data_source_encryption()

        # Verify no HIGH findings (data source is encrypted)
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) == 0


class TestKBVectorStoreEncryption:
    """Test Knowledge Base vector store encryption checks."""

    def test_unencrypted_opensearch_collection(self, mock_checker):
        """Test detection of unencrypted OpenSearch Serverless collections."""
        # Configure Bedrock Agent mock with unencrypted OpenSearch config
        storage_config = {
            'type': 'OPENSEARCH_SERVERLESS',
            'opensearchServerlessConfiguration': {
                'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection',
                'fieldMapping': {
                    'vectorField': 'bedrock-knowledge-base-default-vector',
                    'textField': 'AMAZON_BEDROCK_TEXT_CHUNK',
                    'metadataField': 'AMAZON_BEDROCK_METADATA'
                }
            }
        }
        setup_knowledge_base_mock(
            mock_checker.bedrock_agent,
            kb_id='kb-123',
            kb_name='TestKB',
            storage_config=storage_config
        )

        # Mock OpenSearch Serverless to return unencrypted collection
        mock_checker.bedrock_agent.get_collection_security_policy = lambda **kwargs: {
            'securityPolicyDetail': {
                'type': 'encryption',
                'policy': json.dumps({
                    'Rules': [
                        {
                            'Resource': ['collection/test-collection'],
                            'ResourceType': 'collection'
                        }
                    ],
                    'AWSOwnedKey': True
                })
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_vector_store_encryption()

        # Verify HIGH finding for AWS-owned key (not customer-managed)
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

    def test_encrypted_opensearch_collection(self, mock_checker):
        """Test that encrypted OpenSearch collections pass validation."""
        # Configure Bedrock Agent mock with encrypted OpenSearch config
        storage_config = {
            'type': 'OPENSEARCH_SERVERLESS',
            'opensearchServerlessConfiguration': {
                'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection',
                'fieldMapping': {
                    'vectorField': 'bedrock-knowledge-base-default-vector',
                    'textField': 'AMAZON_BEDROCK_TEXT_CHUNK',
                    'metadataField': 'AMAZON_BEDROCK_METADATA'
                }
            }
        }
        setup_knowledge_base_mock(
            mock_checker.bedrock_agent,
            kb_id='kb-123',
            kb_name='TestKB',
            storage_config=storage_config
        )

        # Mock OpenSearch Serverless to return encrypted collection with customer key
        mock_checker.bedrock_agent.get_collection_security_policy = lambda **kwargs: {
            'securityPolicyDetail': {
                'type': 'encryption',
                'policy': json.dumps({
                    'Rules': [
                        {
                            'Resource': ['collection/test-collection'],
                            'ResourceType': 'collection',
                            'KmsARN': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
                        }
                    ]
                })
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_vector_store_encryption()

        # Verify no HIGH findings (collection uses customer-managed key)
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) == 0


class TestKBChunkingConfiguration:
    """Test Knowledge Base chunking configuration checks."""

    def test_excessive_chunk_size(self, mock_checker):
        """Test detection of excessive chunk sizes."""
        # Configure Bedrock Agent mock with large chunk size
        setup_knowledge_base_mock(mock_checker.bedrock_agent, kb_id='kb-123', kb_name='TestKB')

        # Configure data source with excessive chunk size
        mock_checker.bedrock_agent.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        mock_checker.bedrock_agent.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'vectorIngestionConfiguration': {
                    'chunkingConfiguration': {
                        'chunkingStrategy': 'FIXED_SIZE',
                        'fixedSizeChunkingConfiguration': {
                            'maxTokens': 2000,  # Too large
                            'overlapPercentage': 20
                        }
                    }
                }
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_chunking_configuration()

        # Verify MEDIUM finding for excessive chunk size
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_acceptable_chunk_size(self, mock_checker):
        """Test that acceptable chunk sizes pass validation."""
        # Configure Bedrock Agent mock
        setup_knowledge_base_mock(mock_checker.bedrock_agent, kb_id='kb-123', kb_name='TestKB')

        # Configure data source with acceptable chunk size
        mock_checker.bedrock_agent.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        mock_checker.bedrock_agent.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'vectorIngestionConfiguration': {
                    'chunkingConfiguration': {
                        'chunkingStrategy': 'FIXED_SIZE',
                        'fixedSizeChunkingConfiguration': {
                            'maxTokens': 512,  # Acceptable
                            'overlapPercentage': 20
                        }
                    }
                }
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_chunking_configuration()

        # Verify no MEDIUM findings (chunk size is acceptable)
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) == 0


class TestKBIAMPermissions:
    """Test Knowledge Base IAM permission checks."""

    def test_wildcard_permissions(self, mock_checker):
        """Test detection of wildcard IAM permissions."""
        # Create IAM role with overly permissive policy using Moto
        trust_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'bedrock.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }]
        }

        role_response = mock_checker.iam.create_role(
            RoleName='KBRole',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )

        # Create and attach overly permissive policy
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': 's3:*',
                'Resource': '*'
            }]
        }

        policy_response = mock_checker.iam.create_policy(
            PolicyName='KBPolicy',
            PolicyDocument=json.dumps(policy_document)
        )

        mock_checker.iam.attach_role_policy(
            RoleName='KBRole',
            PolicyArn=policy_response['Policy']['Arn']
        )

        # Configure Bedrock Agent mock
        setup_knowledge_base_mock(
            mock_checker.bedrock_agent,
            kb_id='kb-123',
            kb_name='TestKB',
            role_arn=role_response['Role']['Arn']
        )

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_iam_permissions()

        # Verify CRITICAL finding for wildcard permissions
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) > 0

    def test_least_privilege_permissions(self, mock_checker):
        """Test that least-privilege IAM permissions pass validation."""
        # Create IAM role with least-privilege policy using Moto
        trust_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'bedrock.amazonaws.com'},
                'Action': 'sts:AssumeRole'
            }]
        }

        role_response = mock_checker.iam.create_role(
            RoleName='KBRole',
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )

        # Create and attach least-privilege policy
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': ['s3:GetObject', 's3:ListBucket'],
                'Resource': [
                    'arn:aws:s3:::specific-kb-bucket',
                    'arn:aws:s3:::specific-kb-bucket/*'
                ]
            }]
        }

        policy_response = mock_checker.iam.create_policy(
            PolicyName='KBPolicy',
            PolicyDocument=json.dumps(policy_document)
        )

        mock_checker.iam.attach_role_policy(
            RoleName='KBRole',
            PolicyArn=policy_response['Policy']['Arn']
        )

        # Configure Bedrock Agent mock
        setup_knowledge_base_mock(
            mock_checker.bedrock_agent,
            kb_id='kb-123',
            kb_name='TestKB',
            role_arn=role_response['Role']['Arn']
        )

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_iam_permissions()

        # Verify no CRITICAL findings (permissions are least-privilege)
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) == 0


class TestKBPIIDetection:
    """Test Knowledge Base PII detection checks."""

    def test_pii_in_bucket_name(self, mock_checker):
        """Test detection of PII in S3 bucket names."""
        # Create S3 bucket with PII in name using Moto
        mock_checker.s3.create_bucket(Bucket='kb-john-doe-ssn-123-45-6789')

        # Configure Bedrock Agent mock
        setup_knowledge_base_mock(mock_checker.bedrock_agent, kb_id='kb-123', kb_name='TestKB')

        # Configure data source with PII in bucket name
        mock_checker.bedrock_agent.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        mock_checker.bedrock_agent.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'dataSourceConfiguration': {
                    's3Configuration': {
                        'bucketArn': 'arn:aws:s3:::kb-john-doe-ssn-123-45-6789'
                    }
                }
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_pii_exposure()

        # Verify HIGH finding for PII in bucket name
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) > 0

    def test_no_pii_in_metadata(self, mock_checker):
        """Test that clean metadata passes validation."""
        # Configure Bedrock Agent mock
        setup_knowledge_base_mock(mock_checker.bedrock_agent, kb_id='kb-123', kb_name='TestKB')

        # Configure data source with clean bucket name
        mock_checker.bedrock_agent.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        mock_checker.bedrock_agent.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'dataSourceConfiguration': {
                    's3Configuration': {
                        'bucketArn': 'arn:aws:s3:::clean-kb-bucket'
                    }
                }
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_pii_exposure()

        # Verify no HIGH findings (no PII detected)
        high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
        assert len(high_findings) == 0


class TestKBOpenSearchAccessPolicies:
    """Test Knowledge Base OpenSearch access policy checks."""

    def test_overly_permissive_data_access_policy(self, mock_checker):
        """Test detection of overly permissive data access policies."""
        # Configure Bedrock Agent mock
        storage_config = {
            'type': 'OPENSEARCH_SERVERLESS',
            'opensearchServerlessConfiguration': {
                'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection'
            }
        }
        setup_knowledge_base_mock(
            mock_checker.bedrock_agent,
            kb_id='kb-123',
            kb_name='TestKB',
            storage_config=storage_config
        )

        # Mock overly permissive data access policy
        mock_checker.bedrock_agent.get_data_access_policy = lambda **kwargs: {
            'accessPolicyDetail': {
                'type': 'data',
                'policy': json.dumps([{
                    'Rules': [{
                        'Resource': ['collection/test-collection'],
                        'Permission': ['aoss:*'],
                        'ResourceType': 'collection'
                    }],
                    'Principal': ['*']
                }])
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_opensearch_access_policies()

        # Verify CRITICAL finding for wildcard principal
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) > 0

    def test_restrictive_data_access_policy(self, mock_checker):
        """Test that restrictive data access policies pass validation."""
        # Configure Bedrock Agent mock
        storage_config = {
            'type': 'OPENSEARCH_SERVERLESS',
            'opensearchServerlessConfiguration': {
                'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection'
            }
        }
        setup_knowledge_base_mock(
            mock_checker.bedrock_agent,
            kb_id='kb-123',
            kb_name='TestKB',
            storage_config=storage_config
        )

        # Mock restrictive data access policy
        mock_checker.bedrock_agent.get_data_access_policy = lambda **kwargs: {
            'accessPolicyDetail': {
                'type': 'data',
                'policy': json.dumps([{
                    'Rules': [{
                        'Resource': ['collection/test-collection'],
                        'Permission': ['aoss:ReadDocument', 'aoss:WriteDocument'],
                        'ResourceType': 'collection'
                    }],
                    'Principal': ['arn:aws:iam::123456789012:role/SpecificKBRole']
                }])
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        kb_checks.check_opensearch_access_policies()

        # Verify no CRITICAL findings (policy is restrictive)
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) == 0
