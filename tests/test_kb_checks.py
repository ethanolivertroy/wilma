"""
Tests for Knowledge Base security checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import pytest
from unittest.mock import Mock, patch
from wilma.checks.knowledge_bases import KnowledgeBaseSecurityChecks
from wilma.enums import RiskLevel


class TestKBDataSourceEncryption:
    """Test Knowledge Base data source encryption checks."""

    def test_unencrypted_s3_data_source(self, mock_checker):
        """Test detection of unencrypted S3 data sources."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        bedrock_agent_mock.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'dataSourceConfiguration': {
                    's3Configuration': {
                        'bucketArn': 'arn:aws:s3:::test-bucket'
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Mock S3 encryption check to return unencrypted
        with patch('wilma.checks.knowledge_bases.check_s3_bucket_encryption') as mock_check:
            mock_check.return_value = {'encrypted': False}

            # Run check
            kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
            findings = kb_checks.check_data_source_encryption()

            # Verify HIGH finding for unencrypted data source
            high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
            assert len(high_findings) > 0

    def test_encrypted_s3_data_source(self, mock_checker):
        """Test that encrypted S3 data sources pass validation."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        bedrock_agent_mock.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'dataSourceConfiguration': {
                    's3Configuration': {
                        'bucketArn': 'arn:aws:s3:::test-bucket'
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Mock S3 encryption check to return encrypted
        with patch('wilma.checks.knowledge_bases.check_s3_bucket_encryption') as mock_check:
            mock_check.return_value = {'encrypted': True, 'uses_customer_key': True}

            # Run check
            kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
            findings = kb_checks.check_data_source_encryption()

            # Verify no HIGH findings (data source is encrypted)
            high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
            assert len(high_findings) == 0


class TestKBVectorStoreEncryption:
    """Test Knowledge Base vector store encryption checks."""

    def test_unencrypted_opensearch_collection(self, mock_checker):
        """Test detection of unencrypted OpenSearch Serverless collections."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.get_knowledge_base.return_value = {
            'knowledgeBase': {
                'knowledgeBaseId': 'kb-123',
                'name': 'TestKB',
                'storageConfiguration': {
                    'type': 'OPENSEARCH_SERVERLESS',
                    'opensearchServerlessConfiguration': {
                        'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection'
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Mock AOSS client
        aoss_mock = Mock()
        aoss_mock.get_security_policy.return_value = {
            'securityPolicyDetail': {
                'policy': '{"Rules":[{"ResourceType":"collection","Resource":["collection/test-collection"]}],"AWSOwnedKey":true}'
            }
        }

        with patch.object(mock_checker.session, 'client', side_effect=lambda service: aoss_mock if service == 'opensearchserverless' else bedrock_agent_mock):
            # Run check
            kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
            findings = kb_checks.check_vector_store_encryption()

            # Verify MEDIUM finding for AWS-owned key
            medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
            assert len(medium_findings) > 0

    def test_encrypted_opensearch_collection(self, mock_checker):
        """Test that encrypted OpenSearch Serverless collections pass validation."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.get_knowledge_base.return_value = {
            'knowledgeBase': {
                'knowledgeBaseId': 'kb-123',
                'name': 'TestKB',
                'storageConfiguration': {
                    'type': 'OPENSEARCH_SERVERLESS',
                    'opensearchServerlessConfiguration': {
                        'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection'
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Mock AOSS client with customer-managed key
        aoss_mock = Mock()
        aoss_mock.get_security_policy.return_value = {
            'securityPolicyDetail': {
                'policy': '{"Rules":[{"ResourceType":"collection","Resource":["collection/test-collection"],"KmsARN":"arn:aws:kms:us-east-1:123456789012:key/12345"}]}'
            }
        }

        with patch.object(mock_checker.session, 'client', side_effect=lambda service: aoss_mock if service == 'opensearchserverless' else bedrock_agent_mock):
            # Run check
            kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
            findings = kb_checks.check_vector_store_encryption()

            # Verify no MEDIUM findings (using customer-managed key)
            medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
            assert len(medium_findings) == 0


class TestKBChunkingConfiguration:
    """Test Knowledge Base chunking configuration checks."""

    def test_excessive_chunk_size(self, mock_checker):
        """Test detection of excessive chunk sizes."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        bedrock_agent_mock.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'vectorIngestionConfiguration': {
                    'chunkingConfiguration': {
                        'chunkingStrategy': 'FIXED_SIZE',
                        'fixedSizeChunkingConfiguration': {
                            'maxTokens': 2000,  # Exceeds default threshold of 1000
                            'overlapPercentage': 20
                        }
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        findings = kb_checks.check_chunking_configuration()

        # Verify MEDIUM finding for excessive chunk size
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_acceptable_chunk_size(self, mock_checker):
        """Test that acceptable chunk sizes pass validation."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        bedrock_agent_mock.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'vectorIngestionConfiguration': {
                    'chunkingConfiguration': {
                        'chunkingStrategy': 'FIXED_SIZE',
                        'fixedSizeChunkingConfiguration': {
                            'maxTokens': 500,  # Within threshold
                            'overlapPercentage': 20
                        }
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        findings = kb_checks.check_chunking_configuration()

        # Verify no MEDIUM findings (chunk size is acceptable)
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'chunk size' in f.get('title', '').lower()]
        assert len(medium_findings) == 0


class TestKBIAMPermissions:
    """Test Knowledge Base IAM permission checks."""

    def test_wildcard_permissions(self, mock_checker):
        """Test detection of wildcard permissions in KB roles."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.get_knowledge_base.return_value = {
            'knowledgeBase': {
                'knowledgeBaseId': 'kb-123',
                'name': 'TestKB',
                'roleArn': 'arn:aws:iam::123456789012:role/KBRole'
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Mock IAM role with wildcard permissions
        mock_checker.iam.get_role.return_value = {
            'Role': {
                'RoleName': 'KBRole'
            }
        }
        mock_checker.iam.list_role_policies.return_value = {
            'PolicyNames': ['InlinePolicy']
        }
        mock_checker.iam.get_role_policy.return_value = {
            'PolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }
                ]
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        findings = kb_checks.check_iam_role_permissions()

        # Verify CRITICAL finding for wildcard permissions
        critical_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.CRITICAL]
        assert len(critical_findings) > 0

    def test_least_privilege_permissions(self, mock_checker):
        """Test that least-privilege permissions pass validation."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.get_knowledge_base.return_value = {
            'knowledgeBase': {
                'knowledgeBaseId': 'kb-123',
                'name': 'TestKB',
                'roleArn': 'arn:aws:iam::123456789012:role/KBRole'
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Mock IAM role with least-privilege permissions
        mock_checker.iam.get_role.return_value = {
            'Role': {
                'RoleName': 'KBRole'
            }
        }
        mock_checker.iam.list_role_policies.return_value = {
            'PolicyNames': ['InlinePolicy']
        }
        mock_checker.iam.get_role_policy.return_value = {
            'PolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': ['s3:GetObject', 's3:ListBucket'],
                        'Resource': 'arn:aws:s3:::specific-bucket/*'
                    }
                ]
            }
        }

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        findings = kb_checks.check_iam_role_permissions()

        # Verify no CRITICAL findings (permissions are least-privilege)
        critical_findings = [f for f in mock_checker.findings
                            if f.get('risk_level') == RiskLevel.CRITICAL
                            and 'wildcard' in f.get('title', '').lower()]
        assert len(critical_findings) == 0


class TestKBPIIDetection:
    """Test Knowledge Base PII detection checks."""

    def test_pii_in_bucket_name(self, mock_checker):
        """Test detection of PII patterns in S3 bucket names."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        bedrock_agent_mock.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'dataSourceConfiguration': {
                    's3Configuration': {
                        'bucketArn': 'arn:aws:s3:::customer-data-john.doe@example.com'  # Contains email
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        findings = kb_checks.check_pii_exposure()

        # Verify MEDIUM finding for PII in metadata
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_no_pii_in_metadata(self, mock_checker):
        """Test that clean metadata passes validation."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.list_data_sources.return_value = {
            'dataSourceSummaries': [
                {'dataSourceId': 'ds-123', 'name': 'TestDataSource'}
            ]
        }
        bedrock_agent_mock.get_data_source.return_value = {
            'dataSource': {
                'dataSourceId': 'ds-123',
                'name': 'TestDataSource',
                'dataSourceConfiguration': {
                    's3Configuration': {
                        'bucketArn': 'arn:aws:s3:::customer-documents-bucket'  # No PII
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Run check
        kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
        findings = kb_checks.check_pii_exposure()

        # Verify no MEDIUM findings for PII (INFO finding about limitation is okay)
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'PII' in f.get('title', '')]
        assert len(medium_findings) == 0


class TestKBOpenSearchAccessPolicies:
    """Test OpenSearch Serverless access policy checks."""

    def test_overly_permissive_data_access_policy(self, mock_checker):
        """Test detection of overly permissive data access policies."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.get_knowledge_base.return_value = {
            'knowledgeBase': {
                'knowledgeBaseId': 'kb-123',
                'name': 'TestKB',
                'storageConfiguration': {
                    'type': 'OPENSEARCH_SERVERLESS',
                    'opensearchServerlessConfiguration': {
                        'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection'
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Mock AOSS client with wildcard principal in data access policy
        aoss_mock = Mock()
        aoss_mock.get_access_policy.return_value = {
            'accessPolicyDetail': {
                'policy': '[{"Rules":[{"ResourceType":"collection","Resource":["collection/test-collection"],"Permission":["aoss:*"]}],"Principal":["arn:aws:iam::*:role/*"]}]'
            }
        }

        with patch.object(mock_checker.session, 'client', side_effect=lambda service: aoss_mock if service == 'opensearchserverless' else bedrock_agent_mock):
            # Run check
            kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
            findings = kb_checks.check_opensearch_access_policies()

            # Verify HIGH finding for wildcard principal
            high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
            assert len(high_findings) > 0

    def test_restrictive_data_access_policy(self, mock_checker):
        """Test that restrictive data access policies pass validation."""
        # Create bedrock-agent client mock
        bedrock_agent_mock = Mock()
        bedrock_agent_mock.list_knowledge_bases.return_value = {
            'knowledgeBaseSummaries': [
                {'knowledgeBaseId': 'kb-123', 'name': 'TestKB'}
            ]
        }
        bedrock_agent_mock.get_knowledge_base.return_value = {
            'knowledgeBase': {
                'knowledgeBaseId': 'kb-123',
                'name': 'TestKB',
                'storageConfiguration': {
                    'type': 'OPENSEARCH_SERVERLESS',
                    'opensearchServerlessConfiguration': {
                        'collectionArn': 'arn:aws:aoss:us-east-1:123456789012:collection/test-collection'
                    }
                }
            }
        }
        mock_checker.session.client = Mock(return_value=bedrock_agent_mock)

        # Mock AOSS client with specific principal
        aoss_mock = Mock()
        aoss_mock.get_access_policy.return_value = {
            'accessPolicyDetail': {
                'policy': '[{"Rules":[{"ResourceType":"collection","Resource":["collection/test-collection"],"Permission":["aoss:ReadDocument"]}],"Principal":["arn:aws:iam::123456789012:role/KBRole"]}]'
            }
        }

        with patch.object(mock_checker.session, 'client', side_effect=lambda service: aoss_mock if service == 'opensearchserverless' else bedrock_agent_mock):
            # Run check
            kb_checks = KnowledgeBaseSecurityChecks(mock_checker)
            findings = kb_checks.check_opensearch_access_policies()

            # Verify no HIGH findings (policy is restrictive)
            high_findings = [f for f in mock_checker.findings
                            if f.get('risk_level') == RiskLevel.HIGH
                            and 'permissive' in f.get('title', '').lower()]
            assert len(high_findings) == 0
