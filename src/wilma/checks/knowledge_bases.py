"""
AWS Bedrock Knowledge Bases (RAG) Security Checks

Validates security of Knowledge Bases that connect foundation models to proprietary data.

12 Comprehensive Checks:
1. S3 Bucket Public Access - Prevents data poisoning via public uploads
2. S3 Bucket Encryption - Protects data at rest
3. Vector Store Encryption - Secures embeddings (OpenSearch/Aurora/RDS/Pinecone/Redis)
4. Vector Store Access Control - Validates IAM and network restrictions
5. PII Detection - Scans for sensitive data in embeddings
6. Prompt Injection Detection - Identifies malicious patterns in documents
7. S3 Versioning - Enables recovery from poisoning/corruption
8. Access Pattern Analysis - Monitors IAM roles and permissions
9. Chunking Configuration - Reviews parsing strategies
10. Logging - Validates CloudWatch integration
11. Resource Tagging - Ensures compliance tracking
12. Embedding Model Access - Verifies model permissions

Threat Coverage:
- OWASP LLM01: Prompt Injection (indirect via RAG documents)
- OWASP LLM03: Training Data Poisoning (malicious document injection)
- OWASP LLM06: Sensitive Information Disclosure (PII in embeddings)
- MITRE ATLAS AML.T0020: Poison Training Data
"""

from typing import Dict, List, Optional
from botocore.exceptions import ClientError
from ..enums import RiskLevel
from wilma.utils import paginate_aws_results, handle_aws_error


class KnowledgeBaseSecurityChecks:
    """
    Knowledge Base (RAG) Security Validator

    Each check method returns a list of findings.
    Uses self.checker.add_finding() to report issues.
    """

    def __init__(self, checker):
        """
        Initialize with AWS clients for KB, S3, and vector store access.

        Note: bedrock-agent client provides Knowledge Base API access.
        """
        self.checker = checker
        self.bedrock = checker.bedrock
        self.bedrock_agent = checker.session.client('bedrock-agent')
        self.s3 = checker.session.client('s3')
        self.opensearch = checker.session.client('opensearch')
        self.findings = []

    def _get_all_knowledge_bases(self) -> List[Dict]:
        """
        Get all knowledge bases with pagination support.

        Returns list of knowledge base summaries.
        Handles accounts with >100 knowledge bases.
        """
        knowledge_bases = []
        try:
            for kb in paginate_aws_results(
                self.bedrock_agent.list_knowledge_bases,
                'knowledgeBaseSummaries',
                token_key='nextToken',
                token_param='nextToken',
                maxResults=100
            ):
                knowledge_bases.append(kb)
        except ClientError as e:
            handle_aws_error(e, "listing knowledge bases")
        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return knowledge_bases

    def check_s3_bucket_public_access(self) -> List[Dict]:
        """
        Validate Block Public Access is enabled on all KB data source S3 buckets.

        WHY CRITICAL: Public S3 access enables data poisoning attacks.
        Attackers can inject malicious documents that get embedded into your KB,
        causing the model to return poisoned information to users.

        Checks: S3 Block Public Access configuration for all buckets
        Risk: CRITICAL if disabled
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for S3 bucket security...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get detailed knowledge base configuration
                    kb_details = self.bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
                    kb_config = kb_details.get('knowledgeBase', {})
                    storage_config = kb_config.get('storageConfiguration', {})

                    # Extract S3 data source information
                    data_sources_response = self.bedrock_agent.list_data_sources(
                        knowledgeBaseId=kb_id,
                        maxResults=100
                    )

                    for data_source in data_sources_response.get('dataSourceSummaries', []):
                        ds_id = data_source['dataSourceId']
                        ds_name = data_source.get('name', ds_id)

                        # Get data source details
                        ds_details = self.bedrock_agent.get_data_source(
                            knowledgeBaseId=kb_id,
                            dataSourceId=ds_id
                        )

                        ds_config = ds_details.get('dataSource', {}).get('dataSourceConfiguration', {})
                        s3_config = ds_config.get('s3Configuration', {})
                        bucket_arn = s3_config.get('bucketArn', '')

                        if not bucket_arn:
                            continue

                        # Extract bucket name from ARN (format: arn:aws:s3:::bucket-name)
                        bucket_name = bucket_arn.split(':::')[-1] if ':::' in bucket_arn else None

                        if not bucket_name:
                            continue

                        # Check Block Public Access settings
                        try:
                            bpa_response = self.s3.get_public_access_block(Bucket=bucket_name)
                            bpa_config = bpa_response.get('PublicAccessBlockConfiguration', {})

                            block_public_acls = bpa_config.get('BlockPublicAcls', False)
                            ignore_public_acls = bpa_config.get('IgnorePublicAcls', False)
                            block_public_policy = bpa_config.get('BlockPublicPolicy', False)
                            restrict_public_buckets = bpa_config.get('RestrictPublicBuckets', False)

                            all_blocked = all([
                                block_public_acls,
                                ignore_public_acls,
                                block_public_policy,
                                restrict_public_buckets
                            ])

                            if not all_blocked:
                                findings.append({
                                    'risk_level': RiskLevel.CRITICAL,
                                    'title': f'Knowledge Base S3 bucket lacks complete public access blocking',
                                    'description': (
                                        f'Knowledge Base "{kb_name}" uses S3 bucket "{bucket_name}" '
                                        f'which does not have all Block Public Access settings enabled. '
                                        f'This could allow attackers to inject malicious documents that '
                                        f'get embedded into your RAG system, leading to data poisoning.'
                                    ),
                                    'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                    'resource': f's3://{bucket_name}',
                                    'remediation': (
                                        f'Enable all Block Public Access settings:\n'
                                        f'aws s3api put-public-access-block --bucket {bucket_name} \\\n'
                                        f'  --public-access-block-configuration \\\n'
                                        f'  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
                                    ),
                                    'details': {
                                        'knowledge_base_id': kb_id,
                                        'data_source_id': ds_id,
                                        'bucket_name': bucket_name,
                                        'block_public_acls': block_public_acls,
                                        'ignore_public_acls': ignore_public_acls,
                                        'block_public_policy': block_public_policy,
                                        'restrict_public_buckets': restrict_public_buckets
                                    }
                                })

                        except self.s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                            # No public access block configuration exists - CRITICAL
                            findings.append({
                                'risk_level': RiskLevel.CRITICAL,
                                'title': f'Knowledge Base S3 bucket has no public access blocking',
                                'description': (
                                    f'Knowledge Base "{kb_name}" uses S3 bucket "{bucket_name}" '
                                    f'which has NO Block Public Access configuration. This is extremely '
                                    f'dangerous as the bucket could be made public, allowing attackers '
                                    f'to poison your knowledge base with malicious content.'
                                ),
                                'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                'resource': f's3://{bucket_name}',
                                'remediation': (
                                    f'Enable Block Public Access immediately:\n'
                                    f'aws s3api put-public-access-block --bucket {bucket_name} \\\n'
                                    f'  --public-access-block-configuration \\\n'
                                    f'  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
                                ),
                                'details': {
                                    'knowledge_base_id': kb_id,
                                    'data_source_id': ds_id,
                                    'bucket_name': bucket_name,
                                    'configuration': 'NONE'
                                }
                            })

                        except Exception as e:
                            print(f"[WARN] Could not check public access for bucket {bucket_name}: {str(e)}")

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def _create_s3_encryption_finding(
        self,
        risk_level: RiskLevel,
        title: str,
        kb_name: str,
        kb_id: str,
        ds_name: str,
        ds_id: str,
        bucket_name: str,
        encryption_type: str,
        description_template: str
    ) -> Dict:
        """
        Helper to create S3 encryption findings (DRY principle).

        Eliminates duplicate code for encryption finding generation.
        """
        return {
            'risk_level': risk_level,
            'title': title,
            'description': description_template.format(
                kb_name=kb_name,
                bucket_name=bucket_name,
                ds_name=ds_name
            ),
            'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
            'resource': f's3://{bucket_name}',
            'remediation': (
                f'Enable encryption with customer-managed KMS key:\n'
                f'aws s3api put-bucket-encryption --bucket {bucket_name} \\\n'
                f'  --server-side-encryption-configuration \'{{\n'
                f'    "Rules": [{{\n'
                f'      "ApplyServerSideEncryptionByDefault": {{\n'
                f'        "SSEAlgorithm": "aws:kms",\n'
                f'        "KMSMasterKeyID": "your-kms-key-id"\n'
                f'      }}\n'
                f'    }}]\n'
                f'  }}\''
            ),
            'details': {
                'knowledge_base_id': kb_id,
                'data_source_id': ds_id,
                'bucket_name': bucket_name,
                'encryption': encryption_type
            }
        }

    def check_s3_bucket_encryption(self) -> List[Dict]:
        """
        Verify S3 buckets for knowledge bases use encryption at rest.

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for S3 encryption...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get data sources for this knowledge base
                    data_sources_response = self.bedrock_agent.list_data_sources(
                        knowledgeBaseId=kb_id,
                        maxResults=100
                    )

                    for data_source in data_sources_response.get('dataSourceSummaries', []):
                        ds_id = data_source['dataSourceId']
                        ds_name = data_source.get('name', ds_id)

                        # Get data source details
                        ds_details = self.bedrock_agent.get_data_source(
                            knowledgeBaseId=kb_id,
                            dataSourceId=ds_id
                        )

                        ds_config = ds_details.get('dataSource', {}).get('dataSourceConfiguration', {})
                        s3_config = ds_config.get('s3Configuration', {})
                        bucket_arn = s3_config.get('bucketArn', '')

                        if not bucket_arn:
                            continue

                        # Extract bucket name from ARN
                        bucket_name = bucket_arn.split(':::')[-1] if ':::' in bucket_arn else None

                        if not bucket_name:
                            continue

                        # Check bucket encryption
                        try:
                            encryption_response = self.s3.get_bucket_encryption(Bucket=bucket_name)
                            encryption_rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])

                            if not encryption_rules:
                                findings.append(self._create_s3_encryption_finding(
                                    risk_level=RiskLevel.HIGH,
                                    title=f'Knowledge Base S3 bucket has no encryption',
                                    kb_name=kb_name,
                                    kb_id=kb_id,
                                    ds_name=ds_name,
                                    ds_id=ds_id,
                                    bucket_name=bucket_name,
                                    encryption_type='NONE',
                                    description_template=(
                                        'Knowledge Base "{kb_name}" uses S3 bucket "{bucket_name}" '
                                        'which has no server-side encryption configured. Your proprietary '
                                        'knowledge base data is stored unencrypted at rest.'
                                    )
                                ))
                            else:
                                # Check encryption type
                                for rule in encryption_rules:
                                    sse_config = rule.get('ApplyServerSideEncryptionByDefault', {})
                                    sse_algorithm = sse_config.get('SSEAlgorithm', '')
                                    kms_key_id = sse_config.get('KMSMasterKeyID', '')

                                    if sse_algorithm == 'AES256':
                                        # Using AWS-managed keys (SSE-S3)
                                        findings.append({
                                            'risk_level': RiskLevel.MEDIUM,
                                            'title': f'Knowledge Base S3 bucket uses AWS-managed encryption',
                                            'description': (
                                                f'Knowledge Base "{kb_name}" uses S3 bucket "{bucket_name}" '
                                                f'which is encrypted with AWS-managed keys (SSE-S3). Best practice '
                                                f'is to use customer-managed KMS keys for better control and auditability.'
                                            ),
                                            'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                            'resource': f's3://{bucket_name}',
                                            'remediation': (
                                                f'Upgrade to customer-managed KMS encryption:\n'
                                                f'aws s3api put-bucket-encryption --bucket {bucket_name} \\\n'
                                                f'  --server-side-encryption-configuration \'{{\n'
                                                f'    "Rules": [{{\n'
                                                f'      "ApplyServerSideEncryptionByDefault": {{\n'
                                                f'        "SSEAlgorithm": "aws:kms",\n'
                                                f'        "KMSMasterKeyID": "your-kms-key-id"\n'
                                                f'      }}\n'
                                                f'    }}]\n'
                                                f'  }}\''
                                            ),
                                            'details': {
                                                'knowledge_base_id': kb_id,
                                                'data_source_id': ds_id,
                                                'bucket_name': bucket_name,
                                                'encryption': 'SSE-S3'
                                            }
                                        })
                                    elif sse_algorithm == 'aws:kms' and not kms_key_id:
                                        # Using default AWS KMS key
                                        findings.append({
                                            'risk_level': RiskLevel.MEDIUM,
                                            'title': f'Knowledge Base S3 bucket uses default KMS key',
                                            'description': (
                                                f'Knowledge Base "{kb_name}" uses S3 bucket "{bucket_name}" '
                                                f'which is encrypted with the default AWS KMS key. Best practice '
                                                f'is to use a customer-managed KMS key for better access control.'
                                            ),
                                            'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                            'resource': f's3://{bucket_name}',
                                            'remediation': (
                                                f'Configure customer-managed KMS key:\n'
                                                f'aws s3api put-bucket-encryption --bucket {bucket_name} \\\n'
                                                f'  --server-side-encryption-configuration \'{{\n'
                                                f'    "Rules": [{{\n'
                                                f'      "ApplyServerSideEncryptionByDefault": {{\n'
                                                f'        "SSEAlgorithm": "aws:kms",\n'
                                                f'        "KMSMasterKeyID": "your-kms-key-id"\n'
                                                f'      }}\n'
                                                f'    }}]\n'
                                                f'  }}\''
                                            ),
                                            'details': {
                                                'knowledge_base_id': kb_id,
                                                'data_source_id': ds_id,
                                                'bucket_name': bucket_name,
                                                'encryption': 'aws:kms (default)'
                                            }
                                        })
                                    # else: using customer-managed KMS key - good!

                        except self.s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                            findings.append(self._create_s3_encryption_finding(
                                risk_level=RiskLevel.HIGH,
                                title=f'Knowledge Base S3 bucket has no encryption',
                                kb_name=kb_name,
                                kb_id=kb_id,
                                ds_name=ds_name,
                                ds_id=ds_id,
                                bucket_name=bucket_name,
                                encryption_type='NONE',
                                description_template=(
                                    'Knowledge Base "{kb_name}" uses S3 bucket "{bucket_name}" '
                                    'which has no server-side encryption configured. Your proprietary '
                                    'knowledge base data is stored unencrypted at rest.'
                                )
                            ))

                        except Exception as e:
                            print(f"[WARN] Could not check encryption for bucket {bucket_name}: {str(e)}")

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def check_vector_store_encryption(self) -> List[Dict]:
        """
        Validate vector stores (OpenSearch/Aurora) use encryption.

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for vector store encryption...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get knowledge base details
                    kb_details = self.bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
                    kb_config = kb_details.get('knowledgeBase', {})
                    storage_config = kb_config.get('storageConfiguration', {})
                    storage_type = storage_config.get('type', 'UNKNOWN')

                    # Check based on storage type
                    if storage_type == 'OPENSEARCH_SERVERLESS':
                        # OpenSearch Serverless - check collection ARN
                        oss_config = storage_config.get('opensearchServerlessConfiguration', {})
                        collection_arn = oss_config.get('collectionArn', '')

                        if collection_arn:
                            # OpenSearch Serverless collections are always encrypted at rest
                            # No action needed - this is good!
                            pass

                    elif storage_type == 'PINECONE':
                        # Pinecone - managed service, check configuration
                        pinecone_config = storage_config.get('pineconeConfiguration', {})
                        # Pinecone encrypts at rest by default, but we note it
                        print(f"[INFO] Knowledge Base {kb_name} uses Pinecone (encrypted by default)")

                    elif storage_type == 'REDIS_ENTERPRISE_CLOUD':
                        # Redis Enterprise Cloud - check configuration
                        redis_config = storage_config.get('redisEnterpriseCloudConfiguration', {})
                        # Redis Enterprise encrypts at rest, but we note it
                        print(f"[INFO] Knowledge Base {kb_name} uses Redis Enterprise (encrypted by default)")

                    elif storage_type == 'RDS':
                        # Aurora/RDS - need to check database encryption
                        rds_config = storage_config.get('rdsConfiguration', {})
                        resource_arn = rds_config.get('resourceArn', '')

                        if resource_arn:
                            # Extract cluster identifier from ARN
                            # Format: arn:aws:rds:region:account:cluster:cluster-name
                            cluster_id = resource_arn.split(':')[-1] if ':' in resource_arn else None

                            if cluster_id:
                                try:
                                    rds = self.checker.session.client('rds')
                                    # Check if it's a cluster
                                    try:
                                        cluster_response = rds.describe_db_clusters(
                                            DBClusterIdentifier=cluster_id
                                        )
                                        clusters = cluster_response.get('DBClusters', [])

                                        if clusters:
                                            cluster = clusters[0]
                                            storage_encrypted = cluster.get('StorageEncrypted', False)

                                            if not storage_encrypted:
                                                findings.append({
                                                    'risk_level': RiskLevel.HIGH,
                                                    'title': f'Knowledge Base Aurora cluster is not encrypted',
                                                    'description': (
                                                        f'Knowledge Base "{kb_name}" uses Aurora cluster "{cluster_id}" '
                                                        f'which does not have storage encryption enabled. Your vector '
                                                        f'embeddings are stored unencrypted at rest.'
                                                    ),
                                                    'location': f'Knowledge Base: {kb_name}',
                                                    'resource': cluster_id,
                                                    'remediation': (
                                                        f'Aurora encryption cannot be enabled on existing clusters. '
                                                        f'You must:\n'
                                                        f'1. Create encrypted snapshot of current cluster\n'
                                                        f'2. Copy snapshot with encryption enabled\n'
                                                        f'3. Restore from encrypted snapshot\n'
                                                        f'4. Update knowledge base to use new encrypted cluster'
                                                    ),
                                                    'details': {
                                                        'knowledge_base_id': kb_id,
                                                        'cluster_id': cluster_id,
                                                        'storage_encrypted': False
                                                    }
                                                })

                                    except rds.exceptions.DBClusterNotFoundFault:
                                        # Might be an RDS instance instead
                                        instance_response = rds.describe_db_instances(
                                            DBInstanceIdentifier=cluster_id
                                        )
                                        instances = instance_response.get('DBInstances', [])

                                        if instances:
                                            instance = instances[0]
                                            storage_encrypted = instance.get('StorageEncrypted', False)

                                            if not storage_encrypted:
                                                findings.append({
                                                    'risk_level': RiskLevel.HIGH,
                                                    'title': f'Knowledge Base RDS instance is not encrypted',
                                                    'description': (
                                                        f'Knowledge Base "{kb_name}" uses RDS instance "{cluster_id}" '
                                                        f'which does not have storage encryption enabled. Your vector '
                                                        f'embeddings are stored unencrypted at rest.'
                                                    ),
                                                    'location': f'Knowledge Base: {kb_name}',
                                                    'resource': cluster_id,
                                                    'remediation': (
                                                        f'RDS encryption cannot be enabled on existing instances. '
                                                        f'You must:\n'
                                                        f'1. Create encrypted snapshot of current instance\n'
                                                        f'2. Copy snapshot with encryption enabled\n'
                                                        f'3. Restore from encrypted snapshot\n'
                                                        f'4. Update knowledge base to use new encrypted instance'
                                                    ),
                                                    'details': {
                                                        'knowledge_base_id': kb_id,
                                                        'instance_id': cluster_id,
                                                        'storage_encrypted': False
                                                    }
                                                })

                                except Exception as e:
                                    print(f"[WARN] Could not check RDS encryption for {cluster_id}: {str(e)}")

                    else:
                        print(f"[WARN] Unknown storage type {storage_type} for knowledge base {kb_name}")

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def check_vector_store_access_control(self) -> List[Dict]:
        """
        Verify vector stores have proper network access controls.

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for vector store access control...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get knowledge base details
                    kb_details = self.bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
                    kb_config = kb_details.get('knowledgeBase', {})
                    storage_config = kb_config.get('storageConfiguration', {})
                    storage_type = storage_config.get('type', 'UNKNOWN')

                    # Check based on storage type
                    if storage_type == 'OPENSEARCH_SERVERLESS':
                        # OpenSearch Serverless - check collection access policy
                        oss_config = storage_config.get('opensearchServerlessConfiguration', {})
                        collection_arn = oss_config.get('collectionArn', '')

                        if collection_arn:
                            # Extract collection name from ARN
                            collection_name = collection_arn.split('/')[-1] if '/' in collection_arn else None

                            if collection_name:
                                try:
                                    # Get collection details
                                    aoss = self.checker.session.client('opensearchserverless')
                                    collection_response = aoss.batch_get_collection(
                                        names=[collection_name]
                                    )

                                    collections = collection_response.get('collectionDetails', [])

                                    if collections:
                                        collection = collections[0]
                                        collection_type = collection.get('type', '')

                                        # OpenSearch Serverless collections should have VPC endpoints
                                        # Check if collection has network access policy
                                        try:
                                            network_policy = aoss.get_access_policy(
                                                name=f"{collection_name}-network",
                                                type='network'
                                            )

                                            policy_detail = network_policy.get('accessPolicyDetail', {})
                                            policy_document = policy_detail.get('policy', '')

                                            # Parse policy to check for public access
                                            import json
                                            if policy_document:
                                                try:
                                                    policy_json = json.loads(policy_document)
                                                    # Check for AllowFromPublic rules
                                                    for rule in policy_json:
                                                        if rule.get('AllowFromPublic', False):
                                                            findings.append({
                                                                'risk_level': RiskLevel.CRITICAL,
                                                                'title': f'Knowledge Base OpenSearch collection allows public access',
                                                                'description': (
                                                                    f'Knowledge Base "{kb_name}" uses OpenSearch Serverless '
                                                                    f'collection "{collection_name}" which allows public access. '
                                                                    f'This exposes your vector embeddings to potential unauthorized access.'
                                                                ),
                                                                'location': f'Knowledge Base: {kb_name}',
                                                                'resource': collection_name,
                                                                'remediation': (
                                                                    f'Update network policy to restrict access to VPC only:\n'
                                                                    f'aws opensearchserverless update-access-policy \\\n'
                                                                    f'  --name {collection_name}-network \\\n'
                                                                    f'  --type network \\\n'
                                                                    f'  --policy \'[{{"Rules":[{{"ResourceType":"collection",'
                                                                    f'"Resource":["collection/{collection_name}"]}}],'
                                                                    f'"AllowFromPublic":false,"SourceVPCEs":["your-vpc-endpoint"]}}]\''
                                                                ),
                                                                'details': {
                                                                    'knowledge_base_id': kb_id,
                                                                    'collection_name': collection_name,
                                                                    'public_access': True
                                                                }
                                                            })

                                                except json.JSONDecodeError:
                                                    print(f"[WARN] Could not parse network policy for collection {collection_name}")

                                        except aoss.exceptions.ResourceNotFoundException:
                                            # No network policy - potentially public
                                            findings.append({
                                                'risk_level': RiskLevel.HIGH,
                                                'title': f'Knowledge Base OpenSearch collection has no network policy',
                                                'description': (
                                                    f'Knowledge Base "{kb_name}" uses OpenSearch Serverless '
                                                    f'collection "{collection_name}" which has no network access policy. '
                                                    f'This may allow unrestricted access.'
                                                ),
                                                'location': f'Knowledge Base: {kb_name}',
                                                'resource': collection_name,
                                                'remediation': (
                                                    f'Create network policy to restrict access:\n'
                                                    f'aws opensearchserverless create-access-policy \\\n'
                                                    f'  --name {collection_name}-network \\\n'
                                                    f'  --type network \\\n'
                                                    f'  --policy \'[{{"Rules":[{{"ResourceType":"collection",'
                                                    f'"Resource":["collection/{collection_name}"]}}],'
                                                    f'"AllowFromPublic":false,"SourceVPCEs":["your-vpc-endpoint"]}}]\''
                                                ),
                                                'details': {
                                                    'knowledge_base_id': kb_id,
                                                    'collection_name': collection_name,
                                                    'network_policy': 'NONE'
                                                }
                                            })

                                        # Check data access policy (in addition to network policy)
                                        try:
                                            data_policy = aoss.get_access_policy(
                                                name=f"{collection_name}-data",
                                                type='data'
                                            )

                                            policy_detail = data_policy.get('accessPolicyDetail', {})
                                            policy_document = policy_detail.get('policy', '')

                                            # Parse data access policy
                                            import json
                                            if policy_document:
                                                try:
                                                    policy_json = json.loads(policy_document)

                                                    # Check for overly permissive principals
                                                    has_wildcard_principal = False
                                                    for rule in policy_json:
                                                        principals = rule.get('Principal', [])
                                                        if isinstance(principals, str):
                                                            principals = [principals]

                                                        # Check for wildcards in principals
                                                        for principal in principals:
                                                            if principal == '*' or ':*' in principal:
                                                                has_wildcard_principal = True
                                                                break

                                                    if has_wildcard_principal:
                                                        findings.append({
                                                            'risk_level': RiskLevel.HIGH,
                                                            'title': f'Knowledge Base OpenSearch collection has overly permissive data access policy',
                                                            'description': (
                                                                f'Knowledge Base "{kb_name}" uses OpenSearch Serverless '
                                                                f'collection "{collection_name}" with a data access policy '
                                                                f'that grants access to wildcard principals. This may allow '
                                                                f'unintended IAM principals to access your vector embeddings.'
                                                            ),
                                                            'location': f'Knowledge Base: {kb_name}',
                                                            'resource': collection_name,
                                                            'remediation': (
                                                                f'Update data access policy to specific IAM principals:\n'
                                                                f'aws opensearchserverless update-access-policy \\\n'
                                                                f'  --name {collection_name}-data \\\n'
                                                                f'  --type data \\\n'
                                                                f'  --policy \'[{{"Rules":[{{"ResourceType":"index",'
                                                                f'"Resource":["index/{collection_name}/*"],'
                                                                f'"Permission":["aoss:ReadDocument","aoss:WriteDocument"]}}],'
                                                                f'"Principal":["arn:aws:iam::ACCOUNT:role/SpecificRole"]}}]\''
                                                            ),
                                                            'details': {
                                                                'knowledge_base_id': kb_id,
                                                                'collection_name': collection_name,
                                                                'issue': 'Wildcard principals in data access policy'
                                                            }
                                                        })

                                                except json.JSONDecodeError:
                                                    print(f"[WARN] Could not parse data access policy for collection {collection_name}")

                                        except aoss.exceptions.ResourceNotFoundException:
                                            # No data access policy
                                            findings.append({
                                                'risk_level': RiskLevel.HIGH,
                                                'title': f'Knowledge Base OpenSearch collection has no data access policy',
                                                'description': (
                                                    f'Knowledge Base "{kb_name}" uses OpenSearch Serverless '
                                                    f'collection "{collection_name}" which has no data access policy. '
                                                    f'Collection may be inaccessible or have default overly permissive access.'
                                                ),
                                                'location': f'Knowledge Base: {kb_name}',
                                                'resource': collection_name,
                                                'remediation': (
                                                    f'Create data access policy with least-privilege IAM principals:\n'
                                                    f'aws opensearchserverless create-access-policy \\\n'
                                                    f'  --name {collection_name}-data \\\n'
                                                    f'  --type data \\\n'
                                                    f'  --policy \'[{{"Rules":[{{"ResourceType":"index",'
                                                    f'"Resource":["index/{collection_name}/*"],'
                                                    f'"Permission":["aoss:ReadDocument","aoss:WriteDocument"]}}],'
                                                    f'"Principal":["arn:aws:iam::ACCOUNT:role/KnowledgeBaseRole"]}}]\''
                                                ),
                                                'details': {
                                                    'knowledge_base_id': kb_id,
                                                    'collection_name': collection_name,
                                                    'data_policy': 'NONE'
                                                }
                                            })

                                        except Exception as e:
                                            print(f"[WARN] Could not check data access policy for {collection_name}: {str(e)}")

                                except Exception as e:
                                    print(f"[WARN] Could not check OpenSearch collection {collection_name}: {str(e)}")

                    elif storage_type == 'RDS':
                        # Aurora/RDS - check for public accessibility
                        rds_config = storage_config.get('rdsConfiguration', {})
                        resource_arn = rds_config.get('resourceArn', '')

                        if resource_arn:
                            cluster_id = resource_arn.split(':')[-1] if ':' in resource_arn else None

                            if cluster_id:
                                try:
                                    rds = self.checker.session.client('rds')

                                    try:
                                        cluster_response = rds.describe_db_clusters(
                                            DBClusterIdentifier=cluster_id
                                        )
                                        clusters = cluster_response.get('DBClusters', [])

                                        if clusters:
                                            cluster = clusters[0]
                                            publicly_accessible = cluster.get('PubliclyAccessible', False)

                                            if publicly_accessible:
                                                findings.append({
                                                    'risk_level': RiskLevel.CRITICAL,
                                                    'title': f'Knowledge Base Aurora cluster is publicly accessible',
                                                    'description': (
                                                        f'Knowledge Base "{kb_name}" uses Aurora cluster "{cluster_id}" '
                                                        f'which is configured as publicly accessible. Your vector '
                                                        f'embeddings can be accessed from the internet.'
                                                    ),
                                                    'location': f'Knowledge Base: {kb_name}',
                                                    'resource': cluster_id,
                                                    'remediation': (
                                                        f'Modify cluster to disable public accessibility:\n'
                                                        f'aws rds modify-db-cluster \\\n'
                                                        f'  --db-cluster-identifier {cluster_id} \\\n'
                                                        f'  --no-publicly-accessible'
                                                    ),
                                                    'details': {
                                                        'knowledge_base_id': kb_id,
                                                        'cluster_id': cluster_id,
                                                        'publicly_accessible': True
                                                    }
                                                })

                                    except rds.exceptions.DBClusterNotFoundFault:
                                        instance_response = rds.describe_db_instances(
                                            DBInstanceIdentifier=cluster_id
                                        )
                                        instances = instance_response.get('DBInstances', [])

                                        if instances:
                                            instance = instances[0]
                                            publicly_accessible = instance.get('PubliclyAccessible', False)

                                            if publicly_accessible:
                                                findings.append({
                                                    'risk_level': RiskLevel.CRITICAL,
                                                    'title': f'Knowledge Base RDS instance is publicly accessible',
                                                    'description': (
                                                        f'Knowledge Base "{kb_name}" uses RDS instance "{cluster_id}" '
                                                        f'which is configured as publicly accessible. Your vector '
                                                        f'embeddings can be accessed from the internet.'
                                                    ),
                                                    'location': f'Knowledge Base: {kb_name}',
                                                    'resource': cluster_id,
                                                    'remediation': (
                                                        f'Modify instance to disable public accessibility:\n'
                                                        f'aws rds modify-db-instance \\\n'
                                                        f'  --db-instance-identifier {cluster_id} \\\n'
                                                        f'  --no-publicly-accessible'
                                                    ),
                                                    'details': {
                                                        'knowledge_base_id': kb_id,
                                                        'instance_id': cluster_id,
                                                        'publicly_accessible': True
                                                    }
                                                })

                                except Exception as e:
                                    print(f"[WARN] Could not check RDS accessibility for {cluster_id}: {str(e)}")

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def check_pii_in_embeddings(self) -> List[Dict]:
        """
        Detect if knowledge base data sources contain PII before embedding.

        Returns:
            List of security findings
        """
        findings = []

        # PII patterns for basic detection
        import re
        pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'aws_key': r'AKIA[0-9A-Z]{16}'
        }

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for PII patterns...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)
                kb_description = kb.get('description', '')

                # Check for PII in knowledge base name and description
                pii_found_in_metadata = []
                for pii_type, pattern in pii_patterns.items():
                    if re.search(pattern, kb_name, re.IGNORECASE):
                        pii_found_in_metadata.append(f'{pii_type} in name')
                    if re.search(pattern, kb_description, re.IGNORECASE):
                        pii_found_in_metadata.append(f'{pii_type} in description')

                if pii_found_in_metadata:
                    findings.append({
                        'risk_level': RiskLevel.HIGH,
                        'title': f'Knowledge Base metadata contains PII patterns',
                        'description': (
                            f'Knowledge Base "{kb_name}" has PII-like patterns in its metadata: '
                            f'{", ".join(pii_found_in_metadata)}. This may indicate sensitive '
                            f'information exposure in resource names.'
                        ),
                        'location': f'Knowledge Base: {kb_name}',
                        'resource': kb_id,
                        'remediation': (
                            f'Remove PII from knowledge base metadata:\n'
                            f'1. Update knowledge base name and description to remove sensitive data\n'
                            f'2. Use generic identifiers instead of personal information\n'
                            f'3. Review data governance policies'
                        ),
                        'details': {
                            'knowledge_base_id': kb_id,
                            'pii_types_detected': pii_found_in_metadata
                        }
                    })

                try:
                    # Check S3 data source bucket names and prefixes for PII
                    data_sources_response = self.bedrock_agent.list_data_sources(
                        knowledgeBaseId=kb_id,
                        maxResults=100
                    )

                    for data_source in data_sources_response.get('dataSourceSummaries', []):
                        ds_id = data_source['dataSourceId']
                        ds_name = data_source.get('name', ds_id)
                        ds_description = data_source.get('description', '')

                        # Check data source metadata
                        pii_in_ds = []
                        for pii_type, pattern in pii_patterns.items():
                            if re.search(pattern, ds_name, re.IGNORECASE):
                                pii_in_ds.append(f'{pii_type} in data source name')
                            if re.search(pattern, ds_description, re.IGNORECASE):
                                pii_in_ds.append(f'{pii_type} in data source description')

                        if pii_in_ds:
                            findings.append({
                                'risk_level': RiskLevel.HIGH,
                                'title': f'Knowledge Base data source contains PII patterns',
                                'description': (
                                    f'Data source "{ds_name}" in Knowledge Base "{kb_name}" '
                                    f'contains PII-like patterns: {", ".join(pii_in_ds)}.'
                                ),
                                'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                'resource': ds_id,
                                'remediation': (
                                    f'Remove PII from data source configuration:\n'
                                    f'1. Update data source name and description\n'
                                    f'2. Use AWS Macie for comprehensive PII scanning of S3 buckets\n'
                                    f'3. Implement DLP policies before embedding'
                                ),
                                'details': {
                                    'knowledge_base_id': kb_id,
                                    'data_source_id': ds_id,
                                    'pii_types_detected': pii_in_ds
                                }
                            })

                        # Get S3 configuration
                        ds_details = self.bedrock_agent.get_data_source(
                            knowledgeBaseId=kb_id,
                            dataSourceId=ds_id
                        )

                        ds_config = ds_details.get('dataSource', {}).get('dataSourceConfiguration', {})
                        s3_config = ds_config.get('s3Configuration', {})
                        bucket_arn = s3_config.get('bucketArn', '')

                        if bucket_arn:
                            bucket_name = bucket_arn.split(':::')[-1] if ':::' in bucket_arn else None
                            inclusion_prefixes = s3_config.get('inclusionPrefixes', [])

                            # Check bucket name and prefixes for PII patterns
                            pii_in_s3 = []
                            for pii_type, pattern in pii_patterns.items():
                                if bucket_name and re.search(pattern, bucket_name, re.IGNORECASE):
                                    pii_in_s3.append(f'{pii_type} in bucket name')
                                for prefix in inclusion_prefixes:
                                    if re.search(pattern, prefix, re.IGNORECASE):
                                        pii_in_s3.append(f'{pii_type} in S3 prefix')

                            if pii_in_s3:
                                findings.append({
                                    'risk_level': RiskLevel.MEDIUM,
                                    'title': f'S3 bucket configuration contains PII patterns',
                                    'description': (
                                        f'S3 bucket or prefix for data source "{ds_name}" contains '
                                        f'PII-like patterns: {", ".join(set(pii_in_s3))}. This may '
                                        f'indicate sensitive data organization issues.'
                                    ),
                                    'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                    'resource': f's3://{bucket_name}',
                                    'remediation': (
                                        f'Review S3 bucket structure:\n'
                                        f'1. Use generic bucket names without PII\n'
                                        f'2. Implement Amazon Macie for comprehensive PII detection\n'
                                        f'3. Enable S3 Object Lambda for PII redaction before embedding'
                                    ),
                                    'details': {
                                        'knowledge_base_id': kb_id,
                                        'data_source_id': ds_id,
                                        'bucket_name': bucket_name,
                                        'pii_types_detected': list(set(pii_in_s3))
                                    }
                                })

                except Exception as e:
                    print(f"[WARN] Error checking data sources for KB {kb_name}: {str(e)}")

            # Add informational finding about scan limitations and Macie integration
            if knowledge_bases:
                findings.append({
                    'risk_level': RiskLevel.INFO,
                    'title': '⚠️  LIMITATION: PII check is metadata-only, does not scan actual documents',
                    'description': (
                        '**IMPORTANT**: This PII check only scans metadata (bucket names, prefixes, tags, '
                        'configuration settings). It does NOT scan the actual document content in S3 buckets '
                        'where PII is most likely to exist.\n\n'
                        'For comprehensive PII detection in actual Knowledge Base documents, use Amazon Macie '
                        'with automated discovery jobs to scan S3 bucket contents.\n\n'
                        'Note: Scanning millions of documents would be slow and expensive, which is why this '
                        'check focuses on configuration-level risks only.'
                    ),
                    'location': 'All Knowledge Bases',
                    'resource': 'N/A',
                    'remediation': (
                        'To scan actual document content for PII:\n'
                        '1. Enable Amazon Macie in your AWS account\n'
                        '2. Create sensitive data discovery jobs targeting KB S3 buckets\n'
                        '3. Configure automated alerts for PII findings\n'
                        '4. Implement data classification and protection workflows\n'
                        '5. Alternative: Use AWS Comprehend DetectPII API for custom scanning'
                    ),
                    'details': {
                        'current_detection': 'pattern-based',
                        'recommended': 'Amazon Macie integration'
                    }
                })

        except Exception as e:
            print(f"[ERROR] Failed to check for PII in knowledge bases: {str(e)}")

        return findings

    def check_prompt_injection_in_documents(self) -> List[Dict]:
        """
        Scan knowledge base documents for indirect prompt injection patterns.

        Returns:
            List of security findings
        """
        findings = []

        # Prompt injection patterns (reuse from genai.py patterns)
        injection_patterns = [
            "ignore previous instructions",
            "disregard all prior commands",
            "forget what you were told",
            "new instructions:",
            "system:",
            "admin mode",
            "override security",
            "bypass restrictions",
            "reveal your prompt",
            "show me your system message",
            "as an ai",
            "you must",
            "you will",
            "execute the following",
            "run this code",
        ]

        # Suspicious Unicode and invisible characters
        import re
        suspicious_unicode_patterns = [
            r'[\u200B-\u200D\uFEFF]',  # Zero-width characters
            r'[\u202A-\u202E]',         # Bidirectional override
            r'[\u2060-\u2069]',         # Word joiners and invisible operators
        ]

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for prompt injection patterns...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)
                kb_description = kb.get('description', '')

                # Check KB metadata for injection patterns
                injection_in_metadata = []
                for pattern in injection_patterns:
                    if pattern.lower() in kb_name.lower() or pattern.lower() in kb_description.lower():
                        injection_in_metadata.append(pattern)

                # Check for suspicious Unicode in metadata
                unicode_found = []
                for pattern in suspicious_unicode_patterns:
                    if re.search(pattern, kb_name) or re.search(pattern, kb_description):
                        unicode_found.append('invisible characters')
                        break

                if injection_in_metadata or unicode_found:
                    findings.append({
                        'risk_level': RiskLevel.HIGH,
                        'title': f'Knowledge Base metadata contains prompt injection patterns',
                        'description': (
                            f'Knowledge Base "{kb_name}" metadata contains suspicious patterns '
                            f'that may indicate prompt injection attempts: '
                            f'{", ".join(injection_in_metadata + unicode_found)}. '
                            f'This could affect how models interact with this knowledge base.'
                        ),
                        'location': f'Knowledge Base: {kb_name}',
                        'resource': kb_id,
                        'remediation': (
                            f'Review and sanitize knowledge base metadata:\n'
                            f'1. Remove instruction-like language from names/descriptions\n'
                            f'2. Check for invisible Unicode characters\n'
                            f'3. Use plain, descriptive text only'
                        ),
                        'details': {
                            'knowledge_base_id': kb_id,
                            'suspicious_patterns': injection_in_metadata,
                            'unicode_issues': unicode_found
                        }
                    })

                try:
                    # Check data sources
                    data_sources_response = self.bedrock_agent.list_data_sources(
                        knowledgeBaseId=kb_id,
                        maxResults=100
                    )

                    for data_source in data_sources_response.get('dataSourceSummaries', []):
                        ds_id = data_source['dataSourceId']
                        ds_name = data_source.get('name', ds_id)
                        ds_description = data_source.get('description', '')

                        # Check data source metadata
                        injection_in_ds = []
                        for pattern in injection_patterns:
                            if pattern.lower() in ds_name.lower() or pattern.lower() in ds_description.lower():
                                injection_in_ds.append(pattern)

                        # Check for Unicode
                        unicode_in_ds = []
                        for pattern in suspicious_unicode_patterns:
                            if re.search(pattern, ds_name) or re.search(pattern, ds_description):
                                unicode_in_ds.append('invisible characters')
                                break

                        if injection_in_ds or unicode_in_ds:
                            findings.append({
                                'risk_level': RiskLevel.HIGH,
                                'title': f'Data source contains prompt injection patterns',
                                'description': (
                                    f'Data source "{ds_name}" contains suspicious patterns: '
                                    f'{", ".join(injection_in_ds + unicode_in_ds)}. '
                                    f'Documents from this source may contain indirect prompt injections.'
                                ),
                                'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                'resource': ds_id,
                                'remediation': (
                                    f'Scan and sanitize data source content:\n'
                                    f'1. Review documents for instruction-like content\n'
                                    f'2. Remove invisible Unicode characters\n'
                                    f'3. Implement content filtering before embedding\n'
                                    f'4. Use guardrails to block injection attempts'
                                ),
                                'details': {
                                    'knowledge_base_id': kb_id,
                                    'data_source_id': ds_id,
                                    'suspicious_patterns': injection_in_ds,
                                    'unicode_issues': unicode_in_ds
                                }
                            })

                        # Note: Full document scanning would require S3 access and sampling
                        # which is beyond basic security checks. Document in expert mode.

                except Exception as e:
                    print(f"[WARN] Error checking data sources for KB {kb_name}: {str(e)}")

            # Add informational finding about scan limitations
            if knowledge_bases:
                findings.append({
                    'risk_level': RiskLevel.INFO,
                    'title': '⚠️  LIMITATION: Prompt injection check is metadata-only, does not scan actual documents',
                    'description': (
                        '**IMPORTANT**: This prompt injection check only scans metadata (KB names, '
                        'data source prefixes, configuration strings). It does NOT scan the actual '
                        'document content in S3 buckets where indirect prompt injection attacks are '
                        'most likely to be embedded.\n\n'
                        'Indirect prompt injection is a serious threat where attackers poison documents '
                        'that get retrieved into context. For comprehensive protection, implement '
                        'document-level scanning with:\n'
                        '• Lambda preprocessing functions\n'
                        '• Guardrails on retrieval context\n'
                        '• Custom NLP-based scanning\n\n'
                        'Note: Scanning millions of documents would be slow and expensive, which is why '
                        'this check focuses on configuration-level risks only.'
                    ),
                    'location': 'All Knowledge Bases',
                    'resource': 'N/A',
                    'remediation': (
                        'Implement comprehensive prompt injection prevention:\n'
                        '1. Configure AWS Bedrock Guardrails with PROMPT_ATTACK filters\n'
                        '2. Use Lambda functions to pre-process documents before ingestion\n'
                        '3. Implement content validation pipelines\n'
                        '4. Monitor knowledge base queries for injection attempts\n'
                        '5. Enable CloudWatch alarms for suspicious patterns'
                    ),
                    'details': {
                        'current_coverage': 'metadata-only',
                        'recommended': 'document-level scanning with guardrails'
                    }
                })

        except Exception as e:
            print(f"[ERROR] Failed to check for prompt injection in knowledge bases: {str(e)}")

        return findings

    def check_knowledge_base_versioning(self) -> List[Dict]:
        """
        Verify S3 buckets for knowledge bases have versioning enabled.

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for S3 versioning...")

            checked_buckets = set()  # Avoid duplicate checks

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get data sources
                    data_sources_response = self.bedrock_agent.list_data_sources(
                        knowledgeBaseId=kb_id,
                        maxResults=100
                    )

                    for data_source in data_sources_response.get('dataSourceSummaries', []):
                        ds_id = data_source['dataSourceId']
                        ds_name = data_source.get('name', ds_id)

                        # Get data source details
                        ds_details = self.bedrock_agent.get_data_source(
                            knowledgeBaseId=kb_id,
                            dataSourceId=ds_id
                        )

                        ds_config = ds_details.get('dataSource', {}).get('dataSourceConfiguration', {})
                        s3_config = ds_config.get('s3Configuration', {})
                        bucket_arn = s3_config.get('bucketArn', '')

                        if not bucket_arn:
                            continue

                        # Extract bucket name
                        bucket_name = bucket_arn.split(':::')[-1] if ':::' in bucket_arn else None

                        if not bucket_name or bucket_name in checked_buckets:
                            continue

                        checked_buckets.add(bucket_name)

                        # Check versioning status
                        try:
                            versioning_response = self.s3.get_bucket_versioning(Bucket=bucket_name)
                            versioning_status = versioning_response.get('Status', 'Disabled')

                            if versioning_status != 'Enabled':
                                findings.append({
                                    'risk_level': RiskLevel.MEDIUM,
                                    'title': f'Knowledge Base S3 bucket has versioning disabled',
                                    'description': (
                                        f'Knowledge Base "{kb_name}" uses S3 bucket "{bucket_name}" '
                                        f'which does not have versioning enabled. Without versioning, '
                                        f'you cannot recover from accidental deletions or data poisoning '
                                        f'attacks where malicious content replaces legitimate documents.'
                                    ),
                                    'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                    'resource': f's3://{bucket_name}',
                                    'remediation': (
                                        f'Enable versioning on the S3 bucket:\n'
                                        f'aws s3api put-bucket-versioning --bucket {bucket_name} \\\n'
                                        f'  --versioning-configuration Status=Enabled'
                                    ),
                                    'details': {
                                        'knowledge_base_id': kb_id,
                                        'data_source_id': ds_id,
                                        'bucket_name': bucket_name,
                                        'versioning_status': versioning_status
                                    }
                                })

                        except Exception as e:
                            print(f"[WARN] Could not check versioning for bucket {bucket_name}: {str(e)}")

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def check_knowledge_base_access_patterns(self) -> List[Dict]:
        """
        Analyze who/what has access to knowledge bases.

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for access patterns...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get knowledge base details including role
                    kb_details = self.bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
                    kb_config = kb_details.get('knowledgeBase', {})
                    role_arn = kb_config.get('roleArn', '')

                    if role_arn:
                        # Extract role name
                        role_name = role_arn.split('/')[-1] if '/' in role_arn else None

                        if role_name:
                            try:
                                # Get role policies
                                role_response = self.checker.iam.get_role(RoleName=role_name)
                                role = role_response.get('Role', {})

                                # Check attached policies
                                attached_policies_response = self.checker.iam.list_attached_role_policies(
                                    RoleName=role_name
                                )
                                attached_policies = attached_policies_response.get('AttachedPolicies', [])

                                # Flag if using overly permissive managed policies
                                dangerous_policies = [
                                    'AdministratorAccess',
                                    'PowerUserAccess',
                                    'ReadOnlyAccess'  # Even read-only can be risky for knowledge bases
                                ]

                                for policy in attached_policies:
                                    policy_name = policy.get('PolicyName', '')
                                    if policy_name in dangerous_policies:
                                        findings.append({
                                            'risk_level': RiskLevel.HIGH,
                                            'title': f'Knowledge Base role uses overly permissive policy',
                                            'description': (
                                                f'Knowledge Base "{kb_name}" uses IAM role "{role_name}" '
                                                f'which has the "{policy_name}" policy attached. This grants '
                                                f'far more permissions than necessary for knowledge base operations.'
                                            ),
                                            'location': f'Knowledge Base: {kb_name}',
                                            'resource': role_arn,
                                            'remediation': (
                                                f'Replace with least-privilege policy:\n'
                                                f'1. Create custom policy with only required permissions:\n'
                                                f'   - s3:GetObject, s3:ListBucket (for data sources)\n'
                                                f'   - aoss:APIAccessAll (for OpenSearch Serverless)\n'
                                                f'   - bedrock:InvokeModel (for embedding model)\n'
                                                f'2. Detach "{policy_name}" policy\n'
                                                f'3. Attach custom policy to role'
                                            ),
                                            'details': {
                                                'knowledge_base_id': kb_id,
                                                'role_name': role_name,
                                                'problematic_policy': policy_name
                                            }
                                        })

                                # Check inline policies (not just attached managed policies)
                                try:
                                    inline_policies_response = self.checker.iam.list_role_policies(
                                        RoleName=role_name
                                    )
                                    inline_policy_names = inline_policies_response.get('PolicyNames', [])

                                    for inline_policy_name in inline_policy_names:
                                        # Get inline policy document
                                        policy_response = self.checker.iam.get_role_policy(
                                            RoleName=role_name,
                                            PolicyName=inline_policy_name
                                        )

                                        policy_doc = policy_response.get('PolicyDocument', {})

                                        # Check for overly permissive actions
                                        for statement in policy_doc.get('Statement', []):
                                            if statement.get('Effect') == 'Allow':
                                                actions = statement.get('Action', [])
                                                if isinstance(actions, str):
                                                    actions = [actions]

                                                resources = statement.get('Resource', [])
                                                if isinstance(resources, str):
                                                    resources = [resources]

                                                # Check for dangerous wildcard permissions
                                                has_wildcard_action = any(action == '*' for action in actions)
                                                has_wildcard_resource = any(res == '*' for res in resources)

                                                if has_wildcard_action and has_wildcard_resource:
                                                    findings.append({
                                                        'risk_level': RiskLevel.CRITICAL,
                                                        'title': f'Knowledge Base role has inline policy with full wildcard permissions',
                                                        'description': (
                                                            f'Knowledge Base "{kb_name}" uses IAM role "{role_name}" '
                                                            f'which has an inline policy "{inline_policy_name}" with '
                                                            f'Action:"*" and Resource:"*". This grants unrestricted '
                                                            f'access to all AWS services.'
                                                        ),
                                                        'location': f'Knowledge Base: {kb_name}',
                                                        'resource': role_arn,
                                                        'remediation': (
                                                            f'Replace wildcard inline policy with least-privilege policy:\n'
                                                            f'1. Review required permissions for the knowledge base\n'
                                                            f'2. Create restricted policy with specific actions and resources\n'
                                                            f'3. Delete inline policy: aws iam delete-role-policy --role-name {role_name} --policy-name {inline_policy_name}\n'
                                                            f'4. Attach new restricted policy'
                                                        ),
                                                        'details': {
                                                            'knowledge_base_id': kb_id,
                                                            'role_name': role_name,
                                                            'inline_policy_name': inline_policy_name,
                                                            'issue': 'Full wildcard permissions (Action:* Resource:*)'
                                                        }
                                                    })
                                                elif has_wildcard_action:
                                                    findings.append({
                                                        'risk_level': RiskLevel.HIGH,
                                                        'title': f'Knowledge Base role has inline policy with wildcard actions',
                                                        'description': (
                                                            f'Knowledge Base "{kb_name}" uses IAM role "{role_name}" '
                                                            f'which has an inline policy "{inline_policy_name}" with '
                                                            f'Action:"*". This grants all actions on specified resources.'
                                                        ),
                                                        'location': f'Knowledge Base: {kb_name}',
                                                        'resource': role_arn,
                                                        'remediation': (
                                                            f'Restrict inline policy to specific actions:\n'
                                                            f'Replace Action:"*" with specific required actions like:\n'
                                                            f'  s3:GetObject, s3:ListBucket, aoss:APIAccessAll, bedrock:InvokeModel'
                                                        ),
                                                        'details': {
                                                            'knowledge_base_id': kb_id,
                                                            'role_name': role_name,
                                                            'inline_policy_name': inline_policy_name
                                                        }
                                                    })

                                except Exception as e:
                                    print(f"[WARN] Could not check inline policies for role {role_name}: {str(e)}")

                            except Exception as e:
                                print(f"[WARN] Could not check role {role_name}: {str(e)}")

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def check_knowledge_base_chunking_config(self) -> List[Dict]:
        """
        Validate chunking configurations to prevent information leakage.

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for chunking configuration...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get data sources for chunking configuration
                    data_sources_response = self.bedrock_agent.list_data_sources(
                        knowledgeBaseId=kb_id,
                        maxResults=100
                    )

                    for data_source in data_sources_response.get('dataSourceSummaries', []):
                        ds_id = data_source['dataSourceId']
                        ds_name = data_source.get('name', ds_id)

                        # Get data source details
                        ds_details = self.bedrock_agent.get_data_source(
                            knowledgeBaseId=kb_id,
                            dataSourceId=ds_id
                        )

                        ds_config = ds_details.get('dataSource', {}).get('dataSourceConfiguration', {})
                        s3_config = ds_config.get('s3Configuration', {})

                        # Check chunking strategy
                        chunking_config = ds_config.get('chunkingConfiguration', {})
                        chunking_strategy = chunking_config.get('chunkingStrategy', 'NONE')

                        if chunking_strategy == 'NONE':
                            findings.append({
                                'risk_level': RiskLevel.LOW,
                                'title': f'Knowledge Base data source has no chunking strategy',
                                'description': (
                                    f'Data source "{ds_name}" in Knowledge Base "{kb_name}" has no '
                                    f'chunking strategy defined. This may result in entire documents being '
                                    f'embedded, which can leak unintended context and reduce retrieval accuracy.'
                                ),
                                'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                'resource': ds_id,
                                'remediation': (
                                    f'Configure appropriate chunking strategy:\n'
                                    f'1. Use FIXED_SIZE chunking with reasonable chunk size (e.g., 300-512 tokens)\n'
                                    f'2. Set overlap to 10-20% to maintain context\n'
                                    f'3. Consider HIERARCHICAL chunking for complex documents\n'
                                    f'Update via AWS Bedrock console or update-data-source API'
                                ),
                                'details': {
                                    'knowledge_base_id': kb_id,
                                    'data_source_id': ds_id,
                                    'chunking_strategy': 'NONE'
                                }
                            })
                        elif chunking_strategy == 'FIXED_SIZE':
                            # Check fixed size configuration
                            fixed_size_config = chunking_config.get('fixedSizeChunkingConfiguration', {})
                            max_tokens = fixed_size_config.get('maxTokens', 0)
                            overlap_percentage = fixed_size_config.get('overlapPercentage', 0)

                            if max_tokens > 1000:
                                findings.append({
                                    'risk_level': RiskLevel.LOW,
                                    'title': f'Knowledge Base data source has large chunk size',
                                    'description': (
                                        f'Data source "{ds_name}" in Knowledge Base "{kb_name}" uses '
                                        f'chunks of {max_tokens} tokens, which is quite large. Large chunks '
                                        f'may include unintended context and reduce retrieval precision.'
                                    ),
                                    'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                    'resource': ds_id,
                                    'remediation': (
                                        f'Reduce chunk size to 300-512 tokens for better precision:\n'
                                        f'Update chunking configuration via AWS Bedrock console'
                                    ),
                                    'details': {
                                        'knowledge_base_id': kb_id,
                                        'data_source_id': ds_id,
                                        'max_tokens': max_tokens,
                                        'recommended_max': 512
                                    }
                                })

                            if overlap_percentage > 30:
                                findings.append({
                                    'risk_level': RiskLevel.LOW,
                                    'title': f'Knowledge Base data source has high chunk overlap',
                                    'description': (
                                        f'Data source "{ds_name}" in Knowledge Base "{kb_name}" uses '
                                        f'{overlap_percentage}% chunk overlap. High overlap may leak sensitive '
                                        f'context across chunk boundaries and increase storage costs.'
                                    ),
                                    'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                    'resource': ds_id,
                                    'remediation': (
                                        f'Reduce overlap to 10-20% for balance between context and isolation:\n'
                                        f'Update chunking configuration via AWS Bedrock console'
                                    ),
                                    'details': {
                                        'knowledge_base_id': kb_id,
                                        'data_source_id': ds_id,
                                        'overlap_percentage': overlap_percentage,
                                        'recommended_max': 20
                                    }
                                })

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def check_knowledge_base_logging(self) -> List[Dict]:
        """
        Verify knowledge base operations are logged.

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for logging configuration...")

            logs = self.checker.session.client('logs')
            checked_buckets = set()

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Check for CloudWatch log group for this knowledge base
                    # Knowledge bases typically log to /aws/bedrock/knowledgebases/
                    log_group_name = f'/aws/bedrock/knowledgebases/{kb_id}'

                    try:
                        log_groups_response = logs.describe_log_groups(
                            logGroupNamePrefix=log_group_name,
                            limit=1
                        )

                        log_groups = log_groups_response.get('logGroups', [])

                        if not log_groups:
                            findings.append({
                                'risk_level': RiskLevel.MEDIUM,
                                'title': f'Knowledge Base has no CloudWatch logging',
                                'description': (
                                    f'Knowledge Base "{kb_name}" does not have CloudWatch logging '
                                    f'enabled. Without logging, you cannot audit queries, track usage, '
                                    f'or investigate security incidents.'
                                ),
                                'location': f'Knowledge Base: {kb_name}',
                                'resource': kb_id,
                                'remediation': (
                                    f'Enable CloudWatch logging for the knowledge base. '
                                    f'This is typically configured during knowledge base creation or '
                                    f'through the AWS Bedrock console under logging settings.'
                                ),
                                'details': {
                                    'knowledge_base_id': kb_id,
                                    'expected_log_group': log_group_name,
                                    'logging_status': 'DISABLED'
                                }
                            })
                        else:
                            # Check log retention and encryption
                            log_group = log_groups[0]
                            retention_days = log_group.get('retentionInDays')
                            kms_key_id = log_group.get('kmsKeyId')

                            if not retention_days:
                                findings.append({
                                    'risk_level': RiskLevel.LOW,
                                    'title': f'Knowledge Base CloudWatch logs have no retention policy',
                                    'description': (
                                        f'Knowledge Base "{kb_name}" has CloudWatch logging but no '
                                        f'retention policy. Logs are kept indefinitely, which may '
                                        f'increase costs and complicate compliance.'
                                    ),
                                    'location': f'Knowledge Base: {kb_name}',
                                    'resource': log_group_name,
                                    'remediation': (
                                        f'Set a retention policy for the log group:\n'
                                        f'aws logs put-retention-policy \\\n'
                                        f'  --log-group-name {log_group_name} \\\n'
                                        f'  --retention-in-days 90'
                                    ),
                                    'details': {
                                        'knowledge_base_id': kb_id,
                                        'log_group': log_group_name,
                                        'retention_days': 'NEVER_EXPIRE'
                                    }
                                })

                            if not kms_key_id:
                                findings.append({
                                    'risk_level': RiskLevel.MEDIUM,
                                    'title': f'Knowledge Base CloudWatch logs are not encrypted',
                                    'description': (
                                        f'Knowledge Base "{kb_name}" logs to CloudWatch but the logs '
                                        f'are not encrypted with a customer-managed KMS key. Query logs '
                                        f'may contain sensitive information from your documents.'
                                    ),
                                    'location': f'Knowledge Base: {kb_name}',
                                    'resource': log_group_name,
                                    'remediation': (
                                        f'Encrypt the log group with a KMS key:\n'
                                        f'aws logs associate-kms-key \\\n'
                                        f'  --log-group-name {log_group_name} \\\n'
                                        f'  --kms-key-id your-kms-key-id'
                                    ),
                                    'details': {
                                        'knowledge_base_id': kb_id,
                                        'log_group': log_group_name,
                                        'encryption': 'NONE'
                                    }
                                })

                    except Exception as e:
                        print(f"[WARN] Could not check CloudWatch logs for {kb_name}: {str(e)}")

                    # Check S3 access logging for data sources
                    data_sources_response = self.bedrock_agent.list_data_sources(
                        knowledgeBaseId=kb_id,
                        maxResults=100
                    )

                    for data_source in data_sources_response.get('dataSourceSummaries', []):
                        ds_id = data_source['dataSourceId']
                        ds_name = data_source.get('name', ds_id)

                        ds_details = self.bedrock_agent.get_data_source(
                            knowledgeBaseId=kb_id,
                            dataSourceId=ds_id
                        )

                        ds_config = ds_details.get('dataSource', {}).get('dataSourceConfiguration', {})
                        s3_config = ds_config.get('s3Configuration', {})
                        bucket_arn = s3_config.get('bucketArn', '')

                        if not bucket_arn:
                            continue

                        bucket_name = bucket_arn.split(':::')[-1] if ':::' in bucket_arn else None

                        if not bucket_name or bucket_name in checked_buckets:
                            continue

                        checked_buckets.add(bucket_name)

                        # Check S3 access logging
                        try:
                            logging_response = self.s3.get_bucket_logging(Bucket=bucket_name)
                            logging_enabled = logging_response.get('LoggingEnabled')

                            if not logging_enabled:
                                findings.append({
                                    'risk_level': RiskLevel.LOW,
                                    'title': f'Knowledge Base S3 bucket has no access logging',
                                    'description': (
                                        f'Knowledge Base "{kb_name}" uses S3 bucket "{bucket_name}" '
                                        f'which does not have access logging enabled. You cannot audit '
                                        f'who accessed or modified documents in your knowledge base.'
                                    ),
                                    'location': f'Knowledge Base: {kb_name}, Data Source: {ds_name}',
                                    'resource': f's3://{bucket_name}',
                                    'remediation': (
                                        f'Enable S3 access logging:\n'
                                        f'aws s3api put-bucket-logging --bucket {bucket_name} \\\n'
                                        f'  --bucket-logging-status \'{{\n'
                                        f'    "LoggingEnabled": {{\n'
                                        f'      "TargetBucket": "your-logging-bucket",\n'
                                        f'      "TargetPrefix": "access-logs/{bucket_name}/"\n'
                                        f'    }}\n'
                                        f'  }}\''
                                    ),
                                    'details': {
                                        'knowledge_base_id': kb_id,
                                        'data_source_id': ds_id,
                                        'bucket_name': bucket_name,
                                        'access_logging': 'DISABLED'
                                    }
                                })

                        except Exception as e:
                            print(f"[WARN] Could not check S3 logging for bucket {bucket_name}: {str(e)}")

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def check_knowledge_base_tags(self) -> List[Dict]:
        """
        Validate knowledge bases have proper tagging for governance.

        Returns:
            List of security findings
        """
        findings = []

        # Required tags for governance
        required_tags = ['Environment', 'Owner', 'DataClassification']

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for tagging compliance...")

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get knowledge base details including tags
                    kb_details = self.bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
                    kb_config = kb_details.get('knowledgeBase', {})
                    tags = kb_config.get('tags', {})

                    if not tags:
                        findings.append({
                            'risk_level': RiskLevel.LOW,
                            'title': f'Knowledge Base has no tags',
                            'description': (
                                f'Knowledge Base "{kb_name}" has no tags configured. '
                                f'Tags are important for resource governance, cost allocation, '
                                f'and access control policies.'
                            ),
                            'location': f'Knowledge Base: {kb_name}',
                            'resource': kb_id,
                            'remediation': (
                                f'Add required tags to the knowledge base:\n'
                                f'aws bedrock-agent tag-resource \\\n'
                                f'  --resource-arn arn:aws:bedrock:region:account:knowledge-base/{kb_id} \\\n'
                                f'  --tags Environment=Production,Owner=team-name,DataClassification=Confidential'
                            ),
                            'details': {
                                'knowledge_base_id': kb_id,
                                'tags': 'NONE',
                                'required_tags': required_tags
                            }
                        })
                    else:
                        # Check for required tags
                        missing_tags = [tag for tag in required_tags if tag not in tags]

                        if missing_tags:
                            findings.append({
                                'risk_level': RiskLevel.LOW,
                                'title': f'Knowledge Base missing required tags',
                                'description': (
                                    f'Knowledge Base "{kb_name}" is missing required tags: '
                                    f'{", ".join(missing_tags)}. These tags are important for '
                                    f'governance and access control.'
                                ),
                                'location': f'Knowledge Base: {kb_name}',
                                'resource': kb_id,
                                'remediation': (
                                    f'Add missing tags to the knowledge base:\n'
                                    f'aws bedrock-agent tag-resource \\\n'
                                    f'  --resource-arn arn:aws:bedrock:region:account:knowledge-base/{kb_id} \\\n'
                                    f'  --tags {" ".join([f"{tag}=value" for tag in missing_tags])}'
                                ),
                                'details': {
                                    'knowledge_base_id': kb_id,
                                    'existing_tags': list(tags.keys()),
                                    'missing_tags': missing_tags
                                }
                            })

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def check_embedding_model_access(self) -> List[Dict]:
        """
        Verify embedding models used have appropriate access controls.

        Returns:
            List of security findings
        """
        findings = []

        try:
            # List all knowledge bases (with pagination)
            knowledge_bases = self._get_all_knowledge_bases()

            if not knowledge_bases:
                return findings

            print(f"[CHECK] Analyzing {len(knowledge_bases)} knowledge bases for embedding model access...")

            checked_models = set()

            for kb in knowledge_bases:
                kb_id = kb['knowledgeBaseId']
                kb_name = kb.get('name', kb_id)

                try:
                    # Get knowledge base details
                    kb_details = self.bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
                    kb_config = kb_details.get('knowledgeBase', {})

                    # Get embedding model configuration
                    kb_configuration = kb_config.get('knowledgeBaseConfiguration', {})
                    vector_knowledge_base_config = kb_configuration.get('vectorKnowledgeBaseConfiguration', {})
                    embedding_model_arn = vector_knowledge_base_config.get('embeddingModelArn', '')

                    if not embedding_model_arn or embedding_model_arn in checked_models:
                        continue

                    checked_models.add(embedding_model_arn)

                    # Extract model ID from ARN
                    # Format: arn:aws:bedrock:region::foundation-model/model-id
                    model_id = embedding_model_arn.split('/')[-1] if '/' in embedding_model_arn else embedding_model_arn

                    # Check if custom model access is properly controlled
                    # Note: Foundation models have AWS-managed access, custom models need IAM policies
                    if 'custom-model' in embedding_model_arn.lower():
                        # This is a custom model - should have restricted access
                        findings.append({
                            'risk_level': RiskLevel.MEDIUM,
                            'title': f'Knowledge Base uses custom embedding model',
                            'description': (
                                f'Knowledge Base "{kb_name}" uses a custom embedding model "{model_id}". '
                                f'Ensure that access to this model is properly restricted via IAM policies '
                                f'to prevent unauthorized users from using or modifying it.'
                            ),
                            'location': f'Knowledge Base: {kb_name}',
                            'resource': embedding_model_arn,
                            'remediation': (
                                f'Review and restrict IAM policies for the custom model:\n'
                                f'1. Identify IAM roles/users with bedrock:InvokeModel permission\n'
                                f'2. Ensure only authorized principals have access\n'
                                f'3. Use resource-based policies to limit model access:\n'
                                f'   - Restrict to specific IAM roles\n'
                                f'   - Limit to specific VPCs if applicable'
                            ),
                            'details': {
                                'knowledge_base_id': kb_id,
                                'embedding_model_arn': embedding_model_arn,
                                'model_type': 'custom'
                            }
                        })

                except Exception as e:
                    print(f"[WARN] Error checking knowledge base {kb_name}: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Failed to list knowledge bases: {str(e)}")

        return findings

    def run_all_checks(self) -> List[Dict]:
        """
        Execute all 12 Knowledge Base security checks.

        Validates complete RAG security posture including:
        - Data source security (S3 public access, encryption, versioning)
        - Vector store security (encryption, access control)
        - Content security (PII detection, prompt injection patterns)
        - Operational security (IAM, logging, tagging)
        - Model access control (embedding model permissions)

        Returns:
            List of all findings from all 12 checks
        """
        print("[CHECK] Running AWS Bedrock Knowledge Base security checks...")

        # Data source layer: S3 buckets storing documents
        self.findings.extend(self.check_s3_bucket_public_access())  # CRITICAL
        self.findings.extend(self.check_s3_bucket_encryption())      # HIGH
        self.findings.extend(self.check_knowledge_base_versioning()) # MEDIUM

        # Vector store layer: Embeddings storage
        self.findings.extend(self.check_vector_store_encryption())      # HIGH
        self.findings.extend(self.check_vector_store_access_control())  # CRITICAL

        # Content security: Scanning for threats
        self.findings.extend(self.check_pii_in_embeddings())            # HIGH
        self.findings.extend(self.check_prompt_injection_in_documents()) # HIGH

        # Operational security: IAM, logging, organization
        self.findings.extend(self.check_knowledge_base_access_patterns())  # HIGH
        self.findings.extend(self.check_knowledge_base_logging())          # MEDIUM
        self.findings.extend(self.check_knowledge_base_tags())             # LOW

        # Model and configuration
        self.findings.extend(self.check_knowledge_base_chunking_config())  # LOW
        self.findings.extend(self.check_embedding_model_access())          # MEDIUM

        print(f"[INFO] Knowledge Base security checks: {len(self.findings)} findings")
        return self.findings
