#!/usr/bin/env python3
"""
Wilma Demo Infrastructure Script

Creates AWS resources with INTENTIONAL security issues for testing Wilma's detection.

What it creates:
- S3 bucket WITHOUT encryption (HIGH risk)
- S3 bucket WITHOUT versioning (MEDIUM risk)
- S3 bucket WITHOUT Block Public Access (CRITICAL risk)
- Overpermissive IAM policy with wildcard actions (HIGH risk)
- OpenSearch Serverless collection for vector storage
- Knowledge Base WITHOUT proper tags (LOW risk)
- Sample documents with potential security issues

Usage:
    python scripts/demo_setup.py --setup      # Create demo resources
    python scripts/demo_setup.py --test       # Run Wilma scan
    python scripts/demo_setup.py --cleanup    # Delete all resources
    python scripts/demo_setup.py --all        # Full cycle (setup → test → cleanup)

Cost: Minimal (< $0.10, usually free tier eligible)
WARNING: Real AWS resources are created - remember to cleanup!
"""

import boto3
import argparse
import sys
import json
import time
import subprocess
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# Demo resource identifiers
DEMO_PREFIX = "wilma-demo"
TIMESTAMP = int(time.time())
BUCKET_NAME = f"{DEMO_PREFIX}-kb-{TIMESTAMP}"
LOG_BUCKET_NAME = f"{DEMO_PREFIX}-logs-{TIMESTAMP}"
KB_NAME = f"{DEMO_PREFIX}-kb-{TIMESTAMP}"
KB_ROLE_NAME = f"{DEMO_PREFIX}-kb-role-{TIMESTAMP}"
OVERPERMISSIVE_POLICY_NAME = f"{DEMO_PREFIX}-policy-{TIMESTAMP}"
DS_NAME = f"{DEMO_PREFIX}-datasource-{TIMESTAMP}"
COLLECTION_NAME = f"{DEMO_PREFIX}-col-{TIMESTAMP}"
INDEX_NAME = f"{DEMO_PREFIX}-idx-{TIMESTAMP}"


class WilmaDemo:
    """
    Demo infrastructure manager for Wilma testing.

    Creates intentionally insecure AWS resources to validate Wilma's detection.
    All resources are tagged with demo prefix for easy identification and cleanup.
    """

    def __init__(self, region='us-east-1', profile=None):
        """
        Initialize AWS clients for demo resource management.

        Args:
            region: AWS region (default: us-east-1, Bedrock home region)
            profile: AWS CLI profile name (optional)
        """
        session_params = {'region_name': region}
        if profile:
            session_params['profile_name'] = profile

        self.session = boto3.Session(**session_params)
        self.s3 = self.session.client('s3')
        self.iam = self.session.client('iam')
        self.bedrock_agent = self.session.client('bedrock-agent')
        self.aoss = self.session.client('opensearchserverless')
        self.region = region
        self.account_id = self.session.client('sts').get_caller_identity()['Account']

        print(f"[INFO] Initialized demo for account {self.account_id} in region {self.region}")

    def setup(self):
        """Create demo resources with intentional security issues."""
        print("\n" + "=" * 70)
        print("WILMA DEMO SETUP - Creating AWS Bedrock Resources")
        print("=" * 70)
        print("\n[WARNING] This will create real AWS resources with security issues.")
        print("          These are for demonstration purposes only.")
        print(f"          Estimated cost: $0.00 - $0.10 (usually free tier)\n")

        try:
            # Step 1: Create S3 bucket (intentionally insecure)
            print("[1/7] Creating S3 bucket with security issues...")
            self._create_insecure_s3_bucket()

            # Step 2: Upload sample documents
            print("[2/7] Uploading sample documents...")
            self._upload_sample_documents()

            # Step 3: Create overpermissive IAM policy
            print("[3/7] Creating overpermissive IAM policy...")
            policy_arn = self._create_overpermissive_iam_policy()

            # Step 4: Create unencrypted log bucket
            print("[4/7] Creating unencrypted log bucket...")
            self._create_unencrypted_log_bucket()

            # Step 5: Create IAM role for Knowledge Base
            print("[5/7] Creating IAM role...")
            role_arn = self._create_kb_role()

            # Step 6: Create OpenSearch Serverless collection
            print("[6/7] Creating vector store...")
            collection_arn, collection_endpoint = self._create_vector_store(role_arn)

            # Step 7: Create Knowledge Base
            print("[7/7] Creating Knowledge Base...")
            kb_id = self._create_knowledge_base(role_arn, collection_arn)

            print("\n" + "=" * 70)
            print("DEMO SETUP COMPLETE!")
            print("=" * 70)
            print(f"\nCreated resources:")
            print(f"  - S3 Data Bucket: {BUCKET_NAME}")
            print(f"  - S3 Log Bucket: {LOG_BUCKET_NAME}")
            print(f"  - IAM Role: {KB_ROLE_NAME}")
            print(f"  - IAM Policy: {OVERPERMISSIVE_POLICY_NAME}")
            print(f"  - OpenSearch Collection: {COLLECTION_NAME}")
            print(f"  - Knowledge Base ID: {kb_id}")
            print(f"\nSecurity issues intentionally introduced (19 checks will be tested):")
            print(f"\n  Knowledge Base Security (12 checks):")
            print(f"    [CRITICAL] S3 bucket has no Block Public Access")
            print(f"    [HIGH] S3 bucket not encrypted")
            print(f"    [HIGH] OpenSearch collection publicly accessible")
            print(f"    [MEDIUM] S3 versioning disabled")
            print(f"    [MEDIUM] No CloudWatch logging for KB")
            print(f"    [LOW] Knowledge Base has no tags")
            print(f"    [LOW] Sub-optimal chunking configuration")
            print(f"\n  IAM Security (2 checks):")
            print(f"    [CRITICAL] IAM policy grants bedrock:* wildcard access")
            print(f"\n  Logging & Monitoring (2 checks):")
            print(f"    [HIGH] Model invocation logging not configured")
            print(f"    [MEDIUM] No CloudWatch logs for real-time monitoring")
            print(f"\n  Network Security (1 check):")
            print(f"    [MEDIUM] No VPC endpoints (traffic over public internet)")
            print(f"\n  GenAI Security (3 checks):")
            print(f"    [HIGH] No guardrails to prevent prompt injection")
            print(f"    [HIGH] Unencrypted log bucket")
            print(f"    [MEDIUM] No cost anomaly detection configured")
            print(f"\nExpected Wilma findings: ~14 security issues across all modules")
            print(f"Next step: Run 'python scripts/demo_setup.py --test' to scan these resources")

            return True

        except Exception as e:
            print(f"\n[ERROR] Setup failed: {str(e)}")
            print("[TIP] Run 'python scripts/demo_setup.py --cleanup' to remove partial resources")
            return False

    def test(self):
        """Run Wilma against the demo resources."""
        print("\n" + "=" * 70)
        print("WILMA DEMO TEST - Running Security Scan")
        print("=" * 70)

        try:
            print("\n[INFO] Running: wilma --region " + self.region)
            print("[INFO] This will scan all Bedrock resources including the demo KB\n")

            # Run Wilma
            result = subprocess.run(
                ['wilma', '--region', self.region],
                capture_output=True,
                text=True
            )

            print(result.stdout)
            if result.stderr:
                print(result.stderr)

            print("\n" + "=" * 70)
            print("SCAN COMPLETE!")
            print("=" * 70)
            print("\nWilma should have detected the intentional security issues.")
            print("Next step: Run 'python scripts/demo_setup.py --cleanup' to remove demo resources")

            return result.returncode == 0

        except FileNotFoundError:
            print("\n[ERROR] 'wilma' command not found.")
            print("[TIP] Install Wilma first: pip install -e .")
            return False
        except Exception as e:
            print(f"\n[ERROR] Test failed: {str(e)}")
            return False

    def cleanup(self):
        """Delete all demo resources."""
        print("\n" + "=" * 70)
        print("WILMA DEMO CLEANUP - Removing AWS Resources")
        print("=" * 70)

        errors = []

        try:
            # Delete Knowledge Base and data sources
            print("[1/7] Deleting Knowledge Bases...")
            try:
                kbs = self.bedrock_agent.list_knowledge_bases()
                for kb in kbs.get('knowledgeBaseSummaries', []):
                    if DEMO_PREFIX in kb.get('name', ''):
                        kb_id = kb['knowledgeBaseId']
                        print(f"  Deleting KB: {kb_id}")

                        # Delete data sources first
                        try:
                            data_sources = self.bedrock_agent.list_data_sources(knowledgeBaseId=kb_id)
                            for ds in data_sources.get('dataSourceSummaries', []):
                                self.bedrock_agent.delete_data_source(
                                    knowledgeBaseId=kb_id,
                                    dataSourceId=ds['dataSourceId']
                                )
                                print(f"    Deleted data source: {ds['dataSourceId']}")
                        except Exception as e:
                            errors.append(f"Error deleting data sources: {str(e)}")

                        # Delete knowledge base
                        self.bedrock_agent.delete_knowledge_base(knowledgeBaseId=kb_id)
                        print(f"  Deleted: {kb['name']}")
            except Exception as e:
                errors.append(f"Error listing/deleting KBs: {str(e)}")

            # Delete OpenSearch Serverless collections
            print("[2/7] Deleting OpenSearch Serverless collections...")
            try:
                collections = self.aoss.list_collections()
                for collection in collections.get('collectionSummaries', []):
                    if DEMO_PREFIX in collection.get('name', ''):
                        collection_id = collection['id']
                        collection_name = collection['name']
                        print(f"  Deleting collection: {collection_name}")
                        self.aoss.delete_collection(id=collection_id)
                        print(f"  Deleted: {collection_name}")
            except Exception as e:
                errors.append(f"Error deleting OpenSearch collections: {str(e)}")

            # Delete OpenSearch Serverless security policies
            print("[3/7] Deleting OpenSearch Serverless policies...")
            try:
                # Delete encryption policies
                enc_policies = self.aoss.list_security_policies(type='encryption')
                for policy in enc_policies.get('securityPolicySummaries', []):
                    if DEMO_PREFIX in policy.get('name', ''):
                        self.aoss.delete_security_policy(
                            name=policy['name'],
                            type='encryption'
                        )
                        print(f"  Deleted encryption policy: {policy['name']}")

                # Delete network policies
                net_policies = self.aoss.list_security_policies(type='network')
                for policy in net_policies.get('securityPolicySummaries', []):
                    if DEMO_PREFIX in policy.get('name', ''):
                        self.aoss.delete_security_policy(
                            name=policy['name'],
                            type='network'
                        )
                        print(f"  Deleted network policy: {policy['name']}")

                # Delete data access policies
                data_policies = self.aoss.list_access_policies(type='data')
                for policy in data_policies.get('accessPolicySummaries', []):
                    if DEMO_PREFIX in policy.get('name', ''):
                        self.aoss.delete_access_policy(
                            name=policy['name'],
                            type='data'
                        )
                        print(f"  Deleted data access policy: {policy['name']}")
            except Exception as e:
                errors.append(f"Error deleting OpenSearch policies: {str(e)}")

            # Delete S3 buckets
            print("[4/7] Deleting S3 buckets...")
            try:
                buckets = self.s3.list_buckets()
                for bucket in buckets['Buckets']:
                    if DEMO_PREFIX in bucket['Name']:
                        bucket_name = bucket['Name']
                        print(f"  Deleting bucket: {bucket_name}")

                        # Delete all objects first
                        try:
                            objects = self.s3.list_objects_v2(Bucket=bucket_name)
                            if 'Contents' in objects:
                                for obj in objects['Contents']:
                                    self.s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
                        except Exception as e:
                            errors.append(f"Error deleting objects: {str(e)}")

                        # Delete bucket
                        self.s3.delete_bucket(Bucket=bucket_name)
                        print(f"  Deleted: {bucket_name}")
            except Exception as e:
                errors.append(f"Error deleting S3 buckets: {str(e)}")

            # Delete IAM roles
            print("[5/7] Deleting IAM roles...")
            try:
                roles = self.iam.list_roles()
                for role in roles['Roles']:
                    if DEMO_PREFIX in role['RoleName']:
                        role_name = role['RoleName']
                        print(f"  Deleting role: {role_name}")

                        # Detach policies
                        try:
                            attached = self.iam.list_attached_role_policies(RoleName=role_name)
                            for policy in attached['AttachedPolicies']:
                                self.iam.detach_role_policy(
                                    RoleName=role_name,
                                    PolicyArn=policy['PolicyArn']
                                )
                        except Exception as e:
                            errors.append(f"Error detaching policies: {str(e)}")

                        # Delete inline policies
                        try:
                            inline = self.iam.list_role_policies(RoleName=role_name)
                            for policy_name in inline['PolicyNames']:
                                self.iam.delete_role_policy(
                                    RoleName=role_name,
                                    PolicyName=policy_name
                                )
                        except Exception as e:
                            errors.append(f"Error deleting inline policies: {str(e)}")

                        # Delete role
                        self.iam.delete_role(RoleName=role_name)
                        print(f"  Deleted: {role_name}")
            except Exception as e:
                errors.append(f"Error deleting IAM roles: {str(e)}")

            # Delete IAM policies
            print("[6/7] Deleting IAM policies...")
            try:
                policies = self.iam.list_policies(Scope='Local')
                for policy in policies['Policies']:
                    if DEMO_PREFIX in policy['PolicyName']:
                        policy_arn = policy['Arn']
                        policy_name = policy['PolicyName']
                        print(f"  Deleting policy: {policy_name}")

                        # Delete all non-default policy versions first
                        try:
                            versions = self.iam.list_policy_versions(PolicyArn=policy_arn)
                            for version in versions['Versions']:
                                if not version['IsDefaultVersion']:
                                    self.iam.delete_policy_version(
                                        PolicyArn=policy_arn,
                                        VersionId=version['VersionId']
                                    )
                        except Exception as e:
                            errors.append(f"Error deleting policy versions: {str(e)}")

                        # Delete policy
                        self.iam.delete_policy(PolicyArn=policy_arn)
                        print(f"  Deleted: {policy_name}")
            except Exception as e:
                errors.append(f"Error deleting IAM policies: {str(e)}")

            print("[7/7] Cleanup verification...")
            time.sleep(2)  # Allow AWS eventual consistency

            print("\n" + "=" * 70)
            if errors:
                print("CLEANUP COMPLETED WITH ERRORS")
                print("=" * 70)
                for error in errors:
                    print(f"  - {error}")
            else:
                print("CLEANUP COMPLETE!")
                print("=" * 70)
                print("\nAll demo resources have been removed.")

            return len(errors) == 0

        except Exception as e:
            print(f"\n[ERROR] Cleanup failed: {str(e)}")
            return False

    def _create_insecure_s3_bucket(self):
        """Create S3 bucket with intentional security issues."""
        try:
            if self.region == 'us-east-1':
                self.s3.create_bucket(Bucket=BUCKET_NAME)
            else:
                self.s3.create_bucket(
                    Bucket=BUCKET_NAME,
                    CreateBucketConfiguration={'LocationConstraint': self.region}
                )

            print(f"  Created bucket: {BUCKET_NAME}")
            print(f"  [ISSUE] No encryption configured")
            print(f"  [ISSUE] No versioning enabled")
            print(f"  [ISSUE] No Block Public Access")

        except Exception as e:
            raise Exception(f"Failed to create S3 bucket: {str(e)}")

    def _upload_sample_documents(self):
        """Upload sample documents to S3."""
        sample_docs = {
            'doc1.txt': 'This is a sample document for Wilma demo. It contains information about AWS Bedrock.',
            'doc2.txt': 'Sample document 2: AWS Bedrock Knowledge Bases enable RAG implementations.',
        }

        for filename, content in sample_docs.items():
            self.s3.put_object(
                Bucket=BUCKET_NAME,
                Key=filename,
                Body=content.encode('utf-8')
            )
            print(f"  Uploaded: {filename}")

    def _create_overpermissive_iam_policy(self):
        """Create IAM policy with overly permissive Bedrock access."""
        try:
            # Create policy with wildcard Bedrock permissions (intentional security issue)
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:*",  # Overly permissive - grants all Bedrock access
                        "Resource": "*"
                    }
                ]
            }

            response = self.iam.create_policy(
                PolicyName=OVERPERMISSIVE_POLICY_NAME,
                PolicyDocument=json.dumps(policy_document),
                Description=f"Wilma demo overpermissive policy - created {datetime.now().isoformat()}"
            )

            policy_arn = response['Policy']['Arn']
            print(f"  Created policy: {OVERPERMISSIVE_POLICY_NAME}")
            print(f"  [ISSUE] Policy grants bedrock:* wildcard permissions")

            return policy_arn

        except Exception as e:
            raise Exception(f"Failed to create IAM policy: {str(e)}")

    def _create_unencrypted_log_bucket(self):
        """Create S3 bucket for model logs without encryption."""
        try:
            if self.region == 'us-east-1':
                self.s3.create_bucket(Bucket=LOG_BUCKET_NAME)
            else:
                self.s3.create_bucket(
                    Bucket=LOG_BUCKET_NAME,
                    CreateBucketConfiguration={'LocationConstraint': self.region}
                )

            print(f"  Created log bucket: {LOG_BUCKET_NAME}")
            print(f"  [ISSUE] No encryption configured for log storage")

        except Exception as e:
            raise Exception(f"Failed to create log bucket: {str(e)}")

    def _create_kb_role(self):
        """Create IAM role for Knowledge Base."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }

        try:
            response = self.iam.create_role(
                RoleName=KB_ROLE_NAME,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"Wilma demo KB role - created {datetime.now().isoformat()}"
            )

            role_arn = response['Role']['Arn']

            # Attach minimal permissions (this could be overly permissive - demo issue)
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [
                            f"arn:aws:s3:::{BUCKET_NAME}",
                            f"arn:aws:s3:::{BUCKET_NAME}/*"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["bedrock:InvokeModel"],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["aoss:APIAccessAll"],
                        "Resource": f"arn:aws:aoss:{self.region}:{self.account_id}:collection/*"
                    }
                ]
            }

            self.iam.put_role_policy(
                RoleName=KB_ROLE_NAME,
                PolicyName=f"{KB_ROLE_NAME}-policy",
                PolicyDocument=json.dumps(policy_document)
            )

            print(f"  Created role: {KB_ROLE_NAME}")
            return role_arn

        except Exception as e:
            raise Exception(f"Failed to create IAM role: {str(e)}")

    def _create_vector_store(self, role_arn):
        """Create OpenSearch Serverless collection for vector storage."""
        try:
            # Step 1: Create encryption policy
            print(f"  Creating encryption policy...")
            encryption_policy = {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{COLLECTION_NAME}"]
                    }
                ],
                "AWSOwnedKey": True
            }

            try:
                self.aoss.create_security_policy(
                    name=f"{DEMO_PREFIX}-encryption",
                    type='encryption',
                    policy=json.dumps(encryption_policy)
                )
            except self.aoss.exceptions.ConflictException:
                print(f"    Encryption policy already exists, continuing...")

            # Step 2: Create network policy (allow public access for demo)
            print(f"  Creating network policy...")
            network_policy = [
                {
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": [f"collection/{COLLECTION_NAME}"]
                        },
                        {
                            "ResourceType": "dashboard",
                            "Resource": [f"collection/{COLLECTION_NAME}"]
                        }
                    ],
                    "AllowFromPublic": True
                }
            ]

            try:
                self.aoss.create_security_policy(
                    name=f"{DEMO_PREFIX}-network",
                    type='network',
                    policy=json.dumps(network_policy)
                )
            except self.aoss.exceptions.ConflictException:
                print(f"    Network policy already exists, continuing...")

            # Step 3: Create data access policy
            print(f"  Creating data access policy...")
            data_policy = [
                {
                    "Rules": [
                        {
                            "Resource": [f"collection/{COLLECTION_NAME}"],
                            "Permission": [
                                "aoss:CreateCollectionItems",
                                "aoss:DeleteCollectionItems",
                                "aoss:UpdateCollectionItems",
                                "aoss:DescribeCollectionItems"
                            ],
                            "ResourceType": "collection"
                        },
                        {
                            "Resource": [f"index/{COLLECTION_NAME}/*"],
                            "Permission": [
                                "aoss:CreateIndex",
                                "aoss:DeleteIndex",
                                "aoss:UpdateIndex",
                                "aoss:DescribeIndex",
                                "aoss:ReadDocument",
                                "aoss:WriteDocument"
                            ],
                            "ResourceType": "index"
                        }
                    ],
                    "Principal": [
                        role_arn,
                        f"arn:aws:iam::{self.account_id}:root"
                    ]
                }
            ]

            try:
                self.aoss.create_access_policy(
                    name=f"{DEMO_PREFIX}-data-access",
                    type='data',
                    policy=json.dumps(data_policy)
                )
            except self.aoss.exceptions.ConflictException:
                print(f"    Data access policy already exists, continuing...")

            # Step 4: Create the collection
            print(f"  Creating OpenSearch Serverless collection...")
            print(f"    This may take 2-3 minutes...")

            collection_response = self.aoss.create_collection(
                name=COLLECTION_NAME,
                type='VECTORSEARCH',
                description='Wilma demo vector store'
            )

            collection_id = collection_response['createCollectionDetail']['id']
            collection_arn = collection_response['createCollectionDetail']['arn']

            # Wait for collection to become active
            print(f"    Waiting for collection to become ACTIVE...")
            max_wait = 300  # 5 minutes
            wait_interval = 10
            elapsed = 0

            while elapsed < max_wait:
                response = self.aoss.batch_get_collection(names=[COLLECTION_NAME])
                if response['collectionDetails']:
                    status = response['collectionDetails'][0]['status']
                    if status == 'ACTIVE':
                        collection_endpoint = response['collectionDetails'][0]['collectionEndpoint']
                        print(f"    Collection is ACTIVE!")
                        break
                    print(f"    Status: {status}, waiting...")
                time.sleep(wait_interval)
                elapsed += wait_interval
            else:
                raise Exception("Collection creation timed out after 5 minutes")

            # Step 5: Create vector index
            print(f"  Creating vector index in OpenSearch...")
            print(f"    Waiting for data access policy to propagate...")
            time.sleep(15)  # Wait for policy propagation

            credentials = self.session.get_credentials()
            awsauth = AWS4Auth(
                credentials.access_key,
                credentials.secret_key,
                self.region,
                'aoss',
                session_token=credentials.token
            )

            host = collection_endpoint.replace('https://', '')
            opensearch_client = OpenSearch(
                hosts=[{'host': host, 'port': 443}],
                http_auth=awsauth,
                use_ssl=True,
                verify_certs=True,
                connection_class=RequestsHttpConnection,
                timeout=300
            )

            # Create index with vector configuration
            index_body = {
                "settings": {
                    "index.knn": True,
                    "number_of_shards": 1,
                    "knn.algo_param.ef_search": 512,
                    "number_of_replicas": 0,
                },
                "mappings": {
                    "properties": {
                        "vector": {
                            "type": "knn_vector",
                            "dimension": 1024,  # For amazon.titan-embed-text-v2:0
                            "method": {
                                "name": "hnsw",
                                "engine": "faiss",
                                "parameters": {"ef_construction": 512, "m": 16},
                            },
                        },
                        "text": {"type": "text"},
                        "metadata": {"type": "text"},
                    }
                },
            }

            opensearch_client.indices.create(index=INDEX_NAME, body=index_body)
            print(f"    Created vector index: {INDEX_NAME}")

            # Wait for index to be fully available
            print(f"    Waiting for index to be available...")
            time.sleep(10)

            # Verify index exists
            if opensearch_client.indices.exists(index=INDEX_NAME):
                print(f"    Index verified: {INDEX_NAME}")
            else:
                raise Exception(f"Index {INDEX_NAME} was not found after creation")

            print(f"  Created OpenSearch Serverless collection: {COLLECTION_NAME}")
            return collection_arn, collection_endpoint

        except Exception as e:
            raise Exception(f"Failed to create vector store: {str(e)}")

    def _create_knowledge_base(self, role_arn, collection_arn):
        """Create Knowledge Base with S3 data source."""
        try:
            # Wait a bit for IAM role propagation
            print(f"  Waiting for IAM role propagation...")
            time.sleep(10)

            # Create Knowledge Base
            print(f"  Creating Knowledge Base...")
            kb_response = self.bedrock_agent.create_knowledge_base(
                name=KB_NAME,
                description=f"Wilma demo KB - created {datetime.now().isoformat()}",
                roleArn=role_arn,
                knowledgeBaseConfiguration={
                    'type': 'VECTOR',
                    'vectorKnowledgeBaseConfiguration': {
                        'embeddingModelArn': f'arn:aws:bedrock:{self.region}::foundation-model/amazon.titan-embed-text-v2:0'
                    }
                },
                storageConfiguration={
                    'type': 'OPENSEARCH_SERVERLESS',
                    'opensearchServerlessConfiguration': {
                        'collectionArn': collection_arn,
                        'vectorIndexName': INDEX_NAME,
                        'fieldMapping': {
                            'vectorField': 'vector',
                            'textField': 'text',
                            'metadataField': 'metadata'
                        }
                    }
                }
            )

            kb_id = kb_response['knowledgeBase']['knowledgeBaseId']
            print(f"    Created Knowledge Base: {kb_id}")

            # Wait for KB to become ACTIVE
            print(f"    Waiting for KB to become ACTIVE...")
            max_wait = 60  # 1 minute
            wait_interval = 5
            elapsed = 0

            while elapsed < max_wait:
                kb_status = self.bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
                status = kb_status['knowledgeBase']['status']
                if status == 'ACTIVE':
                    print(f"    Knowledge Base is ACTIVE!")
                    break
                elif status == 'FAILED':
                    raise Exception(f"Knowledge Base creation failed")
                print(f"    Status: {status}, waiting...")
                time.sleep(wait_interval)
                elapsed += wait_interval
            else:
                print(f"    Warning: KB not ACTIVE yet, but continuing...")

            # Create S3 data source
            print(f"  Creating S3 data source...")
            ds_response = self.bedrock_agent.create_data_source(
                knowledgeBaseId=kb_id,
                name=DS_NAME,
                description='Demo S3 data source with sample documents',
                dataSourceConfiguration={
                    'type': 'S3',
                    's3Configuration': {
                        'bucketArn': f'arn:aws:s3:::{BUCKET_NAME}',
                    }
                },
                vectorIngestionConfiguration={
                    'chunkingConfiguration': {
                        'chunkingStrategy': 'FIXED_SIZE',
                        'fixedSizeChunkingConfiguration': {
                            'maxTokens': 300,
                            'overlapPercentage': 20
                        }
                    }
                }
            )

            data_source_id = ds_response['dataSource']['dataSourceId']
            print(f"    Created data source: {data_source_id}")

            # Start ingestion job
            print(f"  Starting ingestion job...")
            ingestion_response = self.bedrock_agent.start_ingestion_job(
                knowledgeBaseId=kb_id,
                dataSourceId=data_source_id
            )

            ingestion_job_id = ingestion_response['ingestionJob']['ingestionJobId']
            print(f"    Started ingestion job: {ingestion_job_id}")
            print(f"    (Ingestion will complete in background)")

            return kb_id

        except Exception as e:
            raise Exception(f"Failed to create Knowledge Base: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description='Wilma Demo Setup - Create, test, and cleanup demo resources'
    )
    parser.add_argument('--setup', action='store_true', help='Create demo resources')
    parser.add_argument('--test', action='store_true', help='Run Wilma scan')
    parser.add_argument('--cleanup', action='store_true', help='Delete demo resources')
    parser.add_argument('--all', action='store_true', help='Setup, test, and cleanup')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--confirm', action='store_true', help='Skip confirmation prompts')

    args = parser.parse_args()

    if not any([args.setup, args.test, args.cleanup, args.all]):
        parser.print_help()
        sys.exit(1)

    # Confirmation for resource creation
    if (args.setup or args.all) and not args.confirm:
        print("\n[WARNING] This will create real AWS resources that may incur costs.")
        response = input("Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            sys.exit(0)

    demo = WilmaDemo(region=args.region, profile=args.profile)

    success = True

    if args.all:
        success = demo.setup() and success
        if success:
            time.sleep(5)  # Wait for resources to be fully created
            success = demo.test() and success
            time.sleep(2)
            success = demo.cleanup() and success
    else:
        if args.setup:
            success = demo.setup() and success
        if args.test:
            success = demo.test() and success
        if args.cleanup:
            success = demo.cleanup() and success

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
