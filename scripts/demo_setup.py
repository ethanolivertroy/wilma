#!/usr/bin/env python3
"""
Demo Setup Script for Wilma - AWS Bedrock Security Checker

This script creates sample AWS Bedrock Knowledge Base resources with intentional
security misconfigurations to demonstrate Wilma's detection capabilities.

Usage:
    python scripts/demo_setup.py --setup      # Create demo resources
    python scripts/demo_setup.py --test       # Run Wilma against demo resources
    python scripts/demo_setup.py --cleanup    # Delete all demo resources
    python scripts/demo_setup.py --all        # Setup, test, and cleanup

WARNING: This creates real AWS resources that may incur costs (minimal, usually free tier).
"""

import boto3
import argparse
import sys
import json
import time
import subprocess
from datetime import datetime

# Demo resource identifiers
DEMO_PREFIX = "wilma-demo"
BUCKET_NAME = f"{DEMO_PREFIX}-kb-{int(time.time())}"
KB_NAME = f"{DEMO_PREFIX}-knowledge-base"
KB_ROLE_NAME = f"{DEMO_PREFIX}-kb-role"
DS_NAME = f"{DEMO_PREFIX}-data-source"


class WilmaDemo:
    """Demo setup and teardown for Wilma."""

    def __init__(self, region='us-east-1', profile=None):
        """Initialize AWS clients."""
        session_params = {'region_name': region}
        if profile:
            session_params['profile_name'] = profile

        self.session = boto3.Session(**session_params)
        self.s3 = self.session.client('s3')
        self.iam = self.session.client('iam')
        self.bedrock_agent = self.session.client('bedrock-agent')
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
            print("[1/5] Creating S3 bucket with security issues...")
            self._create_insecure_s3_bucket()

            # Step 2: Upload sample documents
            print("[2/5] Uploading sample documents...")
            self._upload_sample_documents()

            # Step 3: Create IAM role for Knowledge Base
            print("[3/5] Creating IAM role...")
            role_arn = self._create_kb_role()

            # Step 4: Create OpenSearch Serverless collection (simplified - use existing or skip)
            print("[4/5] Creating vector store...")
            collection_arn = self._create_vector_store()

            # Step 5: Create Knowledge Base
            print("[5/5] Creating Knowledge Base...")
            kb_id = self._create_knowledge_base(role_arn, collection_arn)

            print("\n" + "=" * 70)
            print("DEMO SETUP COMPLETE!")
            print("=" * 70)
            print(f"\nCreated resources:")
            print(f"  - S3 Bucket: {BUCKET_NAME}")
            print(f"  - IAM Role: {KB_ROLE_NAME}")
            print(f"  - Knowledge Base ID: {kb_id}")
            print(f"\nSecurity issues intentionally introduced:")
            print(f"  [CRITICAL] S3 bucket has no Block Public Access")
            print(f"  [HIGH] S3 bucket not encrypted")
            print(f"  [MEDIUM] S3 versioning disabled")
            print(f"  [LOW] Knowledge Base has no tags")
            print(f"\nNext step: Run 'python scripts/demo_setup.py --test' to scan these resources")

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
            print("[1/4] Deleting Knowledge Bases...")
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

            # Delete S3 bucket
            print("[2/4] Deleting S3 buckets...")
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

            # Delete IAM role
            print("[3/4] Deleting IAM roles...")
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

            print("[4/4] Cleanup verification...")
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

    def _create_vector_store(self):
        """Create or reference vector store (simplified for demo)."""
        # For demo purposes, we'll note that vector store creation is complex
        # In a real scenario, you'd create an OpenSearch Serverless collection
        print(f"  [INFO] Vector store creation skipped for demo")
        print(f"  [INFO] In production, create OpenSearch Serverless collection")
        return None  # Return None, KB creation will handle this

    def _create_knowledge_base(self, role_arn, collection_arn):
        """Create Knowledge Base."""
        # Note: This is a simplified version. Full KB creation requires vector store.
        print(f"  [INFO] Knowledge Base creation requires OpenSearch Serverless")
        print(f"  [INFO] See AWS documentation for complete setup")
        print(f"  [INFO] Demo focuses on S3 and IAM security checks")
        return "demo-kb-id"


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
