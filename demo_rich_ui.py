#!/usr/bin/env python3
"""
Demo script to showcase Wilma's beautiful Rich UI
No AWS credentials required!
"""

from wilma.enums import RiskLevel, SecurityMode
from wilma.reports import ReportGenerator


class MockChecker:
    """Mock checker with sample findings to demo the UI"""
    def __init__(self):
        self.account_id = "123456789012"
        self.region = "us-east-1"
        self.mode = SecurityMode.STANDARD
        self.available_models = ["anthropic.claude-v2", "amazon.titan-text-express-v1"]

        # Sample good practices
        self.good_practices = [
            {"practice": "S3 bucket encryption enabled with customer-managed KMS keys"},
            {"practice": "Vector store using private VPC endpoints"},
            {"practice": "CloudWatch logging configured with proper retention"},
            {"practice": "IAM roles follow least-privilege principles"},
            {"practice": "Resource tagging compliance meets organizational standards"},
        ]

        # Sample findings with different risk levels
        self.findings = [
            {
                "risk_level": RiskLevel.CRITICAL,
                "risk_score": 10,
                "category": "Data Security",
                "resource": "s3://company-rag-documents",
                "issue": "S3 bucket allows public write access",
                "recommendation": "Enable Block Public Access on all S3 buckets containing knowledge base data",
                "learn_more": "Anyone on the internet can upload malicious documents to poison your AI's knowledge",
                "technical_details": "Bucket policy contains Principal: '*' with s3:PutObject permission",
                "fix_command": "aws s3api put-public-access-block --bucket company-rag-documents --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            },
            {
                "risk_level": RiskLevel.CRITICAL,
                "risk_score": 9,
                "category": "Guardrails",
                "resource": "No guardrails configured",
                "issue": "Foundation models deployed without content filtering guardrails",
                "recommendation": "Create and attach guardrails with HIGH strength prompt attack filtering",
                "learn_more": "Your AI is vulnerable to prompt injection, jailbreaking, and generating harmful content",
                "technical_details": "No guardrails found via bedrock:ListGuardrails API",
                "fix_command": "aws bedrock create-guardrail --name 'ProductionGuardrail' --blocked-input-messaging 'Request blocked by security policy' --blocked-outputs-messaging 'Response blocked by security policy' --content-policy-config '{\"filtersConfig\": [{\"type\": \"PROMPT_ATTACK\", \"inputStrength\": \"HIGH\", \"outputStrength\": \"HIGH\"}]}'"
            },
            {
                "risk_level": RiskLevel.HIGH,
                "risk_score": 8,
                "category": "Access Control",
                "resource": "IAM Policy: BedrockFullAccess",
                "issue": "IAM policy grants bedrock:* wildcard permissions",
                "recommendation": "Use least-privilege IAM policies with specific actions only",
                "learn_more": "Overly permissive IAM policies increase the blast radius if credentials are compromised",
                "technical_details": "Policy document contains 'Action': ['bedrock:*'] with no resource restrictions",
                "fix_command": "aws iam create-policy-version --policy-arn arn:aws:iam::123456789012:policy/BedrockFullAccess --policy-document file://least-privilege-policy.json --set-as-default"
            },
            {
                "risk_level": RiskLevel.HIGH,
                "risk_score": 8,
                "category": "Network Security",
                "resource": "VPC Endpoint: Not configured",
                "issue": "No VPC endpoint configured for bedrock-runtime",
                "recommendation": "Create VPC endpoints for private connectivity to AWS Bedrock",
                "learn_more": "Model inference traffic traverses the public internet, increasing latency and exposure",
                "technical_details": "No VPC endpoints found with service name com.amazonaws.us-east-1.bedrock-runtime",
                "fix_command": "aws ec2 create-vpc-endpoint --vpc-id vpc-xxxxx --service-name com.amazonaws.us-east-1.bedrock-runtime --subnet-ids subnet-xxxxx --security-group-ids sg-xxxxx"
            },
            {
                "risk_level": RiskLevel.MEDIUM,
                "risk_score": 6,
                "category": "Logging",
                "resource": "Knowledge Base: customer-support-kb",
                "issue": "CloudWatch logging not enabled for knowledge base queries",
                "recommendation": "Enable CloudWatch logging to monitor knowledge base access patterns",
                "learn_more": "Without logs, you can't detect suspicious queries or investigate security incidents",
                "technical_details": "Knowledge base configuration missing cloudWatchLogsConfig",
                "fix_command": "aws bedrock-agent update-knowledge-base --knowledge-base-id XXXXX --knowledge-base-configuration '{\"type\": \"VECTOR\", \"vectorKnowledgeBaseConfiguration\": {...}}'"
            },
            {
                "risk_level": RiskLevel.MEDIUM,
                "risk_score": 5,
                "category": "Encryption",
                "resource": "OpenSearch Collection: rag-vectors",
                "issue": "Vector store using AWS-managed encryption keys instead of customer-managed KMS",
                "recommendation": "Configure customer-managed KMS keys for OpenSearch encryption",
                "learn_more": "Customer-managed keys provide better auditability and control over data access",
                "technical_details": "OpenSearch Serverless collection uses default AWS encryption",
                "fix_command": "aws opensearchserverless create-security-policy --name rag-encryption --type encryption --policy '{\"Rules\": [{\"ResourceType\": \"collection\", \"Resource\": [\"collection/rag-vectors\"], \"KmsKeyId\": \"arn:aws:kms:us-east-1:123456789012:key/YOUR-KEY\"}]}'"
            },
            {
                "risk_level": RiskLevel.LOW,
                "risk_score": 3,
                "category": "Compliance",
                "resource": "Knowledge Base: customer-support-kb",
                "issue": "Resource missing required tags (Environment, Owner, CostCenter)",
                "recommendation": "Add organizational tags for proper governance and cost allocation",
                "learn_more": "Proper tagging enables cost tracking, access control policies, and compliance reporting",
                "technical_details": "Expected tags: Environment, Owner, CostCenter. Found tags: Name",
                "fix_command": "aws bedrock-agent tag-resource --resource-arn arn:aws:bedrock:us-east-1:123456789012:knowledge-base/XXXXX --tags Environment=production,Owner=security-team,CostCenter=engineering"
            }
        ]


def demo_standard_mode():
    """Demo the standard security report with rich UI"""
    print("\n" + "="*80)
    print("DEMO: Standard Security Scan Mode")
    print("="*80 + "\n")

    checker = MockChecker()
    checker.mode = SecurityMode.STANDARD

    reporter = ReportGenerator(checker)
    reporter.generate_report(output_format='text')


def demo_learning_mode():
    """Demo the learning mode with rich UI"""
    print("\n" + "="*80)
    print("DEMO: Learning Mode")
    print("="*80 + "\n")

    checker = MockChecker()
    checker.mode = SecurityMode.LEARN

    reporter = ReportGenerator(checker)
    reporter.generate_report(output_format='text')


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--learn":
        demo_learning_mode()
    else:
        demo_standard_mode()

        print("\n" + "="*80)
        print("TIP: Run with --learn to see the educational mode!")
        print("     python demo_rich_ui.py --learn")
        print("="*80)
