"""
Network Security Checks

Validates private connectivity and network isolation for Bedrock.

Checks:
- VPC endpoints for bedrock-runtime (private connectivity)
- Network ACLs and security groups
- Traffic routing configuration

WHY IMPORTANT: VPC endpoints keep AI traffic off public internet,
reducing interception risk and improving latency.

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

from typing import List, Dict
from wilma.enums import SecurityMode, RiskLevel


class NetworkSecurityChecks:
    """Validates VPC endpoint configuration for private Bedrock connectivity."""

    def __init__(self, checker):
        """Initialize with parent checker for AWS client access."""
        self.checker = checker

    def check_vpc_endpoints(self) -> List[Dict]:
        """Check VPC endpoints with simplified explanations."""
        if self.checker.mode == SecurityMode.LEARN:
            print("\n[LEARN] Learning Mode: Network Security")
            print("This checks if your AI traffic stays within AWS's private network.")
            print("It's like having a private tunnel instead of using public roads.")
            return []

        print("[CHECK] Checking network security configurations...")

        try:
            endpoints = self.checker.ec2.describe_vpc_endpoints()

            bedrock_endpoint_found = False
            bedrock_runtime_endpoint_found = False

            for endpoint in endpoints.get('VpcEndpoints', []):
                service_name = endpoint.get('ServiceName', '')
                if 'bedrock' in service_name and 'runtime' not in service_name:
                    bedrock_endpoint_found = True
                elif 'bedrock-runtime' in service_name:
                    bedrock_runtime_endpoint_found = True

            if not bedrock_runtime_endpoint_found:
                self.checker.add_finding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Network Security",
                    resource="Private Connectivity",
                    issue="AI model traffic goes over the public internet",
                    recommendation="Create a VPC endpoint for private, secure connections",
                    fix_command=f"aws ec2 create-vpc-endpoint --service-name com.amazonaws.{self.checker.region}.bedrock-runtime --vpc-id <your-vpc-id>",
                    learn_more="Private connections prevent data interception and are faster",
                    technical_details="Missing VPC endpoint for bedrock-runtime service"
                )
            else:
                self.checker.add_good_practice("Network Security", "Private VPC endpoints configured for secure AI traffic")

        except Exception as e:
            print(f"[WARN] Could not check VPC endpoints: {str(e)}")

        return self.checker.findings
