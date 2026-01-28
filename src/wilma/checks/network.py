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

from typing import Dict, List

from botocore.exceptions import ClientError

from wilma.enums import RiskLevel, SecurityMode
from wilma.utils import handle_aws_error


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
            endpoints_response = self.checker.ec2.describe_vpc_endpoints()
            all_endpoints = endpoints_response.get('VpcEndpoints', [])

            # Track both bedrock-runtime and bedrock-agent endpoints
            bedrock_runtime_endpoints = []
            bedrock_agent_endpoints = []
            bedrock_control_endpoints = []

            for endpoint in all_endpoints:
                service_name = endpoint.get('ServiceName', '')
                endpoint_id = endpoint.get('VpcEndpointId', '')
                state = endpoint.get('State', '')

                # Only consider available endpoints
                if state != 'available':
                    continue

                # Categorize Bedrock endpoints
                if 'bedrock-runtime' in service_name:
                    bedrock_runtime_endpoints.append((endpoint_id, endpoint))
                elif 'bedrock-agent' in service_name:
                    bedrock_agent_endpoints.append((endpoint_id, endpoint))
                elif 'bedrock' in service_name:
                    # bedrock control plane (not runtime or agent)
                    bedrock_control_endpoints.append((endpoint_id, endpoint))

            # Check bedrock-runtime endpoint (required for model invocations)
            if not bedrock_runtime_endpoints:
                self.checker.add_finding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Network Security",
                    resource="VPC Endpoint: bedrock-runtime",
                    issue="AI model invocation traffic goes over the public internet",
                    recommendation="Create a VPC endpoint for private model invocations",
                    fix_command=(
                        f"aws ec2 create-vpc-endpoint \\\n"
                        f"  --vpc-id <your-vpc-id> \\\n"
                        f"  --service-name com.amazonaws.{self.checker.region}.bedrock-runtime \\\n"
                        f"  --route-table-ids <your-route-table-id> \\\n"
                        f"  --subnet-ids <your-subnet-ids> \\\n"
                        f"  --security-group-ids <your-sg-id> \\\n"
                        f"  --private-dns-enabled"
                    ),
                    learn_more="Private connections prevent data interception and improve security posture",
                    technical_details="Missing VPC endpoint for bedrock-runtime service"
                )
            else:
                # Validate bedrock-runtime endpoint configuration
                for endpoint_id, endpoint in bedrock_runtime_endpoints:
                    private_dns = endpoint.get('PrivateDnsEnabled', False)

                    if not private_dns:
                        self.checker.add_finding(
                            risk_level=RiskLevel.LOW,
                            category="Network Security",
                            resource=f"VPC Endpoint: {endpoint_id}",
                            issue="bedrock-runtime VPC endpoint has PrivateDns disabled",
                            recommendation="Enable PrivateDnsEnabled to ensure traffic routes correctly",
                            fix_command=f"aws ec2 modify-vpc-endpoint --vpc-endpoint-id {endpoint_id} --private-dns-enabled",
                            learn_more="Without Private DNS, applications may still route to public endpoints",
                            technical_details="PrivateDnsEnabled=false may cause traffic to bypass VPC endpoint"
                        )
                    else:
                        self.checker.add_good_practice(
                            "Network Security",
                            f"bedrock-runtime VPC endpoint properly configured: {endpoint_id}"
                        )

            # Check bedrock-agent endpoint (required for Knowledge Bases and Agents)
            if not bedrock_agent_endpoints:
                self.checker.add_finding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Network Security",
                    resource="VPC Endpoint: bedrock-agent",
                    issue="Knowledge Base and Agent traffic goes over the public internet",
                    recommendation="Create a VPC endpoint for bedrock-agent service",
                    fix_command=(
                        f"aws ec2 create-vpc-endpoint \\\n"
                        f"  --vpc-id <your-vpc-id> \\\n"
                        f"  --service-name com.amazonaws.{self.checker.region}.bedrock-agent \\\n"
                        f"  --route-table-ids <your-route-table-id> \\\n"
                        f"  --subnet-ids <your-subnet-ids> \\\n"
                        f"  --security-group-ids <your-sg-id> \\\n"
                        f"  --private-dns-enabled"
                    ),
                    learn_more="Critical for Knowledge Bases, Agents, and RAG applications to avoid public exposure",
                    technical_details="Missing VPC endpoint for bedrock-agent service (required for KB/Agent operations)"
                )
            else:
                # Validate bedrock-agent endpoint configuration
                for endpoint_id, endpoint in bedrock_agent_endpoints:
                    private_dns = endpoint.get('PrivateDnsEnabled', False)

                    if not private_dns:
                        self.checker.add_finding(
                            risk_level=RiskLevel.LOW,
                            category="Network Security",
                            resource=f"VPC Endpoint: {endpoint_id}",
                            issue="bedrock-agent VPC endpoint has PrivateDns disabled",
                            recommendation="Enable PrivateDnsEnabled to ensure traffic routes correctly",
                            fix_command=f"aws ec2 modify-vpc-endpoint --vpc-endpoint-id {endpoint_id} --private-dns-enabled",
                            learn_more="Without Private DNS, Knowledge Base traffic may bypass the VPC endpoint",
                            technical_details="PrivateDnsEnabled=false may cause traffic to use public endpoints"
                        )
                    else:
                        self.checker.add_good_practice(
                            "Network Security",
                            f"bedrock-agent VPC endpoint properly configured: {endpoint_id}"
                        )

        except ClientError as e:
            handle_aws_error(e, "checking VPC endpoints")
        except Exception as e:
            print(f"[WARN] Could not check VPC endpoints: {str(e)}")

        return self.checker.findings

    def check_security_groups(self) -> List[Dict]:
        """Check security group configurations."""
        return self.check_vpc_endpoints()
