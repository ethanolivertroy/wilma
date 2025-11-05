"""
Network security checks

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from typing import List, Dict
from wilma.enums import SecurityMode, RiskLevel


class NetworkSecurityChecks:
    """Network security checks for VPC endpoints."""

    def __init__(self, checker):
        """Initialize with parent checker instance."""
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
