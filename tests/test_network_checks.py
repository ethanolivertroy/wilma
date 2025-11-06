"""
Tests for Network security checks

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
"""

import pytest
from unittest.mock import Mock
from wilma.checks.network import NetworkSecurityChecks
from wilma.enums import RiskLevel


class TestVPCEndpoints:
    """Test VPC endpoint configuration checks."""

    def test_no_vpc_endpoints(self, mock_checker):
        """Test detection when no VPC endpoints are configured."""
        # Setup mock responses
        mock_checker.ec2.describe_vpc_endpoints.return_value = {
            'VpcEndpoints': []
        }

        # Run check
        network_checks = NetworkSecurityChecks(mock_checker)
        findings = network_checks.check_vpc_endpoints()

        # Verify MEDIUM finding for missing endpoints
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) >= 2  # One for bedrock-runtime, one for bedrock-agent

    def test_bedrock_runtime_endpoint_exists(self, mock_checker):
        """Test that bedrock-runtime endpoint passes validation."""
        # Setup mock responses
        mock_checker.ec2.describe_vpc_endpoints.return_value = {
            'VpcEndpoints': [
                {
                    'VpcEndpointId': 'vpce-123',
                    'ServiceName': 'com.amazonaws.us-east-1.bedrock-runtime',
                    'State': 'available',
                    'PrivateDnsEnabled': True
                },
                {
                    'VpcEndpointId': 'vpce-456',
                    'ServiceName': 'com.amazonaws.us-east-1.bedrock-agent',
                    'State': 'available',
                    'PrivateDnsEnabled': True
                }
            ]
        }

        # Run check
        network_checks = NetworkSecurityChecks(mock_checker)
        findings = network_checks.check_vpc_endpoints()

        # Verify no MEDIUM findings (both endpoints configured)
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'missing' in f.get('title', '').lower()]
        assert len(medium_findings) == 0

    def test_bedrock_agent_endpoint_missing(self, mock_checker):
        """Test detection when bedrock-agent endpoint is missing."""
        # Setup mock responses (only bedrock-runtime, no bedrock-agent)
        mock_checker.ec2.describe_vpc_endpoints.return_value = {
            'VpcEndpoints': [
                {
                    'VpcEndpointId': 'vpce-123',
                    'ServiceName': 'com.amazonaws.us-east-1.bedrock-runtime',
                    'State': 'available',
                    'PrivateDnsEnabled': True
                }
            ]
        }

        # Run check
        network_checks = NetworkSecurityChecks(mock_checker)
        findings = network_checks.check_vpc_endpoints()

        # Verify MEDIUM finding for missing bedrock-agent endpoint
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        bedrock_agent_findings = [f for f in medium_findings if 'bedrock-agent' in f.get('issue', '').lower() or 'Knowledge Base' in f.get('issue', '')]
        assert len(bedrock_agent_findings) > 0

    def test_private_dns_disabled(self, mock_checker):
        """Test detection when PrivateDnsEnabled is False."""
        # Setup mock responses
        mock_checker.ec2.describe_vpc_endpoints.return_value = {
            'VpcEndpoints': [
                {
                    'VpcEndpointId': 'vpce-123',
                    'ServiceName': 'com.amazonaws.us-east-1.bedrock-runtime',
                    'State': 'available',
                    'PrivateDnsEnabled': False  # Disabled
                }
            ]
        }

        # Run check
        network_checks = NetworkSecurityChecks(mock_checker)
        findings = network_checks.check_vpc_endpoints()

        # Verify LOW finding for disabled private DNS
        low_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.LOW]
        assert len(low_findings) > 0


class TestPublicAccess:
    """Test public access configuration checks."""

    def test_detect_public_s3_bucket(self, mock_checker):
        """Test detection of publicly accessible S3 buckets."""
        # This would be tested if we had S3 public access checks
        # Placeholder for future implementation
        pass

    def test_detect_public_endpoints(self, mock_checker):
        """Test detection of public-facing endpoints."""
        # This would be tested if we had public endpoint checks
        # Placeholder for future implementation
        pass


class TestSecurityGroups:
    """Test security group configuration checks."""

    def test_overly_permissive_security_groups(self, mock_checker):
        """Test detection of security groups with 0.0.0.0/0 access."""
        # Setup mock responses
        mock_checker.ec2.describe_vpc_endpoints.return_value = {
            'VpcEndpoints': [
                {
                    'VpcEndpointId': 'vpce-123',
                    'ServiceName': 'com.amazonaws.us-east-1.bedrock-runtime',
                    'State': 'available',
                    'PrivateDnsEnabled': True,
                    'Groups': [
                        {
                            'GroupId': 'sg-123',
                            'GroupName': 'bedrock-sg'
                        }
                    ]
                }
            ]
        }
        mock_checker.ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-123',
                    'GroupName': 'bedrock-sg',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 443,
                            'ToPort': 443,
                            'IpRanges': [
                                {'CidrIp': '0.0.0.0/0'}  # Overly permissive
                            ]
                        }
                    ]
                }
            ]
        }

        # Run check
        network_checks = NetworkSecurityChecks(mock_checker)
        findings = network_checks.check_security_groups()

        # Verify MEDIUM finding for overly permissive rules
        medium_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.MEDIUM]
        assert len(medium_findings) > 0

    def test_restrictive_security_groups(self, mock_checker):
        """Test that restrictive security groups pass validation."""
        # Setup mock responses
        mock_checker.ec2.describe_vpc_endpoints.return_value = {
            'VpcEndpoints': [
                {
                    'VpcEndpointId': 'vpce-123',
                    'ServiceName': 'com.amazonaws.us-east-1.bedrock-runtime',
                    'State': 'available',
                    'PrivateDnsEnabled': True,
                    'Groups': [
                        {
                            'GroupId': 'sg-123',
                            'GroupName': 'bedrock-sg'
                        }
                    ]
                }
            ]
        }
        mock_checker.ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-123',
                    'GroupName': 'bedrock-sg',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 443,
                            'ToPort': 443,
                            'IpRanges': [
                                {'CidrIp': '10.0.0.0/16'}  # Restrictive to VPC
                            ]
                        }
                    ]
                }
            ]
        }

        # Run check
        network_checks = NetworkSecurityChecks(mock_checker)
        findings = network_checks.check_security_groups()

        # Verify no MEDIUM findings (restrictive rules are good)
        medium_findings = [f for f in mock_checker.findings
                          if f.get('risk_level') == RiskLevel.MEDIUM
                          and 'overly permissive' in f.get('title', '').lower()]
        assert len(medium_findings) == 0
