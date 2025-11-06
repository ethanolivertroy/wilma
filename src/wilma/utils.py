"""
Shared utility functions for Wilma security checks

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import re
from typing import Any, Callable, Dict, Iterator, List, Optional

from botocore.exceptions import ClientError

# ============================================================================
# SECURITY PATTERN CONSTANTS
# ============================================================================

# Common PII patterns for data privacy checks
PII_PATTERNS = {
    'SSN': r'\b\d{3}-?\d{2}-?\d{4}\b',  # Supports both hyphenated and non-hyphenated
    'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Phone': r'\b(\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b',  # Various formats
    'Credit Card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    'IP Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'AWS Access Key': r'\bAKIA[0-9A-Z]{16}\b',
}

# Common prompt injection patterns
PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "disregard all prior commands",
    "forget what you were told",
    "new instructions:",
    "system prompt",
    "reveal your instructions",
    "what are your rules",
    "bypass security",
    "jailbreak",
    "DAN mode",
    "developer mode",
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

# Suspicious Unicode patterns (for prompt injection detection)
SUSPICIOUS_UNICODE_PATTERNS = [
    r'[\u200B-\u200D\uFEFF]',  # Zero-width characters
    r'[\u202A-\u202E]',         # Bidirectional override
    r'[\u2060-\u2069]',         # Word joiners and invisible operators
]


# ============================================================================
# ARN PARSING UTILITIES
# ============================================================================

def parse_arn(arn: str) -> Optional[Dict[str, str]]:
    """
    Parse an AWS ARN into its components.

    Args:
        arn: AWS ARN string (e.g., "arn:aws:s3:::bucket-name")

    Returns:
        Dictionary with ARN components or None if invalid:
        {
            'partition': 'aws',
            'service': 's3',
            'region': '',
            'account': '',
            'resource_type': '',
            'resource': 'bucket-name'
        }

    Examples:
        >>> parse_arn("arn:aws:s3:::my-bucket")
        {'partition': 'aws', 'service': 's3', ...}

        >>> parse_arn("arn:aws:iam::123456789012:role/MyRole")
        {'partition': 'aws', 'service': 'iam', 'account': '123456789012', ...}
    """
    if not arn or not isinstance(arn, str):
        return None

    # ARN format: arn:partition:service:region:account-id:resource-type/resource-id
    # or: arn:partition:service:region:account-id:resource-type:resource-id
    # or: arn:partition:service:::resource (for S3)

    parts = arn.split(':', 5)
    if len(parts) < 6 or parts[0] != 'arn':
        return None

    result = {
        'arn': arn,
        'partition': parts[1],
        'service': parts[2],
        'region': parts[3],
        'account': parts[4],
        'resource_type': '',
        'resource': parts[5] if len(parts) > 5 else ''
    }

    # Parse resource part (can be resource-type/resource-id or resource-type:resource-id)
    resource_part = parts[5] if len(parts) > 5 else ''

    # Special handling for S3 ARNs - bucket name comes before first '/'
    if result['service'] == 's3' and '/' in resource_part:
        # For S3, everything before first '/' is the bucket name
        result['resource'] = resource_part.split('/')[0]
        result['resource_type'] = 'bucket'
    elif '/' in resource_part:
        resource_parts = resource_part.split('/', 1)
        result['resource_type'] = resource_parts[0]
        result['resource'] = resource_parts[1] if len(resource_parts) > 1 else ''
    elif ':' in resource_part:
        resource_parts = resource_part.split(':', 1)
        result['resource_type'] = resource_parts[0]
        result['resource'] = resource_parts[1] if len(resource_parts) > 1 else ''
    else:
        result['resource'] = resource_part

    return result


def extract_resource_from_arn(arn: str, default: Optional[str] = None) -> Optional[str]:
    """
    Extract the resource identifier from an ARN.

    Args:
        arn: AWS ARN string
        default: Default value to return if parsing fails

    Returns:
        Resource identifier or default value

    Examples:
        >>> extract_resource_from_arn("arn:aws:s3:::my-bucket")
        'my-bucket'

        >>> extract_resource_from_arn("arn:aws:iam::123456789012:role/MyRole")
        'MyRole'
    """
    parsed = parse_arn(arn)
    if parsed:
        return parsed['resource'] or default
    return default


# ============================================================================
# PAGINATION UTILITIES
# ============================================================================

def paginate_aws_results(
    client_method: Callable,
    result_key: str,
    token_key: str = 'NextToken',  # noqa: S107 - AWS pagination token, not a password
    token_param: str = 'NextToken',  # noqa: S107 - AWS pagination parameter, not a password
    **kwargs
) -> Iterator[Dict[str, Any]]:
    """
    Generic pagination helper for AWS API calls.

    Args:
        client_method: Boto3 client method to call (e.g., bedrock.list_knowledge_bases)
        result_key: Key in response containing the results list (e.g., 'knowledgeBaseSummaries')
        token_key: Key in response containing the next token (default: 'NextToken')
        token_param: Parameter name for pagination token (default: 'NextToken')
        **kwargs: Additional arguments to pass to the client method

    Yields:
        Individual items from the paginated results

    Example:
        >>> for kb in paginate_aws_results(
        ...     bedrock_agent.list_knowledge_bases,
        ...     'knowledgeBaseSummaries',
        ...     maxResults=100
        ... ):
        ...     print(kb['knowledgeBaseId'])
    """
    next_token = None

    while True:
        try:
            # Add pagination token if we have one
            if next_token:
                kwargs[token_param] = next_token

            # Call the API method
            response = client_method(**kwargs)

            # Yield each item from the results
            yield from response.get(result_key, [])

            # Check if there are more results
            next_token = response.get(token_key)
            if not next_token:
                break

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                print(f"[WARN] Permission denied during pagination: {str(e)}")
                break
            else:
                raise


def paginate_iam_results(
    client_method: Callable,
    result_key: str,
    **kwargs
) -> Iterator[Dict[str, Any]]:
    """
    Specialized pagination for IAM APIs that use 'Marker' instead of 'NextToken'.

    Args:
        client_method: IAM client method to call
        result_key: Key in response containing the results list
        **kwargs: Additional arguments to pass to the client method

    Yields:
        Individual items from the paginated results

    Example:
        >>> for policy in paginate_iam_results(
        ...     iam.list_policies,
        ...     'Policies',
        ...     Scope='Local',
        ...     MaxItems=100
        ... ):
        ...     print(policy['PolicyName'])
    """
    return paginate_aws_results(
        client_method,
        result_key,
        token_key='Marker',
        token_param='Marker',
        **kwargs
    )


# ============================================================================
# S3 SECURITY UTILITIES
# ============================================================================

def check_s3_bucket_encryption(s3_client, bucket_name: str) -> Dict[str, Any]:
    """
    Check S3 bucket encryption configuration.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket

    Returns:
        Dictionary with encryption details:
        {
            'encrypted': bool,
            'algorithm': 'AES256' | 'aws:kms' | None,
            'kms_key_id': str | None,
            'uses_customer_key': bool
        }

    Example:
        >>> result = check_s3_bucket_encryption(s3, 'my-bucket')
        >>> if not result['encrypted']:
        ...     print("Bucket is not encrypted!")
    """
    result = {
        'encrypted': False,
        'algorithm': None,
        'kms_key_id': None,
        'uses_customer_key': False
    }

    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])

        if rules:
            result['encrypted'] = True
            sse_config = rules[0].get('ApplyServerSideEncryptionByDefault', {})
            result['algorithm'] = sse_config.get('SSEAlgorithm')
            result['kms_key_id'] = sse_config.get('KMSMasterKeyID')

            # Check if using customer-managed KMS key
            if result['algorithm'] == 'aws:kms' and result['kms_key_id']:
                result['uses_customer_key'] = True

    except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        # No encryption configured
        pass
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchBucket':
            raise

    return result


def check_s3_bucket_public_access(s3_client, bucket_name: str) -> Dict[str, Any]:
    """
    Check S3 bucket Block Public Access settings.

    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket

    Returns:
        Dictionary with public access details:
        {
            'fully_blocked': bool,
            'block_public_acls': bool,
            'ignore_public_acls': bool,
            'block_public_policy': bool,
            'restrict_public_buckets': bool
        }
    """
    result = {
        'fully_blocked': False,
        'block_public_acls': False,
        'ignore_public_acls': False,
        'block_public_policy': False,
        'restrict_public_buckets': False,
        'config_exists': False
    }

    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get('PublicAccessBlockConfiguration', {})

        result['config_exists'] = True
        result['block_public_acls'] = config.get('BlockPublicAcls', False)
        result['ignore_public_acls'] = config.get('IgnorePublicAcls', False)
        result['block_public_policy'] = config.get('BlockPublicPolicy', False)
        result['restrict_public_buckets'] = config.get('RestrictPublicBuckets', False)

        # All settings must be True for full protection
        result['fully_blocked'] = all([
            result['block_public_acls'],
            result['ignore_public_acls'],
            result['block_public_policy'],
            result['restrict_public_buckets']
        ])

    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        # No configuration exists - this is bad
        pass
    except ClientError as e:
        if e.response['Error']['Code'] not in ['NoSuchBucket', 'AccessDenied']:
            raise

    return result


# ============================================================================
# TAG VALIDATION UTILITIES
# ============================================================================

def validate_resource_tags(
    actual_tags: Dict[str, str],
    required_tags: List[str]
) -> Dict[str, Any]:
    """
    Validate that a resource has all required tags.

    Args:
        actual_tags: Dictionary of actual tags on the resource
        required_tags: List of required tag keys

    Returns:
        Dictionary with validation results:
        {
            'compliant': bool,
            'missing_tags': List[str],
            'present_tags': List[str]
        }

    Example:
        >>> result = validate_resource_tags(
        ...     {'Environment': 'prod', 'Owner': 'team'},
        ...     ['Environment', 'Owner', 'Project']
        ... )
        >>> print(result['missing_tags'])
        ['Project']
    """
    present_tags = list(actual_tags.keys())
    missing_tags = [tag for tag in required_tags if tag not in actual_tags]

    return {
        'compliant': len(missing_tags) == 0,
        'missing_tags': missing_tags,
        'present_tags': present_tags
    }


def normalize_boto3_tags(tags: List[Dict[str, str]]) -> Dict[str, str]:
    """
    Convert boto3 tag list format to simple dictionary.

    Args:
        tags: List of tag dicts in boto3 format [{'Key': 'foo', 'Value': 'bar'}, ...]
            or [{'key': 'foo', 'value': 'bar'}, ...] (case variations)

    Returns:
        Dictionary of tags {key: value}

    Example:
        >>> normalize_boto3_tags([{'Key': 'Env', 'Value': 'prod'}])
        {'Env': 'prod'}
    """
    if not tags:
        return {}

    result = {}
    for tag in tags:
        # Handle both 'Key'/'Value' and 'key'/'value' formats
        key = tag.get('Key') or tag.get('key')
        value = tag.get('Value') or tag.get('value')
        if key:
            result[key] = value or ''

    return result


# ============================================================================
# PII DETECTION UTILITIES
# ============================================================================

def scan_text_for_pii(text: str, patterns: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Scan text for PII patterns.

    Args:
        text: Text to scan
        patterns: Optional custom patterns dict (default: PII_PATTERNS)

    Returns:
        List of PII types detected (e.g., ['Email', 'Phone'])

    Example:
        >>> scan_text_for_pii("Contact: john@example.com or 555-1234")
        ['Email', 'Phone']
    """
    if patterns is None:
        patterns = PII_PATTERNS

    detected = []
    for pii_type, pattern in patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pii_type)

    return detected


def scan_text_for_prompt_injection(text: str) -> Dict[str, Any]:
    """
    Scan text for prompt injection patterns.

    Args:
        text: Text to scan

    Returns:
        Dictionary with scan results:
        {
            'has_injection_patterns': bool,
            'patterns_found': List[str],
            'has_suspicious_unicode': bool
        }

    Example:
        >>> result = scan_text_for_prompt_injection("ignore previous instructions")
        >>> result['has_injection_patterns']
        True
    """
    patterns_found = []

    # Check for text-based injection patterns
    text_lower = text.lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.lower() in text_lower:
            patterns_found.append(pattern)

    # Check for suspicious Unicode
    has_unicode = False
    for pattern in SUSPICIOUS_UNICODE_PATTERNS:
        if re.search(pattern, text):
            has_unicode = True
            break

    return {
        'has_injection_patterns': len(patterns_found) > 0,
        'patterns_found': patterns_found,
        'has_suspicious_unicode': has_unicode
    }


# ============================================================================
# ERROR HANDLING UTILITIES
# ============================================================================

def handle_aws_error(
    error: Exception,
    operation: str,
    resource: str = '',
    log_access_denied: bool = True
) -> None:
    """
    Standardized AWS error handling with appropriate logging.

    Args:
        error: The exception that was raised
        operation: Description of the operation (e.g., "checking S3 encryption")
        resource: Optional resource identifier for context
        log_access_denied: Whether to log AccessDenied errors (default: True)

    Example:
        >>> try:
        ...     s3.get_bucket_encryption(Bucket='my-bucket')
        ... except ClientError as e:
        ...     handle_aws_error(e, "checking bucket encryption", "my-bucket")
    """
    if isinstance(error, ClientError):
        error_code = error.response['Error']['Code']

        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            if log_access_denied:
                resource_msg = f" for {resource}" if resource else ""
                print(f"[WARN] Permission denied while {operation}{resource_msg}")
        elif error_code in ['ResourceNotFound', 'NoSuchEntity', 'NoSuchBucket']:
            resource_msg = f" {resource}" if resource else ""
            print(f"[INFO] Resource not found{resource_msg} while {operation}")
        else:
            resource_msg = f" ({resource})" if resource else ""
            print(f"[ERROR] AWS API error while {operation}{resource_msg}: {error_code}")
    else:
        resource_msg = f" ({resource})" if resource else ""
        print(f"[ERROR] Unexpected error while {operation}{resource_msg}: {str(error)}")


# ============================================================================
# CLOUDWATCH LOGGING UTILITIES
# ============================================================================

def check_log_group_encryption(
    logs_client,
    log_group_name: str
) -> Dict[str, Any]:
    """
    Check CloudWatch Logs log group encryption.

    Args:
        logs_client: Boto3 CloudWatch Logs client
        log_group_name: Name of the log group

    Returns:
        Dictionary with encryption details:
        {
            'exists': bool,
            'encrypted': bool,
            'kms_key_id': str | None,
            'retention_days': int | None
        }
    """
    result = {
        'exists': False,
        'encrypted': False,
        'kms_key_id': None,
        'retention_days': None
    }

    try:
        response = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_name,
            limit=1
        )

        log_groups = [lg for lg in response.get('logGroups', [])
                     if lg.get('logGroupName') == log_group_name]

        if log_groups:
            log_group = log_groups[0]
            result['exists'] = True
            result['kms_key_id'] = log_group.get('kmsKeyId')
            result['encrypted'] = result['kms_key_id'] is not None
            result['retention_days'] = log_group.get('retentionInDays')

    except ClientError as e:
        handle_aws_error(e, "checking log group encryption", log_group_name, log_access_denied=False)

    return result
