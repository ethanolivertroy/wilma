# Wilma Test Suite

Comprehensive test suite for the Wilma AWS Bedrock security configuration checker.

## Overview

This test suite provides comprehensive coverage for all security checks implemented in Wilma, using pytest with mocked AWS services to enable testing without actual AWS credentials.

## Test Structure

```
tests/
├── __init__.py                 # Test package initialization
├── conftest.py                 # Shared pytest fixtures and mocks
├── test_utils.py              # Utility function tests
├── test_genai_checks.py       # GenAI security check tests
├── test_iam_checks.py         # IAM security check tests
├── test_network_checks.py     # Network security check tests
├── test_logging_checks.py     # Logging & monitoring check tests
├── test_tagging_checks.py     # Tagging compliance check tests
└── test_kb_checks.py          # Knowledge Base check tests
```

## Running Tests

### Run All Tests
```bash
pytest tests/
```

### Run Specific Test File
```bash
pytest tests/test_genai_checks.py
pytest tests/test_iam_checks.py
pytest tests/test_kb_checks.py
```

### Run Specific Test Class
```bash
pytest tests/test_genai_checks.py::TestPromptInjectionCheck
pytest tests/test_iam_checks.py::TestOverlyPermissivePolicies
```

### Run Specific Test Method
```bash
pytest tests/test_genai_checks.py::TestPromptInjectionCheck::test_no_guardrails_configured
pytest tests/test_utils.py::TestPIIDetection::test_detect_email
```

### Run with Verbose Output
```bash
pytest -v tests/
```

### Run with Coverage Report
```bash
pytest --cov=wilma --cov-report=html tests/
```

## Test Fixtures

All test files use shared fixtures defined in `conftest.py`:

### `mock_boto3_session`
Provides a mocked boto3 session with pre-configured AWS service clients.

### `mock_checker`
Provides a fully configured `BedrockSecurityChecker` instance with mocked AWS clients.

### `mock_config`
Provides a `WilmaConfig` instance with default configuration values.

### Sample Data Fixtures
- `sample_s3_bucket_arn`: Example S3 bucket ARN
- `sample_kb_config`: Example Knowledge Base configuration
- `sample_iam_policy`: Example IAM policy document
- `sample_guardrail_config`: Example guardrail configuration

## Test Coverage by Module

### 1. Utility Functions (`test_utils.py`)
- **ARN Parsing**: Tests for `parse_arn()` and `extract_resource_from_arn()`
- **PII Detection**: Tests for email, SSN, phone, credit card, and AWS key detection
- **Prompt Injection Detection**: Tests for jailbreak attempts and suspicious unicode
- **Tag Validation**: Tests for tag normalization and validation

### 2. GenAI Security Checks (`test_genai_checks.py`)
- **Prompt Injection Protection**:
  - No guardrails configured (HIGH risk)
  - Missing PROMPT_ATTACK filter (HIGH risk)
  - Weak filter strength (MEDIUM risk)
  - Properly configured guardrails (PASS)

- **Cost Anomaly Detection**:
  - No cost monitors (MEDIUM risk)
  - Cost monitors exist (PASS)

- **Data Privacy Compliance**:
  - Logging disabled (MEDIUM risk)
  - Unencrypted S3 logging (HIGH risk)
  - Unencrypted CloudWatch logging (HIGH risk)
  - Encrypted logging (PASS)

### 3. IAM Security Checks (`test_iam_checks.py`)
- **Overly Permissive Policies**:
  - Wildcard Bedrock permissions (CRITICAL risk)
  - AdministratorAccess policy (CRITICAL risk)
  - PowerUserAccess policy (HIGH risk)
  - Least-privilege policies (PASS)

- **Cross-Account Access**:
  - External account trust relationships (MEDIUM risk)
  - Service principals (PASS)

- **Role Session Duration**:
  - Excessive session duration (MEDIUM risk)
  - Acceptable session duration (PASS)

### 4. Network Security Checks (`test_network_checks.py`)
- **VPC Endpoints**:
  - No VPC endpoints (MEDIUM risk)
  - Missing bedrock-agent endpoint (MEDIUM risk)
  - PrivateDnsEnabled disabled (LOW risk)
  - Properly configured endpoints (PASS)

- **Security Groups**:
  - Overly permissive rules (0.0.0.0/0) (MEDIUM risk)
  - Restrictive rules (PASS)

### 5. Logging & Monitoring Checks (`test_logging_checks.py`)
- **Model Invocation Logging**:
  - Logging disabled (MEDIUM risk)
  - S3 logging enabled (PASS)
  - CloudWatch logging enabled (PASS)
  - Dual logging (PASS)

- **Log Retention**:
  - Insufficient retention (MEDIUM risk)
  - Adequate retention (PASS)
  - Indefinite retention (PASS)

- **Log Encryption**:
  - Unencrypted CloudWatch logs (HIGH risk)
  - Unencrypted S3 logs (HIGH risk)
  - Encrypted logs (PASS)

### 6. Tagging Compliance Checks (`test_tagging_checks.py`)
- **Resource Tagging**:
  - Untagged foundation models (LOW risk)
  - Untagged custom models (LOW risk)
  - Untagged Knowledge Bases (LOW risk)
  - Properly tagged resources (PASS)

- **Tag Normalization**:
  - Uppercase key normalization
  - Lowercase key normalization
  - Empty/None tag handling

### 7. Knowledge Base Checks (`test_kb_checks.py`)
- **Data Source Encryption**:
  - Unencrypted S3 data sources (HIGH risk)
  - Encrypted S3 data sources (PASS)

- **Vector Store Encryption**:
  - AWS-owned encryption keys (MEDIUM risk)
  - Customer-managed encryption keys (PASS)

- **Chunking Configuration**:
  - Excessive chunk sizes (MEDIUM risk)
  - Acceptable chunk sizes (PASS)

- **IAM Permissions**:
  - Wildcard permissions (CRITICAL risk)
  - Least-privilege permissions (PASS)

- **PII Detection**:
  - PII in bucket names (MEDIUM risk)
  - Clean metadata (PASS)

- **OpenSearch Access Policies**:
  - Overly permissive data access policies (HIGH risk)
  - Restrictive data access policies (PASS)

## Mocking Strategy

All tests use comprehensive mocking to avoid requiring actual AWS credentials:

1. **boto3 Session Mocking**: The `mock_boto3_session` fixture provides a mocked session
2. **Service Client Mocking**: Each AWS service client (bedrock, iam, s3, etc.) is mocked
3. **API Response Mocking**: All AWS API responses are pre-configured with test data
4. **Utility Function Mocking**: Where needed, utility functions are patched for specific test scenarios

Example:
```python
def test_unencrypted_s3_logging(self, mock_checker):
    mock_checker.bedrock.get_model_invocation_logging_configuration.return_value = {
        'loggingConfig': {'s3Config': {'bucketName': 'test-bucket'}}
    }

    with patch('wilma.checks.genai.check_s3_bucket_encryption') as mock_check:
        mock_check.return_value = {'encrypted': False}
        # ... test code
```

## Adding New Tests

### 1. Identify the Check Module
Determine which check module your test belongs to (genai, iam, network, logging, tagging, kb).

### 2. Create Test Class
Group related tests into a class with a descriptive name:
```python
class TestNewSecurityCheck:
    \"\"\"Test new security check functionality.\"\"\"
```

### 3. Write Test Methods
Each test method should:
- Have a descriptive name starting with `test_`
- Use the `mock_checker` fixture
- Set up mocked AWS responses
- Run the check
- Assert expected findings

Example:
```python
def test_security_issue_detected(self, mock_checker):
    \"\"\"Test detection of security issue.\"\"\"
    # Setup mock
    mock_checker.service.api_call.return_value = {'insecure': True}

    # Run check
    checks = SecurityChecks(mock_checker)
    findings = checks.check_security()

    # Assert
    high_findings = [f for f in mock_checker.findings if f.get('risk_level') == RiskLevel.HIGH]
    assert len(high_findings) > 0
```

### 4. Test Both Pass and Fail Cases
Always test:
- **Failure cases**: When the security check should flag an issue
- **Pass cases**: When the configuration is secure and should pass validation

## Best Practices

1. **Use Descriptive Test Names**: Test names should clearly describe what they're testing
2. **Test One Thing**: Each test should verify a single behavior
3. **Mock External Dependencies**: Never make real AWS API calls in tests
4. **Assert Specifically**: Check for specific findings, not just "some finding exists"
5. **Use Fixtures**: Leverage shared fixtures from `conftest.py` to reduce duplication
6. **Document Complex Tests**: Add docstrings explaining non-obvious test scenarios

## Continuous Integration

These tests are designed to run in CI/CD pipelines without AWS credentials:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    pip install -r requirements-dev.txt
    pytest tests/ -v --cov=wilma
```

## Dependencies

Test dependencies (install via `pip install -r requirements-dev.txt`):
- `pytest>=7.0.0` - Test framework
- `pytest-cov>=4.0.0` - Coverage reporting
- `pytest-mock>=3.10.0` - Enhanced mocking capabilities

## Troubleshooting

### Test Fails with "AttributeError: Mock object has no attribute X"
**Cause**: The mock client doesn't have the required AWS API method configured.
**Fix**: Add the method to the `create_mock_client()` function in `conftest.py`.

### Test Fails with "ImportError: cannot import name X"
**Cause**: Missing or circular import.
**Fix**: Ensure the module is properly installed and check for circular dependencies.

### Test Passes but Coverage is Low
**Cause**: Not all code paths are being exercised.
**Fix**: Add tests for edge cases, error handling, and alternative code paths.

## Contributing

When contributing new tests:

1. Follow the existing test structure and naming conventions
2. Ensure all new code has corresponding tests
3. Run the full test suite before submitting (`pytest tests/`)
4. Verify coverage hasn't decreased (`pytest --cov=wilma tests/`)
5. Update this README if adding new test categories

## License

Copyright (C) 2024  Ethan Troy
Licensed under GPL v3
