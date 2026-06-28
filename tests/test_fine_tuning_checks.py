"""Tests for AWS Bedrock fine-tuning security checks."""

from wilma.checks.fine_tuning import FineTuningSecurityChecks
from wilma.enums import RiskLevel


def test_fine_tuning_jobs_paginate_with_lowercase_nexttoken(mock_checker):
    """Model customization job inventory should scan beyond the first page."""
    mock_checker.bedrock.list_model_customization_jobs.side_effect = [
        {
            "modelCustomizationJobSummaries": [{"jobName": "job-1", "jobArn": "arn:job/1"}],
            "nextToken": "token-2",
        },
        {
            "modelCustomizationJobSummaries": [{"jobName": "job-2", "jobArn": "arn:job/2"}],
        },
    ]
    checks = FineTuningSecurityChecks(mock_checker)

    jobs = checks._list_model_customization_jobs()

    assert [job["jobName"] for job in jobs] == ["job-1", "job-2"]
    assert mock_checker.bedrock.list_model_customization_jobs.call_args_list[1].kwargs["nextToken"] == "token-2"


def test_custom_models_paginate_with_lowercase_nexttoken(mock_checker):
    """Custom model inventory should scan beyond the first page."""
    mock_checker.bedrock.list_custom_models.side_effect = [
        {
            "modelSummaries": [{"modelName": "model-1", "modelArn": "arn:model/1"}],
            "nextToken": "token-2",
        },
        {
            "modelSummaries": [{"modelName": "model-2", "modelArn": "arn:model/2"}],
        },
    ]
    checks = FineTuningSecurityChecks(mock_checker)

    models = checks._list_custom_models()

    assert [model["modelName"] for model in models] == ["model-1", "model-2"]
    assert mock_checker.bedrock.list_custom_models.call_args_list[1].kwargs["nextToken"] == "token-2"


def test_custom_model_with_kms_key_has_no_output_encryption_finding(mock_checker):
    """Current get_custom_model modelKmsKeyArn field should be accepted."""
    model_arn = "arn:aws:bedrock:us-east-1:123456789012:custom-model/secure"
    mock_checker.bedrock.list_custom_models.return_value = {
        "modelSummaries": [{"modelName": "secure-model", "modelArn": model_arn}]
    }
    mock_checker.bedrock.get_custom_model.return_value = {
        "modelName": "secure-model",
        "modelArn": model_arn,
        "modelKmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/1234",
    }
    checks = FineTuningSecurityChecks(mock_checker)

    findings = checks.check_output_model_encryption()

    assert not [
        finding
        for finding in findings
        if finding["risk_level"] == RiskLevel.HIGH
        and finding["title"] == "Custom model not encrypted with customer-managed KMS key"
    ]
