"""Smoke tests for the optional live-demo helper."""

import subprocess
import sys
from pathlib import Path

import pytest


def test_demo_setup_help_runs_without_aws_calls():
    """The demo entrypoint should import and parse --help without AWS access."""
    pytest.importorskip("opensearchpy")
    pytest.importorskip("requests_aws4auth")
    project_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/demo_setup.py", "--help"],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Create demo resources" in result.stdout
