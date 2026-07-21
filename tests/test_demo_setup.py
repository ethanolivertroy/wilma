"""Smoke tests for the optional live-demo helper."""

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load_demo_setup(script_path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("wilma_demo_setup", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_demo_test_forwards_the_selected_profile(monkeypatch):
    """The scan subprocess must use the same profile as the demo resources."""
    pytest.importorskip("opensearchpy")
    pytest.importorskip("requests_aws4auth")
    demo_setup = _load_demo_setup(Path(__file__).resolve().parents[1] / "scripts" / "demo_setup.py")
    demo = object.__new__(demo_setup.WilmaDemo)
    demo.region = "us-east-1"
    demo.profile = "test-sandbox"

    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(demo_setup.subprocess, "run", fake_run)

    assert demo.test()
    assert calls == [
        (
            ["wilma", "--region", "us-east-1", "--profile", "test-sandbox"],
            {"capture_output": True, "text": True},
        )
    ]


def test_all_attempts_cleanup_after_a_partial_setup_failure(monkeypatch):
    """The all-in-one path must clean up even when setup reports failure."""
    pytest.importorskip("opensearchpy")
    pytest.importorskip("requests_aws4auth")
    demo_setup = _load_demo_setup(Path(__file__).resolve().parents[1] / "scripts" / "demo_setup.py")
    calls: list[str] = []

    class PartialSetupDemo:
        def __init__(self, region: str, profile: str | None):
            assert region == "us-east-1"
            assert profile == "test-sandbox"

        def setup(self) -> bool:
            calls.append("setup")
            return False

        def test(self) -> bool:
            calls.append("test")
            return True

        def cleanup(self) -> bool:
            calls.append("cleanup")
            return True

    monkeypatch.setattr(demo_setup, "WilmaDemo", PartialSetupDemo)
    monkeypatch.setattr(demo_setup.time, "sleep", lambda _: None)
    monkeypatch.setattr(
        demo_setup.sys,
        "argv",
        ["demo_setup.py", "--all", "--confirm", "--profile", "test-sandbox"],
    )

    with pytest.raises(SystemExit) as exited:
        demo_setup.main()

    assert exited.value.code == 1
    assert calls == ["setup", "cleanup"]


def test_all_attempts_cleanup_after_a_scan_failure(monkeypatch):
    """The all-in-one path must clean up when Wilma itself fails."""
    pytest.importorskip("opensearchpy")
    pytest.importorskip("requests_aws4auth")
    demo_setup = _load_demo_setup(Path(__file__).resolve().parents[1] / "scripts" / "demo_setup.py")
    calls: list[str] = []

    class FailedScanDemo:
        def __init__(self, region: str, profile: str | None):
            assert region == "us-east-1"
            assert profile == "test-sandbox"

        def setup(self) -> bool:
            calls.append("setup")
            return True

        def test(self) -> bool:
            calls.append("test")
            return False

        def cleanup(self) -> bool:
            calls.append("cleanup")
            return True

    monkeypatch.setattr(demo_setup, "WilmaDemo", FailedScanDemo)
    monkeypatch.setattr(demo_setup.time, "sleep", lambda _: None)
    monkeypatch.setattr(
        demo_setup.sys,
        "argv",
        ["demo_setup.py", "--all", "--confirm", "--profile", "test-sandbox"],
    )

    with pytest.raises(SystemExit) as exited:
        demo_setup.main()

    assert exited.value.code == 1
    assert calls == ["setup", "test", "cleanup"]
