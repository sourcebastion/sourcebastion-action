from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_script(name: str, *arguments: str, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / name), *arguments],
        env=env,
        capture_output=True,
        text=True,
    )


def write_report(path: Path, findings: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"findings": findings}), encoding="utf-8")


def test_sarif_preserves_rule_severity_and_location(tmp_path):
    source = tmp_path / "results.json"
    destination = tmp_path / "results.sarif"
    write_report(
        source,
        [
            {
                "rule": "python.sql-injection",
                "name": "SQL injection",
                "message": "unsafe query",
                "severity": "HIGH",
                "file": "src/app.py",
                "line": 17,
            }
        ],
    )

    completed = run_script("sarif.py", str(source), str(destination))

    assert completed.returncode == 0, completed.stderr
    document = json.loads(destination.read_text(encoding="utf-8"))
    result = document["runs"][0]["results"][0]
    assert result["ruleId"] == "python.sql-injection"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "src/app.py"},
        "region": {"startLine": 17},
    }


def test_sarif_does_not_create_output_for_an_unreadable_report(tmp_path):
    destination = tmp_path / "results.sarif"

    completed = run_script(
        "sarif.py", str(tmp_path / "missing.json"), str(destination)
    )

    assert completed.returncode == 0
    assert "native report unreadable" in completed.stderr
    assert not destination.exists()


def test_annotations_escape_workflow_command_injection(tmp_path):
    source = tmp_path / "results.json"
    summary = tmp_path / "summary.md"
    write_report(
        source,
        [
            {
                "name": "unsafe,title",
                "message": "matched%0A::error file=other.py::forged\nnext",
                "severity": "high",
                "file": "src/a:b,c.py",
                "line": 4,
            }
        ],
    )
    env = dict(os.environ, GITHUB_STEP_SUMMARY=str(summary))

    completed = run_script("annotate.py", str(source), env=env)

    assert completed.returncode == 0, completed.stderr
    assert sum(
        line.startswith("::error ") for line in completed.stdout.splitlines()
    ) == 1
    assert "src/a%3Ab%2Cc.py" in completed.stdout
    assert "unsafe%2Ctitle" in completed.stdout
    assert "%250A%3A%3Aerror" not in completed.stdout
    assert "%250A::error" in completed.stdout
    assert "%0Anext" in completed.stdout
    summary_text = summary.read_text(encoding="utf-8")
    assert "### ez-appsec scan: 1 finding" in summary_text
    assert "::error" not in summary_text


def test_gate_fails_closed_for_invalid_threshold(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [])

    completed = run_script("gate.py", str(source), "urgent")

    assert completed.returncode == 2
    assert "fail-on-severity must be one of" in completed.stderr


def test_gate_treats_ungraded_findings_as_non_failing(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [{"name": "new class", "severity": "future"}])

    completed = run_script("gate.py", str(source), "low")

    assert completed.returncode == 0, completed.stderr
    assert "policy passed" in completed.stdout


def test_fork_signal_prevents_managed_upload(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [])
    env = dict(
        os.environ,
        EZ_APPSEC_API_KEY="must-not-be-sent",
        EZ_APPSEC_FORK_PR="true",
    )

    completed = run_script(
        "upload.py", str(source), "http://127.0.0.1:1", "check-id", env=env
    )

    assert completed.returncode == 0, completed.stderr
    assert "fork pull request" in completed.stdout


def test_managed_upload_requires_a_check_id_before_network(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [])
    env = dict(os.environ, EZ_APPSEC_API_KEY="test-key")
    env.pop("EZ_APPSEC_FORK_PR", None)

    completed = run_script("upload.py", str(source), "http://127.0.0.1:1", env=env)

    assert completed.returncode == 1
    assert "without a check id" in completed.stderr
