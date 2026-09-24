from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
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
    assert "### SourceBastion scan: 1 finding" in summary_text
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
        SOURCEBASTION_API_KEY="must-not-be-sent",
        SOURCEBASTION_FORK_PR="true",
    )

    completed = run_script(
        "upload.py", str(source), "http://127.0.0.1:1", "check-id", env=env
    )

    assert completed.returncode == 0, completed.stderr
    assert "fork pull request" in completed.stdout


def test_hosted_v2_fails_without_key_or_fork_credentials(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [])
    env = dict(os.environ, SOURCEBASTION_POLICY_GATE_MODE="hosted-v2")
    env.pop("SOURCEBASTION_API_KEY", None)
    no_key = run_script(
        "upload.py", str(source), "http://127.0.0.1:1", "check-id", env=env
    )
    assert no_key.returncode == 1
    assert "cannot pass keyless" in no_key.stderr
    env["SOURCEBASTION_API_KEY"] = "test-key"
    env["SOURCEBASTION_FORK_PR"] = "true"
    fork = run_script(
        "upload.py", str(source), "http://127.0.0.1:1", "check-id", env=env
    )
    assert fork.returncode == 1
    assert "fork PR without credentials" in fork.stderr


def test_hosted_v2_requires_current_commit_versioned_decision(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [])
    responses = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - HTTP server callback
            self.rfile.read(int(self.headers["Content-Length"]))
            payload = json.dumps({"ingest_result": responses.pop(0)}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = dict(
            os.environ,
            SOURCEBASTION_API_KEY="test-key",
            SOURCEBASTION_POLICY_GATE_MODE="hosted-v2",
            COMMIT_SHA="a" * 40,
            REF="refs/pull/7/head",
            CI_RUN_ID="100",
        )
        env.pop("SOURCEBASTION_FORK_PR", None)
        valid = {
            "policy_profile": "scan-gate.v2", "policy_status": "passed",
            "policy_ref": env["REF"], "policy_repo_key": "repo-key",
            "policy_commit_sha": env["COMMIT_SHA"],
            "policy_findings_run_id": 1,
            "policy_snapshot_digest": "sha256:" + "b" * 64,
            "policy_bundle_digest": "sha256:" + "c" * 64,
        }
        responses.extend([
            {"policy_status": "passed"},
            {**valid, "policy_commit_sha": "d" * 40},
            {**valid, "policy_bundle_digest": "invalid"},
            valid,
            {**valid, "policy_status": "error"},
        ])
        outcomes = [
            run_script(
                "upload.py", str(source), f"http://127.0.0.1:{server.server_port}",
                "check-id", "repo-key", env=env,
            )
            for _ in range(5)
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert [outcome.returncode for outcome in outcomes] == [1, 1, 1, 0, 1]
    assert "scan-gate.v2 decision" in outcomes[0].stderr
    assert "scan-gate.v2 decision" in outcomes[1].stderr


def test_managed_upload_requires_a_check_id_before_network(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [])
    env = dict(os.environ, SOURCEBASTION_API_KEY="test-key")
    env.pop("SOURCEBASTION_FORK_PR", None)

    completed = run_script("upload.py", str(source), "http://127.0.0.1:1", env=env)

    assert completed.returncode == 1
    assert "without a check id" in completed.stderr


def test_managed_upload_requires_explicit_sourcebastion_url(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [])
    env = dict(os.environ, SOURCEBASTION_API_KEY="test-key")
    env.pop("SOURCEBASTION_FORK_PR", None)

    completed = run_script("upload.py", str(source), "", "check-id", env=env)

    assert completed.returncode == 1
    assert "requires an explicit ingest-url" in completed.stderr


def test_managed_upload_uses_sourcebastion_protocol(tmp_path):
    source = tmp_path / "results.json"
    write_report(source, [])
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - HTTP server callback
            length = int(self.headers["Content-Length"])
            seen.append({
                "path": self.path,
                "content_type": self.headers["Content-Type"],
                "user_agent": self.headers["User-Agent"],
                "authorization": self.headers["Authorization"],
                "body": json.loads(self.rfile.read(length)),
            })
            payload = b'{"ingest_result":{"policy_status":"passed"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = dict(os.environ, SOURCEBASTION_API_KEY="test-key")
        env.pop("SOURCEBASTION_FORK_PR", None)
        completed = run_script(
            "upload.py", str(source), f"http://127.0.0.1:{server.server_port}",
            "check-id", "repo-key", env=env,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert completed.returncode == 0, completed.stderr
    assert seen[0]["path"] == "/checks/check-id/ingest"
    assert seen[0]["content_type"] == "application/vnd.sourcebastion.ingest.v1+json"
    assert seen[0]["user_agent"].startswith("sourcebastion-action/")
    assert seen[0]["authorization"] == "Bearer test-key"
    assert "test-key" not in json.dumps(seen[0]["body"])


def test_report_cannot_override_ci_repository_or_commit_identity(tmp_path):
    source = tmp_path / "results.json"
    source.write_text(json.dumps({
        "findings": [], "repo_key": "spoofed",
        "run_context": {"commit_sha": "f" * 40, "ref": "refs/heads/spoofed"},
    }), encoding="utf-8")
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - HTTP server callback
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            response = b'{"ingest_result":{"policy_status":"passed"}}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = dict(os.environ, SOURCEBASTION_API_KEY="test-key",
                   COMMIT_SHA="a" * 40, REF="refs/heads/main")
        env.pop("SOURCEBASTION_FORK_PR", None)
        result = run_script(
            "upload.py", str(source), f"http://127.0.0.1:{server.server_port}",
            "check-id", "real-repo", env=env,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert result.returncode == 0
    assert seen[0]["repo_key"] == "real-repo"
    assert seen[0]["run_context"]["commit_sha"] == "a" * 40
    assert seen[0]["run_context"]["ref"] == "refs/heads/main"
