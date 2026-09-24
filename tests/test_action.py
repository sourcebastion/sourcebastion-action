from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ACTION_PATH = ROOT / "action.yml"
ACTION_TEXT = ACTION_PATH.read_text(encoding="utf-8")
ACTION = yaml.safe_load(ACTION_TEXT)
STEPS = ACTION["runs"]["steps"]
BY_NAME = {step.get("name", ""): step for step in STEPS}


def test_action_has_no_required_inputs_or_secret_references():
    assert "${{ secrets." not in ACTION_TEXT
    for name, spec in ACTION["inputs"].items():
        assert spec.get("required") is False, name
        assert spec.get("default") is not None, name


def test_third_party_actions_are_sha_pinned_and_labelled():
    files = [ACTION_PATH, *(ROOT / ".github" / "workflows").glob("*.yml")]
    found = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        matches = re.findall(
            r"^\s*uses:\s*([^\s#]+)(?:\s+#\s+(v\d+(?:\.\d+)*))?\s*$",
            text,
            re.MULTILINE,
        )
        for reference, version in matches:
            if reference.startswith("./"):
                continue
            found += 1
            assert re.fullmatch(
                r"[^/@]+/[^@]+@[0-9a-f]{40}", reference
            ), f"{path}: {reference}"
            assert version, f"{path}: {reference}"
    assert found


def test_managed_upload_reads_the_scan_output():
    step = BY_NAME["Report findings to SourceBastion (managed mode)"]
    assert step["env"]["SOURCEBASTION_RESULTS_DIR"] == (
        "${{ steps.scan.outputs.results_dir }}"
    )
    assert '"$SOURCEBASTION_RESULTS_DIR/results.json"' in step["run"]
    assert "scan-results/results.json" not in step["run"]


def test_hosted_v2_never_skips_the_required_upload_or_falls_back_to_legacy():
    upload = BY_NAME["Report findings to SourceBastion (managed mode)"]
    gate = BY_NAME["Enforce the policy gate"]
    assert "inputs.policy-gate-mode == 'hosted-v2'" in upload["if"]
    assert upload["env"]["SOURCEBASTION_POLICY_GATE_MODE"] == (
        "${{ inputs.policy-gate-mode }}"
    )
    assert "inputs.policy-gate-mode == 'legacy'" in gate["if"]
    assert ACTION["inputs"]["policy-gate-mode"]["default"] == "legacy"


def test_vulnerability_db_preparation_cannot_read_the_repository():
    script = BY_NAME["Scan the repository"]["run"]
    preparation, scan = script.split("docker run --rm", 2)[1:]
    assert "--entrypoint grype" in preparation
    assert "db update" in preparation
    assert "$GITHUB_WORKSPACE" not in preparation
    assert "SOURCEBASTION_API_KEY" not in preparation
    assert "--network none" in scan
    assert "$GITHUB_WORKSPACE:/scan:ro" in scan
    assert "GRYPE_DB_AUTO_UPDATE=false" in scan


def test_keyless_upload_performs_no_request(tmp_path):
    report = tmp_path / "results.json"
    report.write_text(json.dumps({"findings": []}), encoding="utf-8")
    env = dict(os.environ)
    env.pop("SOURCEBASTION_API_KEY", None)
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "upload.py"),
            str(report),
            "http://127.0.0.1:1",
            "",
            "",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "staying keyless" in completed.stdout


def test_gate_fails_closed_on_a_high_finding(tmp_path):
    report = tmp_path / "results.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "name": "SQL injection",
                        "severity": "high",
                        "message": "unsafe query",
                        "location": {"file": "app.py", "start_line": 3},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gate.py"), str(report), "high"],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert "1 high" in completed.stderr


def test_public_openapi_contains_only_ingest():
    document = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    assert list(document["paths"]) == ["/checks/{check_id}/ingest"]


def test_release_requires_provenance_and_a_protected_environment():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    assert "environment: release" in workflow
    assert '"$GITHUB_REF" != "refs/heads/main"' in workflow
    assert "attestations: write" in workflow
    assert "id-token: write" in workflow
    assert re.search(r"uses: actions/attest@[0-9a-f]{40} # v4", workflow)
    assert "full-version releases are immutable" in workflow
    assert 'git push --force origin "refs/tags/$MAJOR_TAG"' in workflow


def test_ci_cache_tracks_the_actual_dependency_manifest():
    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(
        encoding="utf-8"
    )
    assert "cache-dependency-path: requirements-dev.txt" in workflow


def test_security_ci_covers_dependency_changes_and_source_analysis():
    workflow = (ROOT / ".github" / "workflows" / "security.yml").read_text(
        encoding="utf-8"
    )
    assert "pull_request:" in workflow
    assert "branches: [main]" in workflow
    assert "schedule:" in workflow
    assert "name: Dependency review" in workflow
    assert re.search(
        r"uses: actions/dependency-review-action@[0-9a-f]{40} # v5\.0\.0",
        workflow,
    )
    assert "name: CodeQL (python)" in workflow
    assert "security-events: write" in workflow
    assert "languages: python" in workflow
    assert len(
        re.findall(r"uses: github/codeql-action/(?:init|analyze)@[0-9a-f]{40} # v4", workflow)
    ) == 2


def test_documentation_recommends_verifiable_usage():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    prose = " ".join(readme.split())
    assert "sourcebastion/sourcebastion-action@v1" in readme
    assert "gh attestation verify" in readme
    assert "full 40-character commit SHA" in prose
    assert "API-COMPATIBILITY.md" in readme


def test_new_action_surfaces_are_sourcebastion_branded():
    assert ACTION["name"] == "SourceBastion scan"
    assert ACTION["author"] == "SourceBastion"
    assert "ez-appsec" not in ACTION_TEXT.lower()
    assert "EZ_APPSEC" not in ACTION_TEXT
    assert ACTION["inputs"]["image"]["default"].startswith(
        "ghcr.io/sourcebastion/sourcebastion-scanner@sha256:"
    )
    assert ACTION["inputs"]["ingest-url"]["default"] == ""
    assert "sourcebastion-scan" in ACTION_TEXT
