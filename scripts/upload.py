#!/usr/bin/env python3
"""The managed-mode client (M030 S05, M043) — upload or verify the App gate.

The same scan runs keyless or managed; the key decides whether the result is
also posted to the platform, and nothing else changes — not the scanner, not
the findings, not the local gate. That is the entire difference, and this
client is where it lives.

Contract, published in ``API-COMPATIBILITY.md`` and mirrored by
``openapi.json`` (generated from the platform's own models, so it
cannot drift):

* ``POST {base}/checks/{check_id}/ingest``, Bearer key in the header — never
  in the body.
* Envelope: ``repo_key``, ``idempotency_key``, ``run_context`` and the
  findings list, all optional server-side; this client always sends them
  when the CI environment provides the values.
* Media type versioning: ``application/vnd.sourcebastion.ingest.v1+json``, so a
  pinned ``@v1`` uploader keeps posting across additive platform changes.
  Its own version rides in ``User-Agent``.

Behaviour the free tier depends on:

* **No key means no network call** — the guard runs before any request is
  built. Keyless legacy scans never touch us; hosted-v2 fails closed.
* **A failed upload does not fail the build by default** (S05's own risk: a
  platform incident must not become an outage in every customer's pipeline).
  Set ``SOURCEBASTION_STRICT_UPLOAD=true`` to make it fatal.
* **A policy rejection is always fatal** — the platform saw the scan and
  refused it; that is a gate verdict, not a delivery problem (M028-D6).
* **Errors name the cause and the action** (M025 S03): an expired key, a
  revoked project and an unreachable platform are three different sentences.
* **A fork pull request cannot reach secrets**, so legacy mode is keyless with
  an honest message; hosted-v2 fails closed rather than claiming a pass.
* **Hosted-v2 reads only the GitHub App's server-owned decision** for the exact
  PR/branch head. It does not upload a CI report that could supersede the App
  findings run, and never treats the CI payload as policy evidence.

Exit codes: 0 = sent and accepted, or deliberately not sent; 1 = policy
rejected, configuration error, or (strict mode) delivery failed; 2 = usage.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# The version rides in User-Agent so a breaking change can be measured
# against real adoption (INGEST-CONTRACT T04). The file is bumped by the
# Action repository's release process.
try:
    VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text(encoding="utf-8").strip()
except OSError:
    VERSION = "unknown"

# The same provider-signal mapping the generated templates use: one trigger
# vocabulary, whatever CI posted the scan.
TRIGGER_KINDS = {
    "push": "push",
    "pull_request": "pull_request",
    "merge_request_event": "pull_request",
    "workflow_dispatch": "manual",
    "web": "manual",
    "api": "manual",
    "schedule": "schedule",
}

# M025 S03's rule: three failures an operator can actually tell apart. Each
# names the cause and the next action; none hides behind "upload failed".
NAMED_ERRORS = {
    401: "the API key was rejected — it is expired or revoked. Mint a new key from the repository's Integrate-with-CI flow; it is shown once.",
    403: "the platform refused this project — the key's project was revoked or its entitlement has lapsed. Check the project's status in the SourceBastion dashboard.",
    404: "the check was not found — the check id is wrong, or the platform URL points at the wrong deployment. Verify the check id in the dashboard.",
    429: "the platform is rate-limiting this project. The scan's verdict and artifacts are already delivered by this pipeline; retry, or contact support if it persists.",
}


def _fail_delivery(message: str, strict: bool) -> int:
    # A delivery failure is reported loudly and — unless the customer asked
    # for strictness — does not fail the build (S05 T03). The workflow-command
    # form is GitHub-only; GitLab gets the same sentence as plain text.
    line = f"SourceBastion: upload failed: {message}"
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("::error::" + line, file=sys.stderr)
    else:
        print(line, file=sys.stderr)
    if strict:
        print(
            "SourceBastion: SOURCEBASTION_STRICT_UPLOAD is set, so this failure fails the build.",
            file=sys.stderr,
        )
        return 1
    print(
        "SourceBastion: the scan's verdict and artifacts were delivered by this pipeline; "
        "the platform copy is what is missing.",
        file=sys.stderr,
    )
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: upload.py RESULTS_JSON INGEST_BASE_URL [CHECK_ID [REPO_KEY]]",
            file=sys.stderr,
        )
        return 2
    source, base_url = sys.argv[1], sys.argv[2].rstrip("/")
    check_id = sys.argv[3] if len(sys.argv) > 3 else ""
    repo_key = sys.argv[4] if len(sys.argv) > 4 else ""
    gate_mode = os.environ.get("SOURCEBASTION_POLICY_GATE_MODE", "legacy").strip() or "legacy"
    if gate_mode not in {"legacy", "hosted-v2"}:
        print("SourceBastion: policy-gate-mode must be legacy or hosted-v2", file=sys.stderr)
        return 1
    hosted_v2 = gate_mode == "hosted-v2"
    strict = hosted_v2 or os.environ.get("SOURCEBASTION_STRICT_UPLOAD", "").strip().lower() in ("1", "true", "yes")

    # The free tier's boundary, first and unconditional: no key, no request.
    # Nothing below this line runs on a keyless scan.
    key = os.environ.get("SOURCEBASTION_API_KEY", "").strip()
    if not key:
        if hosted_v2:
            print("SourceBastion: hosted-v2 requires an API key; the gate cannot pass keyless", file=sys.stderr)
            return 1
        print(
            "SourceBastion: no API key — staying keyless. Nothing was sent to the "
            "platform: no account, no repository record, no findings."
        )
        return 0

    if os.environ.get("SOURCEBASTION_FORK_PR", "").strip().lower() == "true":
        if hosted_v2:
            print("SourceBastion: hosted-v2 cannot verify a fork PR without credentials", file=sys.stderr)
            return 1
        print(
            "SourceBastion: fork pull request — GitHub withholds repository secrets "
            "from these runs, so this job reports nothing to the platform. The "
            "scan, its annotations and its artifacts are unaffected; nothing is "
            "misconfigured."
        )
        return 0

    if not check_id:
        print(
            "SourceBastion: an API key was provided without a check id. Set the "
            "check-id input (GitHub) or SOURCEBASTION_CHECK_ID (GitLab) to the check "
            "this repository reports to.",
            file=sys.stderr,
        )
        return 1
    if not base_url:
        print(
            "SourceBastion: an API key requires an explicit ingest-url until "
            "the production SourceBastion API host is available.",
            file=sys.stderr,
        )
        return 1
    gate_commit = os.environ.get("SOURCEBASTION_GATE_COMMIT_SHA") or os.environ.get("COMMIT_SHA") or ""
    gate_ref = os.environ.get("SOURCEBASTION_GATE_REF") or os.environ.get("REF") or ""
    if hosted_v2 and not (
        repo_key and re.fullmatch(r"[0-9a-f]{40}", gate_commit)
        and (gate_ref.startswith("refs/heads/") or re.fullmatch(r"refs/pull/[1-9][0-9]*/head", gate_ref))
    ):
        print(
            "SourceBastion: hosted-v2 requires an exact repository and GitHub head identity",
            file=sys.stderr,
        )
        return 1

    if hosted_v2:
        # The uploaded CI report cannot attest that every configured scanner
        # ran, or that the account's mandatory floor was applied. Only the
        # GitHub App execution can make that claim. Keep the CI report local
        # and read its independently persisted, exact-head decision instead.
        query = urllib.parse.urlencode({
            "repo_key": repo_key, "ref": gate_ref, "commit_sha": gate_commit,
        })
        url = f"{base_url}/checks/{check_id}/policy-decision?{query}"
        for attempt in range(30):
            request = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {key}",
                    "User-Agent": f"sourcebastion-action/{VERSION}",
                },
                method="GET",
            )
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    if response.status == 202:
                        if attempt < 29:
                            time.sleep(10)
                            continue
                        print(
                            "SourceBastion: GitHub App policy decision did not complete within five minutes",
                            file=sys.stderr,
                        )
                        return 1
                    result = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    print("SourceBastion: hosted policy decision is missing or stale", file=sys.stderr)
                    return 1
                return _fail_delivery(
                    NAMED_ERRORS.get(exc.code, f"the platform returned HTTP {exc.code}"),
                    True,
                )
            except (urllib.error.URLError, OSError, ValueError) as exc:
                return _fail_delivery(
                    f"the platform could not be reached at {base_url}: {exc}", True
                )
            expected = {
                "policy_profile": "scan-gate.v2",
                "policy_ref": gate_ref,
                "policy_repo_key": repo_key,
                "policy_commit_sha": gate_commit,
            }
            if (
                not isinstance(result, dict)
                or any(result.get(name) != value for name, value in expected.items())
                or not isinstance(result.get("policy_engine_version"), str)
                or re.fullmatch(
                    r"[0-9]+\.[0-9]+\.[0-9]+",
                    result["policy_engine_version"],
                ) is None
                or not isinstance(result.get("policy_findings_run_id"), int)
                or isinstance(result.get("policy_findings_run_id"), bool)
                or result["policy_findings_run_id"] <= 0
                or not all(
                    isinstance(result.get(name), int)
                    and not isinstance(result.get(name), bool)
                    and result[name] >= 0
                    for name in ("policy_project_version", "policy_organization_version")
                )
                or any(
                    not isinstance(result.get(name), str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", result[name]) is None
                    for name in ("policy_snapshot_digest", "policy_bundle_digest")
                )
                or result.get("policy_status") not in {"passed", "failed", "error"}
            ):
                print(
                    "SourceBastion: platform did not return a complete current-commit scan-gate.v2 decision",
                    file=sys.stderr,
                )
                return 1
            if result["policy_status"] == "passed":
                print("SourceBastion: GitHub App policy gate passed")
                return 0
            print(
                f"SourceBastion: GitHub App policy gate {result['policy_status']}",
                file=sys.stderr,
            )
            return 1

    try:
        with open(source, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        return _fail_delivery(f"the native report could not be read: {exc}", strict)

    sequence = os.environ.get("CI_RUN_SEQUENCE") or ""
    provider_trigger = os.environ.get("PROVIDER_TRIGGER") or ""
    body = dict(payload) if isinstance(payload, dict) else {"findings": payload}
    body.update({
        "repo_key": repo_key,
        "idempotency_key": os.environ.get("IDEMPOTENCY_KEY")
        or ":".join(
            part
            for part in (check_id, repo_key, os.environ.get("COMMIT_SHA") or "", os.environ.get("CI_RUN_ID") or "")
            if part
        ),
        "run_context": {
            "commit_sha": os.environ.get("COMMIT_SHA") or "",
            "ref": os.environ.get("REF") or None,
            "ci_run_id": os.environ.get("CI_RUN_ID") or None,
            "ci_run_sequence": int(sequence) if sequence.isdigit() else None,
            "delivery_mode": os.environ.get("DELIVERY_MODE") or "api",
            "trigger_kind": TRIGGER_KINDS.get(provider_trigger, "unknown"),
        },
    })

    request = urllib.request.Request(
        f"{base_url}/checks/{check_id}/ingest",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            # Media-type versioning: v1 keeps posting across additive changes
            # (INGEST-CONTRACT T02/T04). The key is in the header, never the body.
            "Content-Type": "application/vnd.sourcebastion.ingest.v1+json",
            "User-Agent": f"sourcebastion-action/{VERSION}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            print(
                "SourceBastion: the platform rejected this CI report because "
                "the hosted policy gate owns this project or its scan identity "
                "conflicts; use hosted-v2 verification for an App-gated project",
                file=sys.stderr,
            )
            return 1
        message = NAMED_ERRORS.get(exc.code)
        if message is None:
            message = (
                f"the platform returned HTTP {exc.code}. "
                + (
                    "This looks like a platform incident — the scan itself already succeeded."
                    if exc.code >= 500
                    else "Verify the platform URL and the key's project."
                )
            )
        return _fail_delivery(message, strict)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return _fail_delivery(
            f"the platform could not be reached at {base_url}: {exc}", strict
        )

    # Legacy verdict: the platform saw the scan and answered. A rejection here is
    # a gate outcome and always fatal (M028-D6) — unlike the delivery
    # failures above, which merely lost the copy.
    result = document.get("ingest_result") if isinstance(document, dict) else None
    if isinstance(document, dict) and "ingest_result" not in document:
        result = document.get("result")
    policy_status = result.get("policy_status") if isinstance(result, dict) else None
    reason = result.get("reason") if isinstance(result, dict) else None
    if policy_status == "passed":
        print("SourceBastion: uploaded; platform policy passed")
        return 0
    message = reason or (
        "platform policy failed" if policy_status == "failed"
        else "platform returned no final policy verdict"
    )
    print(f"SourceBastion: the platform rejected this scan: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
