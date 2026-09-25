"""The free tier's policy gate (M030 S03).

The paid path's verdict comes from the platform after ingest. This is the
keyless equivalent, evaluated on the runner from the same
``scan-results/results.json`` the SARIF emitter and the annotation renderer
read: one scan, three views, one verdict.

Fails closed (M028-D6, M030 S03). A report that cannot be read, parsed, or
graded is a failed gate, not a passed one -- a green build with no trustworthy
verdict is a security bypass. The one tolerant case mirrors the other two
views: a finding whose severity the scanner did not state is graded
``unknown`` and announced at notice level, so it does not fail the gate even
at a strict threshold. It was evaluated; it was announced; it is not unknown
to the reader.

Exit codes, which the caller sees and CI surfaces:

* ``0`` -- policy passed (which includes "no findings").
* ``1`` -- policy violation: findings at or above the threshold exist.
* ``2`` -- unevaluable output: the report is missing, unreadable, has an
  unsupported shape, or the threshold input is not a supported severity name.
  Never a green build.
"""

import json
import os
import sys

# The same order the annotation renderer ranks by and the SARIF emitter maps
# from. One vocabulary across every surface of one scan.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown", "none")
THRESHOLDS = ("critical", "high", "medium", "low", "none")


def findings_of(document):
    # The same accepted keys the platform's own reader (policy.extract_findings),
    # the SARIF emitter and the annotation renderer use.
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            value = document.get(key)
            if isinstance(value, list):
                return value
    raise ValueError(
        "the scan report must be a list or an object containing a findings list"
    )


def severity_of(finding):
    # Presence wins over truthiness, matching policy.finding_severity and both
    # sibling scripts. FindingV2 can also carry severity as an identifier.
    for key in ("severity", "level", "risk"):
        if key in finding:
            value = finding.get(key)
            break
    else:
        value = None
        identifiers = finding.get("identifiers")
        if isinstance(identifiers, list):
            for identifier in identifiers:
                if (
                    isinstance(identifier, dict)
                    and identifier.get("type") == "severity"
                ):
                    value = identifier.get("value") or identifier.get("name")
                    break
    severity = "unknown" if value is None else str(value).strip().lower()
    return severity if severity in SEVERITY_ORDER else "unknown"


def main():
    if len(sys.argv) < 2:
        print("usage: gate.py RESULTS_JSON [FAIL_ON_SEVERITY]", file=sys.stderr)
        raise SystemExit(2)
    source = sys.argv[1]
    threshold = sys.argv[2] if len(sys.argv) > 2 else "high"
    if threshold not in THRESHOLDS:
        print(
            f"SourceBastion: fail-on-severity must be one of "
            f"{', '.join(THRESHOLDS)}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    try:
        with open(source, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        print(
            f"SourceBastion: the scan report could not be read, so the policy "
            f"verdict cannot be evaluated: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    try:
        raw_findings = findings_of(payload)
    except ValueError as exc:
        print(
            f"SourceBastion: the scan report cannot be graded: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if any(not isinstance(finding, dict) for finding in raw_findings):
        print(
            "SourceBastion: the scan report cannot be graded: every finding must "
            "be an object",
            file=sys.stderr,
        )
        raise SystemExit(2)
    findings = raw_findings
    counts = {}
    for finding in findings:
        severity = severity_of(finding)
        counts[severity] = counts.get(severity, 0) + 1

    # An unrecognized severity is graded "unknown" -- announced, never a
    # silent drop and never an excuse to fail without saying what happened.
    graded = {s: counts.get(s, 0) for s in SEVERITY_ORDER}

    # At-or-above, inclusive of the threshold itself. "none" disables the
    # gate outright: nothing is at-or-above nothing.
    limit = SEVERITY_ORDER.index(threshold) if threshold != "none" else -1
    failing = {
        severity: graded[severity]
        for severity in SEVERITY_ORDER[: limit + 1]
        if graded[severity]
    }

    lines = [f"### SourceBastion policy: {len(findings)} finding{'s' if len(findings) != 1 else ''}"]
    lines.append("")
    if findings:
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for severity in SEVERITY_ORDER:
            if graded[severity]:
                lines.append(f"| {severity} | {graded[severity]} |")
        lines.append("")
    scope = "nothing (gate disabled)" if threshold == "none" else f"`{threshold}` or above"
    lines.append(f"Gate: fails on {scope} -- **{'failed' if failing else 'passed'}**")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        except OSError as exc:
            # The summary is a delivery surface, not the verdict. Preserve the
            # evaluated exit code and explain the degraded presentation.
            print(
                f"SourceBastion: could not write the job summary: {exc}",
                file=sys.stderr,
            )

    if not failing:
        print(f"SourceBastion policy passed ({len(findings)} findings, threshold {threshold})")
        raise SystemExit(0)

    detail = ", ".join(f"{count} {severity}" for severity, count in failing.items())
    print(
        f"SourceBastion policy failed: {detail} at or above the "
        f"'{threshold}' threshold",
        file=sys.stderr,
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
