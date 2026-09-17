import json, os, sys

SEVERITY_TO_COMMAND = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "notice",
    "unknown": "notice",
    "none": "notice",
}
# Per level, per step. GitHub documents this ceiling for warnings and errors;
# notices use the same conservative budget so the UI never becomes the place
# where we discover a separate provider limit.
LIMIT_PER_LEVEL = 10
# Workflow-command output and the step summary are rendering surfaces, not the
# authoritative report. Bound copied scanner text so one finding cannot flood
# the log or GitHub's 1 MiB per-step summary; the complete value remains in the
# uploaded native and SARIF artifacts.
MAX_MESSAGE_CHARS = 4000
MAX_PATHLESS_DETAILS = 20
MAX_EXTRA_SEVERITY_ROWS = 10
MAX_SEVERITY_LABEL_CHARS = 64

source = sys.argv[1]
try:
    with open(source, encoding="utf-8") as handle:
        payload = json.load(handle)
except (OSError, ValueError) as exc:
    print(f"ez-appsec: native report unreadable; no annotations ({exc})", file=sys.stderr)
    raise SystemExit(0)


def findings_of(document):
    # The same accepted keys the platform's own reader uses (and the SARIF
    # emitter uses): a payload that ingests also annotates.
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            value = document.get(key)
            if isinstance(value, list):
                return value
    return []


def normalized_severity(value):
    # policy.normalize_severity: outside the vocabulary is "unknown", and so
    # is None. A bare .lower() left " CRITICAL " ungraded and put a stray row
    # in the summary table.
    if value is None:
        return "unknown"
    severity = str(value).strip().lower()
    return severity if severity in SEVERITY_TO_COMMAND else "unknown"


def severity_of(finding):
    # policy.finding_severity, followed exactly, so all three surfaces -- the
    # gate, the SARIF and this -- grade one finding identically.
    #
    # Keyed on a key being *present*, not truthy: {"severity": "", "level":
    # "critical"} is "unknown" to the gate and the build passes, so an
    # ::error here would contradict the check beside it. And severity carried
    # as an identifier is what a GitLab-shaped report does; without it a
    # build-failing critical was annotated as a ::notice.
    for key in ("severity", "level", "risk"):
        if key in finding:
            return normalized_severity(finding.get(key))
    identifiers = finding.get("identifiers")
    if isinstance(identifiers, list):
        for identifier in identifiers:
            if isinstance(identifier, dict) and identifier.get("type") == "severity":
                return normalized_severity(
                    identifier.get("value") or identifier.get("name")
                )
    return "unknown"


def label_of(finding):
    # What the summary table calls this finding's severity. Deliberately the
    # scanner's own word, not the graded one: a table that silently relabels
    # "bizarre" as "unknown" hides that the scanner is emitting a severity
    # nothing here recognises. The *grade* is still severity_of -- the label
    # describes, it does not decide.
    for key in ("severity", "level", "risk"):
        if key not in finding:
            continue
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()[:MAX_SEVERITY_LABEL_CHARS]
        # Presence answers the question in policy.finding_severity. Falling
        # through here would call {"severity": "", "level": "critical"}
        # critical in the table beside a notice annotation and a passing gate.
        return severity_of(finding)
    return severity_of(finding)[:MAX_SEVERITY_LABEL_CHARS]


def path_of(finding):
    location = finding.get("location")
    if isinstance(location, dict):
        candidate = location.get("file")
        if isinstance(candidate, dict):
            candidate = (
                candidate.get("file_name")
                or candidate.get("path")
                or candidate.get("uri")
            )
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    for key in ("file", "file_path", "path"):
        if isinstance(finding.get(key), str) and finding[key].strip():
            return finding[key].strip()
    return None


def line_of(finding):
    location = finding.get("location")
    values = []
    if isinstance(location, dict):
        file_location = location.get("file")
        values = [
            location.get("start_line"),
            location.get("startLine"),
            location.get("line"),
            file_location.get("line") if isinstance(file_location, dict) else None,
        ]
    values.extend(
        [finding.get("line"), finding.get("start_line"), finding.get("startLine")]
    )
    for value in values:
        try:
            line = int(value)
        except (TypeError, ValueError):
            continue
        # Line 0 is "unplaced" in the scanner report; pinning an annotation
        # to line 1 would claim a position the scan never saw.
        if line > 0:
            return line
    return None


def title_of(finding):
    keys = ("name", "title", "rule", "ruleId", "rule_id", "check_id", "id")
    for key in keys:
        if isinstance(finding.get(key), str) and finding[key].strip():
            return finding[key].strip()
    return "Finding"


def message_of(finding):
    # Matched content is copied, never composed (M027 S06).
    for key in ("message", "description", "name", "title"):
        if isinstance(finding.get(key), str) and finding[key].strip():
            return finding[key].strip()
    return "ez-appsec finding"


def bounded(value, limit=MAX_MESSAGE_CHARS):
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def summary_text(value, limit=MAX_MESSAGE_CHARS):
    # Scanner-controlled text is untrusted Markdown. Flatten it, bound it, and
    # escape every CommonMark punctuation character so a finding cannot forge
    # a link, image, heading, table row or HTML element in the job summary.
    text = bounded(" ".join(str(value).split()), limit)
    backslash = chr(92)
    punctuation = backslash + "`*_{}[]<>()#+-.!|"
    return "".join(backslash + char if char in punctuation else char for char in text)


def escape_data(value):
    # The message half of a workflow command: %, CR and LF, and nothing else.
    #
    # "%" first, or the escapes this function writes get escaped again. It is
    # not decoration: the runner decodes %0A back into a newline, so a scanner
    # message containing the literal text "%0A::error ..." -- matched content
    # from the scanned repository, which on a fork PR is written by whoever
    # opened it -- rendered as a second line that reads exactly like another
    # annotation from this tool. Escaping the "%" keeps it text.
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def escape(property_value):
    # A property value additionally escapes the two characters that separate
    # properties from each other and from the message.
    return escape_data(property_value).replace(":", "%3A").replace(",", "%2C")


findings = [f for f in findings_of(payload) if isinstance(f, dict)]
order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5, "none": 6}
ranked = sorted(findings, key=lambda f: order.get(severity_of(f), 5))

annotated = {"error": 0, "warning": 0, "notice": 0}
held_back = {"error": 0, "warning": 0, "notice": 0}
pathless = []
pathless_count = 0
counts = {}
for finding in ranked:
    severity = severity_of(finding)
    counts[label_of(finding)] = counts.get(label_of(finding), 0) + 1
    command = SEVERITY_TO_COMMAND.get(severity, "notice")
    path = path_of(finding)
    if path is None:
        # Without a path there is nowhere on the diff to place an annotation.
        pathless_count += 1
        if len(pathless) < MAX_PATHLESS_DETAILS:
            pathless.append(finding)
        continue
    if annotated[command] >= LIMIT_PER_LEVEL:
        held_back[command] += 1
        continue
    properties = ["file=" + escape(path)]
    line = line_of(finding)
    if line is not None:
        properties.append("line=" + str(line))
    properties.append("title=" + escape(title_of(finding)[:255]))
    # Comma-separated. The runner reads everything between the command name
    # and the closing "::" as one property list split on ",", so a space here
    # produced a single property `file` whose value was
    # "src/app.py line=7 title=..." -- a path matching no file in the repo,
    # which is an annotation that never lands on the diff. That is the whole
    # point of the step, and it failed silently.
    message = escape_data(bounded(message_of(finding)))
    print(f"::{command} {','.join(properties)}::{message}")
    annotated[command] += 1

total = len(findings)
summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
lines = [f"### ez-appsec scan: {total} finding{'s' if total != 1 else ''}"]
lines.append("")
if total:
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    known = ("critical", "high", "medium", "low", "info", "unknown")
    # A severity the table does not know still happened; dropping its row
    # would make the table sum to less than the stated total.
    extra = sorted(s for s in counts if s not in known)
    visible_extra = extra[:MAX_EXTRA_SEVERITY_ROWS]
    for severity in known + tuple(visible_extra):
        if counts.get(severity):
            label = summary_text(severity, MAX_SEVERITY_LABEL_CHARS)
            lines.append(f"| {label} | {counts[severity]} |")
    hidden_extra_count = sum(
        counts[severity] for severity in extra[MAX_EXTRA_SEVERITY_ROWS:]
    )
    if hidden_extra_count:
        lines.append(f"| other unrecognized labels | {hidden_extra_count} |")
    lines.append("")
    shown = annotated["error"] + annotated["warning"] + annotated["notice"]
    held = held_back["error"] + held_back["warning"] + held_back["notice"]
    if held:
        lines.append(
            f"ez-appsec emits at most {LIMIT_PER_LEVEL} error, {LIMIT_PER_LEVEL} warning "
            f"and {LIMIT_PER_LEVEL} notice annotations per step; {shown} of {total} "
            "findings are annotated above. "
            f"**{held} more are in the `ez-appsec-scan` artifact** (results.sarif)."
        )
        lines.append("")
    if pathless_count:
        plural = "s" if pathless_count != 1 else ""
        lines.append(
            f"{pathless_count} finding{plural} with no file path — these cannot "
            f"be placed on the diff, so up to {MAX_PATHLESS_DETAILS} are listed here:"
        )
        lines.append("")
        for finding in pathless:
            lines.append(
                f"- {summary_text(title_of(finding), 255)} — "
                f"{summary_text(message_of(finding))}"
            )
        omitted_pathless = pathless_count - len(pathless)
        if omitted_pathless:
            lines.append(
                f"- **{omitted_pathless} more path-less findings are in the "
                "`ez-appsec-scan` artifact.**"
            )
        lines.append("")
else:
    lines.append("No findings. Clean scan.")

if summary_path:
    try:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError as exc:
        # The summary is a view. Its filesystem failing must not replace the
        # scanner/platform verdict; annotations already printed remain useful.
        print(
            f"ez-appsec: step summary could not be written ({exc})", file=sys.stderr
        )
print(
    f"ez-appsec: {annotated['error']} error, {annotated['warning']} warning, "
    f"{annotated['notice']} notice annotations"
)
