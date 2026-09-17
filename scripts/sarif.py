import json, sys

# ez-appsec severity -> SARIF level. SARIF has four levels and no "critical",
# so critical and high share "error" -- the one lossy point, stated in
# docs/M030/S01-SARIF.md and mirrored by the inverse table the platform's own
# inbound normalizer (findings_sarif.py) already uses.
SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
    "unknown": "none",
    "none": "none",
}

source, destination = sys.argv[1], sys.argv[2]
try:
    with open(source, encoding="utf-8") as handle:
        payload = json.load(handle)
except (OSError, ValueError) as exc:
    print(f"ez-appsec: native report unreadable; no SARIF written: {exc}", file=sys.stderr)
    raise SystemExit(0)


def findings_of(document):
    # The same accepted keys the platform's own reader (policy.extract_findings)
    # uses, so a payload that ingests also converts, and one that does not
    # cannot half-convert.
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            value = document.get(key)
            if isinstance(value, list):
                return value
    return []


def rule_id_of(finding):
    # FindingV2 -- the shape written by `ez-appsec scan --output` -- carries
    # the canonical identity at the top level. Prefer those explicit rule
    # fields before consulting legacy/GitLab identifiers. Do not use `id`
    # here: in GitLab-shaped reports it is the finding UUID, not the rule.
    for key in ("rule", "ruleId", "rule_id", "check_id"):
        if isinstance(finding.get(key), str) and finding[key].strip():
            return finding[key]
    identifiers = finding.get("identifiers")
    if isinstance(identifiers, list):
        # The first *rule* identifier wins. A severity identifier
        # ({"type": "severity"}) classifies the finding, it does not name
        # the rule -- using it would publish ruleId "critical".
        for identifier in identifiers:
            if not isinstance(identifier, dict) or identifier.get("type") == "severity":
                continue
            for key in ("value", "name"):
                if isinstance(identifier.get(key), str) and identifier[key].strip():
                    return identifier[key]
    # Older raw scanner results may have only a title/name (or a stable id).
    for key in ("id", "name", "title"):
        if isinstance(finding.get(key), str) and finding[key].strip():
            return finding[key]
    scanner = finding.get("scanner")
    if isinstance(scanner, dict):
        candidate = scanner.get("id")
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    for key in ("category", "type"):
        if isinstance(finding.get(key), str) and finding[key].strip():
            return finding[key]
    return "ez-appsec-finding"


def text_of(finding):
    # `message` and `description` carry matched content (M027 S06). They are
    # copied, never composed or extended: the SARIF view must not contain
    # anything the native report does not already carry.
    for key in ("message", "description", "name", "title"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return "ez-appsec finding"


def location_of(finding):
    location = finding.get("location")
    if not isinstance(location, dict):
        location = {}
    # FindingV2 uses top-level `file`/`line`; the older dashboard/GitLab shape
    # nests them under `location`. Follow the same aliases as
    # findings_store.normalize_finding so an ingestible report is placeable in
    # its SARIF view too.
    file_name = location.get("file") or finding.get("file")
    file_location = file_name if isinstance(file_name, dict) else {}
    # The dashboard payload nests file metadata; the scanner report uses a
    # plain path. Both are accepted, neither is guessed.
    if isinstance(file_name, dict):
        file_name = (
            file_name.get("file_name")
            or file_name.get("path")
            or file_name.get("uri")
        )
    file_name = file_name or finding.get("file_path") or finding.get("path")
    if not isinstance(file_name, str) or not file_name.strip():
        return None
    try:
        line = int(
            location.get("start_line")
            or location.get("startLine")
            or location.get("line")
            or file_location.get("line")
            or finding.get("line")
            or finding.get("start_line")
            or finding.get("startLine")
            or 0
        )
    except (TypeError, ValueError):
        line = 0
    physical = {"artifactLocation": {"uri": file_name}}
    # A missing or non-positive line is omitted rather than clamped to 1:
    # pinning a finding to the wrong line is worse than leaving it unplaced.
    if line > 0:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def normalized_severity(value):
    # policy.normalize_severity: anything outside the vocabulary is "unknown",
    # and None is too. Not a bare `.lower()` -- "Critical " and "CRITICAL" must
    # land on the same word the gate used.
    if value is None:
        return "unknown"
    severity = str(value).strip().lower()
    return severity if severity in SEVERITY_TO_LEVEL else "unknown"


def severity_of(finding):
    # policy.finding_severity, followed exactly, because this is the one place
    # the SARIF view could contradict the gate that ran beside it.
    #
    # Keyed on the *presence* of a key, not on its truthiness. A finding
    # carrying `{"severity": "", "level": "critical"}` grades "unknown" in the
    # gate -- the empty severity answers the question -- and a converter that
    # skipped to `level` would publish an `error` for a finding the build
    # passed.
    for key in ("severity", "level", "risk"):
        if key in finding:
            return normalized_severity(finding.get(key))
    # GitLab-shaped reports carry severity as an identifier rather than a
    # field. The gate reads it; without this the SARIF called a
    # build-failing critical "none" and left no severity at all.
    identifiers = finding.get("identifiers")
    if isinstance(identifiers, list):
        for identifier in identifiers:
            if isinstance(identifier, dict) and identifier.get("type") == "severity":
                return normalized_severity(
                    identifier.get("value") or identifier.get("name")
                )
    return "unknown"


rules = {}
results = []
for finding in findings_of(payload):
    if not isinstance(finding, dict):
        continue
    rule_id = rule_id_of(finding)
    severity = severity_of(finding)
    result = {
        "ruleId": rule_id,
        "level": SEVERITY_TO_LEVEL[severity],
        "message": {"text": text_of(finding)},
    }
    location = location_of(finding)
    if location is not None:
        result["locations"] = [location]
    # Bounded metadata only (M027 DECISIONS): severity, confidence, category
    # and cve classify a finding; they are not matched content.
    properties = {}
    for key in ("severity", "confidence", "category", "cve"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            properties[key] = value
    # A severity the gate found somewhere other than the `severity` field --
    # in the identifiers -- still belongs here, or the SARIF records a level
    # with nothing to explain it.
    if "severity" not in properties and severity != "unknown":
        properties["severity"] = severity
    if properties:
        result["properties"] = properties
    if rule_id not in rules:
        rule = {"id": rule_id}
        name = finding.get("name") or finding.get("title")
        if isinstance(name, str) and name.strip():
            rule["shortDescription"] = {"text": name}
        rules[rule_id] = rule
    results.append(result)

order = list(rules)
document = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "ez-appsec",
                    "informationUri": "https://github.com/ez-appsec/ez-appsec",
                    "rules": [rules[rule_id] for rule_id in order],
                }
            },
            "results": results,
        }
    ],
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2)
    handle.write("\n")
print(f"ez-appsec: wrote {destination} ({len(results)} findings)")
