# Ingest API compatibility and privacy

`openapi.json` is the public, ingest-only contract for
`POST /checks/{check_id}/ingest`. It is generated from the same models the
service validates and excludes account, billing, administration, and other
retained platform routes.

## Version 1 compatibility

Clients send:

```http
Content-Type: application/vnd.sourcebastion.ingest.v1+json
```

Within a major version, SourceBastion will not change the meaning or type of an
existing envelope field, remove an accepted findings-list name, change the
idempotency-key contract, change the authentication mechanism, or remove an
existing enum member.

Additive changes may introduce optional fields, append accepted findings-list
names, add enum members, or make server validation more permissive. Clients
must ignore unknown response fields. Older servers may reject an enum member
introduced by a newer client.

A breaking change requires a new major version. Its deprecation and support
window will be announced in release notes and in this document before the old
version is removed. No blanket response-time or support-duration commitment is
made here.

## M043 hosted-v2 opt-in

The Action's optional `hosted-v2` mode does not upload its CI report. It reads
`GET /checks/{check_id}/policy-decision` with a project-scoped Bearer key and
the exact GitHub repository key, PR/branch head ref, and commit SHA. A 202 is
pending; a 409 is missing or stale. A 200 can be green only when the
server-owned `scan-gate.v2` response has `policy_status: passed`, a semantic
`policy_engine_version`, matching repository/ref/commit, positive
`policy_findings_run_id`, nonnegative project/account policy versions, and
valid snapshot and bundle SHA-256 digests. `failed`, `error`, missing fields,
stale identity, and transport failures are non-green. The platform must
revalidate its GitHub App-owned decision and protected target before the 200.
Do not enable `hosted-v2` on a required check before that server integration
and provider protection are released.

## Finding-data privacy

The platform may persist only these scanner-controlled fields:

```text
category, code_class, code_method, confidence, cve, end_line,
external_id, file, line, name, rule, scanner, severity, solution
```

Known matched-content fields are never persisted in plaintext:

```text
search_value, expected_value, actual_value, extra, description, message
```

`search_value`, `expected_value`, and `actual_value` may be represented by a
non-reversible keyed HMAC digest. Producers must not place matched secrets in
an allowlisted field. The Action's keyless default does not contact the
platform at all; this boundary applies only when an API key enables managed
upload.
