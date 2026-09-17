# Ingest API compatibility and privacy

`openapi.json` is the public, ingest-only contract for
`POST /checks/{check_id}/ingest`. It is generated from the same models the
service validates and excludes account, billing, administration, and other
retained platform routes.

## Version 1 compatibility

Clients send:

```http
Content-Type: application/vnd.ez-appsec.ingest.v1+json
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
