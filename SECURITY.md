# Security policy

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting on this repository** —
"Report a vulnerability" under the Security tab. It needs no mailbox, no
DNS, and no owner to accept a report, and it keeps coordination private by
default. Please do not open a public issue for a security report.

A disclosure mailbox is planned; until it passes an end-to-end delivery
test it will not be listed here. A channel that bounces is worse than none.

## What to expect

Security reports are read and triaged on a best-effort basis. No
acknowledgement window or fix window is promised here, because a promise
without a named owner is not a promise — the commitments that do exist are
the ones the main policy has verified. See the support statement in this
repository's README.

## Scope

This repository ships a CI integration: it runs a digest-pinned scanner
image in your pipeline and, only if you supply an API key, posts results to
the ez-appsec platform. Reports about the scanner's detection rules belong
in the scanner repository; reports about the platform's handling of an
uploaded scan belong with the platform. Everything in between — the CI
files and scripts this repository ships, including the uploader — is this
repository's scope.
