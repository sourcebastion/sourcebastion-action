# SourceBastion scan

Scan your repository and gate your pipeline. **No account, no configuration,
no secrets** — the free tier is a verdict on one commit, delivered through
your own CI:

- findings as **annotations** on the pull-request diff;
- **SARIF + native results** as an artifact on the workflow run;
- code-scanning **alerts** where your repository has code scanning enabled
  (optional — see permissions below);
- a **non-zero exit code** when policy fails.

The scanner is the same scanner on every tier. A free scan detects exactly
what a paid scan detects; what it does not do is remember anything — no
cross-run history, triage state, or dashboards on our side. Adding an API key
turns the same scan into a managed one — see "Managed mode" below. Without
it (the default) there is nothing to configure and nothing leaves your runner:
findings are not sent to SourceBastion, and GitHub receives only the annotations
and optional run/code-scanning artifacts described above.

> [!NOTE]
> **Actively maintained with automation and human review.** Automated dependency
> updates and hosted security CI keep this public Action current; releases and
> issue-driven changes remain human-governed. SourceBastion dependency updates
> receive at least a two-day soak before integration unless a maintainer confirms
> a zero-day emergency. Found a problem or have an idea? Please open a
> [bug report](https://github.com/sourcebastion/sourcebastion-action/issues/new?template=bug.yml)
> or [feature request](https://github.com/sourcebastion/sourcebastion-action/issues/new?template=feature.yml).
> Report vulnerabilities privately through the
> [Security tab](https://github.com/sourcebastion/sourcebastion-action/security/advisories/new).

## Usage

```yaml
name: SourceBastion
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  sourcebastion:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - uses: sourcebastion/sourcebastion-action@v1
```

That is the whole thing. The Action checks out nothing itself — scan the
commit your job checked out, not a different fetch of it.

The Action requires a Linux runner with Bash, Python 3, and Docker. GitHub's
`ubuntu-latest` runner provides all three. A self-hosted runner must run as an
unprivileged account: the Action deliberately refuses to turn the scanner into
a root container. The repository is mounted read-only, the report is written
to the runner's temporary directory, and the scanner runs without network
access. Before that scan, a separate container downloads Grype's vulnerability
database from Anchore. That preparation container has no repository mount or
SourceBastion credential; if the database cannot be prepared, the scan fails
closed.

## Permissions

`action.yml` cannot declare permissions for your workflow, so the sample
above carries them. What each scope does:

| Scope | Required? | What it is for | Without it |
| --- | --- | --- | --- |
| `contents: read` | **Yes** | `actions/checkout` reading your code | The job cannot start usefully |
| `security-events: write` | No | Uploading SARIF to code scanning | Upload is attempted, then a failure is explained with a notice; annotations and the artifact are unaffected |
| anything else | No | — | — |

**Fork pull requests:** GitHub withholds secrets and restricts the token on
fork-run runs. The keyless path needs no secret, so the scan, annotations,
artifact and gate all behave identically; the code-scanning upload may be
refused, which is non-fatal and explained in the job log.

**Restricted-token runs** degrade the same way and for the same reason: the
optional upload fails, everything the free tier promises still happens.

## Inputs

| Input | Default | Notes |
| --- | --- | --- |
| `image` | digest-pinned `ghcr.io/sourcebastion/sourcebastion-scanner@sha256:…` | Override only with another digest-pinned reference. The Action rejects tags and other floating references. |
| `fail-on-severity` | `high` | Lowest severity that fails the build: `critical`, `high`, `medium`, `low`, `none`. |
| `policy-gate-mode` | `legacy` | `legacy` uses the local severity gate. `hosted-v2` requires a current-commit, versioned SourceBastion policy decision and never falls back to the legacy gate. |
| `api-key` | *(empty — keyless)* | Set it and the same scan is also reported to the platform. Pass a secret: `api-key: ${{ secrets.SOURCEBASTION_API_KEY }}`. |
| `check-id` | *(empty)* | Required with `api-key`; minted with the key from the Integrate-with-CI flow. |
| `repo-key` | *(empty)* | Repository identity within the check, for lifecycle and delta on the platform. |
| `ingest-url` | *(empty)* | Required with `api-key` until the production SourceBastion API host is available. Use your deployment's HTTPS API base URL. |
| `strict-upload` | `false` | `true` makes a failed platform upload fail the build. `hosted-v2` always treats upload failure as fatal. |

## Exit codes

| Code | Meaning |
| --- | --- |
| job fails, scan step | The scanner or its execution failed — fail closed (M028-D6) |
| job fails, gate step, exit 1 | Policy violation: findings at or above `fail-on-severity` |
| job fails, gate step, exit 2 | Output could not be evaluated (report missing, unreadable, structurally invalid, or an invalid threshold) — fail closed |
| job fails, upload step | Managed mode only: the platform rejected the scan (always fatal), or `strict-upload: true` and the upload failed |
| job fails, hosted-v2 upload step | Required credentials, complete current-commit v2 decision, or platform delivery was unavailable; no legacy fallback |
| job succeeds | Policy passed |

A failed *optional delivery* (code-scanning upload, or a platform upload
without `strict-upload`) is reported with an error naming the cause and
never fails the build.

## Managed mode: add a key, that is all

```yaml
      - uses: sourcebastion/sourcebastion-action@v1
        with:
          api-key: ${{ secrets.SOURCEBASTION_API_KEY }}
          check-id: chk_your_check
          ingest-url: https://staging-api.sourcebastion.com/api
```

In the default `legacy` mode, the same scan runs — same scanner, same findings,
same gate. With a key it
is *also* posted to the platform: persistence, cross-run history, triage
state, dashboards. Nothing else changes in `legacy` mode. Without a key, no findings are sent
to SourceBastion — `upload.py`'s first guard exits before any platform request
is built. The image pull and the vulnerability-database download still use the
network, without access to the repository contents. In `legacy` mode, fork
pull requests run keyless with a message saying so.

A platform upload failure does not fail your build by default — your
pipeline already has the verdict and the artifacts. Errors name the cause
(expired key, revoked project, wrong check id, unreachable platform) so the
fix is obvious. The request schema is a published contract: `openapi.json`
here is a deterministic **ingest-only** export generated from the platform's
own models — it describes the ingest endpoint and nothing else.

### Hosted v2 opt-in is not yet a production gate

`policy-gate-mode: hosted-v2` disables the local threshold fallback and
requires the upload response to carry a `scan-gate.v2` decision bound to the
same repository, ref, commit, and findings run, with snapshot and bundle
digests. A missing key, fork-secret loss, failed upload, stale commit, or
legacy response fails the job. The current platform ingest API still returns
a legacy response, so this mode intentionally fails until the M043 server
integration and cross-consumer proofs are released. Keep the default
`legacy` mode for existing workflows; do not make `hosted-v2` a required
check yet.

## Verify a release

For the strongest reproducibility, pin the Action to a full 40-character
commit SHA. The moving `v1` tag deliberately receives compatible security
and bug fixes; a SHA trades those automatic updates for an immutable reference.
Full-version releases such as `v1.0.0` are immutable.

Every full-version release includes a source archive, its SHA-256 checksum,
and GitHub build-provenance attestation. Verify a downloaded archive before
inspection or redistribution:

```bash
gh attestation verify sourcebastion-action-v1.0.0.tar.gz \
  --repo sourcebastion/sourcebastion-action
sha256sum --check sourcebastion-action-v1.0.0.tar.gz.sha256
```

Provenance identifies the source commit and workflow that produced the archive.
It does not prove that either was safe; branch review and the protected release
environment are separate controls.

## What the free tier does not do

No SourceBastion account, repository record, finding row, or execution record is
created, and no request is made to the SourceBastion platform. Your CI provider
retains annotations, logs and artifacts under its own retention rules — that
is delivery, not a history product. If you need a dismissal to stay dismissed,
cross-run fingerprints, or "open 40 days" SLA clocks, that is the managed
product.

## Support

**SourceBastion is published under MIT and maintained on a best-effort basis.**
Issues and pull requests are welcome and read, but there is no response-time
commitment and issues may be closed unanswered. Two things carry real
commitments: **security reports** (see [SECURITY.md](SECURITY.md)) and
**breaking changes to the published ingest API** (see
[API-COMPATIBILITY.md](API-COMPATIBILITY.md)). Everything else is best effort.

## Licence

MIT — see [LICENSE](LICENSE).
