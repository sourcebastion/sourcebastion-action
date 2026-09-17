# Releasing sourcebastion-action

Full-version releases are immutable. The `v1` tag is the only moving release
reference and points to the newest compatible `v1.x.y` release.

1. Open a pull request that changes `VERSION` to the next semantic version and
   describes any ingest-contract compatibility impact.
2. Obtain review from a CODEOWNER and merge only after the required `Test`
   check passes. The author cannot satisfy their own required review.
3. Run the `Release` workflow on `main` with the exact `vMAJOR.MINOR.PATCH`
   value. Its `release` environment requires a different administrator's
   approval and prevents self-review.
4. Confirm that the GitHub release contains the source archive, checksum, and
   Sigstore bundle, and that the moving major tag points to the same commit.
5. Verify from a separate checkout:

   ```bash
   gh release download v1.0.0 --repo sourcebastion/sourcebastion-action
   sha256sum --check sourcebastion-action-v1.0.0.tar.gz.sha256
   gh attestation verify sourcebastion-action-v1.0.0.tar.gz \
     --repo sourcebastion/sourcebastion-action
   ```

The attestation proves which source commit and workflow produced the archive;
it does not establish that either was safe. CODEOWNERS, required review,
required checks, a fresh hosted runner, and the protected release environment
are independent controls.
