# Local witness for CI

A CI job that tests witnessing starts this repository's service inside the job
instead of posting to the hosted witness at `witness.agentactioncapsule.org`
(#109). Pin the action by commit SHA, like any other dependency.

```yaml
- id: witness
  uses: action-state-group/capsule-anchor/ci/local-witness@<sha>
- name: the step that registers checkpoints
  env:
    SSL_CERT_FILE: ${{ steps.witness.outputs.ca-bundle }}
  run: ... # point the client at ${{ steps.witness.outputs.url }} with key ${{ steps.witness.outputs.public-key }}
- if: always()
  uses: action-state-group/capsule-anchor/ci/local-witness/check@<sha>
  with:
    log: ${{ steps.witness.outputs.log }}
```

- The witness serves `https://localhost:<port>` with a self-signed certificate.
  Clients trust it through `SSL_CERT_FILE` (the system roots plus that
  certificate), which Go's default transport and httpx read on Linux.
  capsulectl takes only an HTTPS endpoint.
- `public-key` is the authority's raw Ed25519 public key in hex: the value of
  capsulectl's `--checkpoint-public-key` and of a profile's
  `checkpoint.public_key`.
- The store is in memory and the key is thrown away: receipts from this witness
  mean nothing after the job.
- Unless `block-production: "false"`, `witness.`, `anchor.` and
  `ts.agentactioncapsule.org` resolve to this host for the rest of the job, so a
  call that still reaches for the hosted witness fails.
- The service runs from its own venv, made from `python3` (3.11 or later; set
  `PYTHON` to choose another), and ignores any `CAPSULE_ANCHOR_*` setting of the
  calling job.
- Made for Linux runners. `scripts/check.sh` also runs it on a Mac, with
  `BLOCK=false`.
