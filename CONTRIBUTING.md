# Contributing to capsule-anchor

`capsule-anchor` is the **transparency-service layer** for the Agent Action
Capsule specification
([`agent-action-capsule`](https://github.com/action-state-group/agent-action-capsule)).
Contributions are welcome.

## License (Apache-2.0)

All contributions are licensed under the **Apache License 2.0** (see `LICENSE`).

### Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Sign off every commit:

```bash
git commit -s -m "your message"
```

No CLA is required — the DCO is the whole agreement.

## Scope discipline (review gates, not preferences)

1. **Digest-only stays digest-only.** The anchor path accepts digests and
   COSE_Sign1 Signed Statements and never returns or stores plaintext. Any
   change that could put raw content on the wire is a correctness (and security)
   regression — see `SECURITY.md`.
2. **Product-free.** This service carries the transparency-log and receipt
   issuance logic only — nothing tenant-specific, billing-specific, or
   internal to a downstream product. PRs that import product internals will
   be declined; that belongs in a downstream engine.
3. **Neutrality is enforced.** A CI gate scans every PR for a reserved-vocabulary
   set (held in a repo secret, not listed here). Keep contributions vendor-neutral.
4. **The spec is the source of truth.** When `capsule-anchor` and the
   [`agent-action-capsule`](https://github.com/action-state-group/agent-action-capsule)
   draft disagree, fix the implementation or open an issue against the spec —
   never let them silently diverge. A receipt issued here MUST verify with the
   reference verifier.
5. **Standards honesty.** The underlying profile is an **individual IETF
   Internet-Draft**, not an RFC; never claim an RFC number or WG adoption it
   does not have.

## Dev setup

```bash
pip install -e ".[dev]"       # editable install + dev tools
pytest -q                      # run the suite
ruff check .                   # lint
```

## Where discussion happens

The underlying SCITT specification is discussed in the IETF **SCITT** Working
Group (`scitt@ietf.org`). Service issues (API, receipt format, CT log, storage)
belong here as GitHub issues.
