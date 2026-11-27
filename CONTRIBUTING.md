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

Before every push, run `scripts/check.sh` (under 2 minutes on an Apple-silicon Mac). It runs what CI runs on pull requests and main: the DCO sign-off check on the commits not yet on `origin/main`, ruff and the suite on Python 3.11 and 3.12, the suite again against Postgres (the `test-postgres` job), the hostname lint, the neutrality scanner's self-test and the local-witness smoke run. For Postgres it uses `CAPSULE_ANCHOR_TEST_DATABASE_URL` when set, and otherwise starts a throwaway server from the local `initdb` and `pg_ctl` (`brew install postgresql@17`), failing when neither is there. Two CI steps are not run: the neutrality scan itself, unless `NEUTRALITY_TERMS` holds the term list (it is a repository secret, and the script says when it skipped the scan), and local-witness's production-hostname block, which edits `/etc/hosts` with sudo.

```bash
pip install -e ".[dev]"       # editable install + dev tools
pytest -q                      # run the suite
ruff check .                   # lint
```

The suite runs in memory by default and ignores any `CAPSULE_ANCHOR_DATABASE_URL` in your shell, so it never touches a real witness database. To run it against Postgres as well, install the `postgres` extra and point `CAPSULE_ANCHOR_TEST_DATABASE_URL` at a database you can create schemas in. Each test then gets an empty schema of its own there, dropped when the test ends; nothing else in that database is changed. Give each concurrent run its own test database: the store's writer lock is a Postgres advisory lock, which is shared across schemas.

```bash
pip install -e ".[dev,postgres]"
CAPSULE_ANCHOR_TEST_DATABASE_URL=postgresql://USER@localhost:5432/capsule_anchor_test pytest -q
```

## Where discussion happens

The underlying SCITT specification is discussed in the IETF **SCITT** Working
Group (`scitt@ietf.org`). Service issues (API, receipt format, CT log, storage)
belong here as GitHub issues.
