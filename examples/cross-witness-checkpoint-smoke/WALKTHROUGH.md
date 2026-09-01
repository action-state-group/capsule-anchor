# Cross-witness checkpoint smoke test — walkthrough

This is the hand-off for a foreign log operator (e.g. AgenTrust's trace
registry) integrating with `witness.agentactioncapsule.org` — the
[cll-checkpoint-cose-wire] wire form that `POST /checkpoints` accepts (single-host
witness ruling, 2026-08-27). Two scripts, both runnable with only this public
repo installed (`pip install -e .` from the repo root; needs `httpx`,
`cbor2`, `cryptography`, `scitt-cose`, all already declared in
`pyproject.toml`).

## What this proves

`submit_checkpoint.py` builds a CLL checkpoint from scratch, signs it,
submits it, and — independently of the submission itself — fetches it back
and verifies the witness's countersignature offline. Five steps, each printed
so a run's stdout is a readable transcript:

1. Generate an Ed25519 test key + a checkpoint claims map.
2. Wrap it as a COSE_Sign1 Signed Statement.
3. `POST` the raw COSE bytes to `/checkpoints`.
4. A **separate** `GET /v1/inclusion/{digest}` call — not just trusting the
   POST response — to confirm the record is actually stored.
5. `GET /anchor/authority-pubkey` and verify the returned COSE Receipt
   offline with `scitt_cose.verify_receipt` — no trust in the operator's own
   claims about what it did.

Run it:

```
pip install -e .
python examples/cross-witness-checkpoint-smoke/submit_checkpoint.py \
    --host https://witness.agentactioncapsule.org \
    --log-id "<your-log-id>" \
    --out /tmp/checkpoint-smoke
```

`--log-id` defaults to a clearly-synthetic test identity
(`asg-smoke-test/v1`) — swap in your own `log_id` (this becomes the CWT
issuer / the `log_id` under which the witness will record your checkpoint)
and let the script generate a fresh key, or point it at your own signing key
by adapting `build_checkpoint_cose()`.

## Current registration policy (as of this writing, 2026-09-01)

`/checkpoints` verifies the submitted COSE_Sign1's own signature against the
Ed25519 public key named in its own `kid` header — it does **not** currently
check the submitter's identity against an allowlist. That is expected to
change (`[witness-enroll-trace-registry-key]` / `[witness-external-submitter]`
are in flight) to a config-driven allowlist of `(iss, key)` pairs before
launch. Foreign checkpoints are, and will remain, countersigned under an
**"observed" grade** — the witness records that it saw and timestamped your
checkpoint; it does **not** verify your log's own consistency proofs (that is
out of scope for v1). Never read a `/checkpoints` acceptance as an MMR-verified
claim about your log's internal consistency — only about existence-and-time.

## Leg 1 vs leg 2

This directory captures **leg 1**: a full run against the live witness using
our own synthetic test identity (`asg-smoke-test/v1`), proving the wire
format and the round-trip work end-to-end today, without waiting on any
external party's state. See `leg1-transcript.txt` for the captured run and
`leg1-artifacts/` for the raw bytes (test private key, COSE checkpoint,
receipt) it produced.

**Leg 2** — re-running the fetch-back + offline-verify steps against a real
trace-registry checkpoint once one is actually published — is intentionally
**not run yet**. As of 2026-09-01, AgenTrust's checkpoint pipeline was a
no-op (their fix PR was still in review, staging empty, zero checkpoints
published anywhere). Leg 2 is gated on that landing; running it early would
just produce a 404.

## Watching for leg 2's trigger: `watch_witness.py`

```
python examples/cross-witness-checkpoint-smoke/watch_witness.py --baseline 582
```

**Read the limitation before wiring this to anything automated.**
`POST /checkpoints` is a *stateless* route: the witness dispatches your
checkpoint as a bare SHA-256 digest and does not retain your `log_id`,
`mmr_size`, or any other claim after registration. The public
`GET /anchor/transparency-log` feed has no `kind` value for "checkpoint" and
no field tying an entry back to a submitter. There is no GET-by-log_id
endpoint. **This means nothing on the public read surface can currently
distinguish "AgenTrust's first checkpoint landed" from "anyone registered
anything."** `watch_witness.py` polls `GET /anchor/sth` for `tree_size`
growth as the cheapest available signal and alerts on any growth — a
necessary-but-not-sufficient trigger to go check (with Imran, or by
re-running leg 2 against a known digest), not proof by itself.

A precise, log_id-scoped watcher needs a stored/queryable record keyed by
submitter identity — which is exactly what
`[witness-enroll-trace-registry-key]` / `[witness-external-submitter]`'s
acceptance criteria ("MMR vs foreign grade distinguishable in the
stored/served checkpoint record") are expected to add. Once that lands,
point the watcher at that surface instead of this heuristic.

## Files here

- `submit_checkpoint.py` — the leg-1/leg-2 script.
- `watch_witness.py` — the tree-size-growth watcher.
- `leg1-transcript.txt` — captured stdout of an actual leg-1 run against the
  live witness (2026-09-01).
- `leg1-artifacts/` — the raw bytes from that run: `test_key.pem` (the
  synthetic test private key — throwaway, generated for this run only),
  `checkpoint.cose` (the submitted COSE_Sign1 statement), `receipt.cose` (the
  COSE Receipt the witness returned).
