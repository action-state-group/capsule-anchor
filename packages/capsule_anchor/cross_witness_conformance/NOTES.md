# Notes — building `[trace-registry-first-checkpoint-conformance]` ahead of the trigger event

Written 2026-09-01, base_sha `origin/main` `26083a7bd7720267cdd4e3711e8d76689ea989be`. This task
fires when AgenTrust's trace-registry publishes its first REAL checkpoint to
`witness.agentactioncapsule.org`. That hasn't happened yet (Imran's fix PR is still in review, per
the `[cross-witness-synthetic-smoke-first]` amendment). Rather than wait idle, this builds the
conformance + chain-continuity machinery now so it's ready the moment a checkpoint exists. Two
things were found along the way that the manager should know about — neither is a defect in
AgenTrust's checkpoint (there isn't one to check yet), both are gaps in **our own** witness.

## Gap 1 — no read-back / discovery surface

`POST /checkpoints` (`packages/capsule_anchor/anchoring/router.py:563`) is stateless and its
response (`CheckpointStampResponse`) carries only `receipt_b64`/`entry_hash`/`entry_hash_scheme`/
`leaf_index`/`tree_size` — **no claim fields** (no `log_id`/`log_size`/`commitment`/etc). The
underlying store (`packages/capsule_anchor/anchoring/store.py`) persists only the digest and the
COSE Receipt, never the original checkpoint bytes. There is no `GET`/query-by-`log_id` route
anywhere. Consequence: **a third party cannot recover a submitted checkpoint's claims from any
public endpoint** — you have to already hold the bytes (or know the exact `capsule_id` digest) to
ask the witness anything about it.

This means the task card's phrase "fetch it from the witness" cannot mean "fetch the checkpoint
content" — there is nothing to fetch. It can only mean "fetch the witness's *receipt* for a
checkpoint whose bytes you already have" — which is what `check_witness_tie_back` in `checker.py`
does (recomputes `capsule_id` via `_checkpoint_digest`, then `GET /v1/inclusion/{capsule_id}` and
verifies the COSE Receipt offline). That part is fully buildable and tested here.

**What's still missing:** a way to obtain the trace-registry's checkpoint bytes in the first place.
This tooling does not — and should not — guess at a URL for AgenTrust's own registry. `watcher.py`
is written to accept checkpoint bytes handed to it (file path or stdin) rather than to poll
anything, and documents this plainly. Recommend flagging to Steven/Imran whether AgenTrust
publishes checkpoints somewhere we can read (their own public trace-registry), or whether the
hand-off will be informal (Imran tells us, we run the watcher on what he sends).

## Gap 2 — no countersign "grade" label exists yet

The launch-tasks brief (`_work/cross-witness-launch-tasks-2026-08-31.md`, Task 1) requires the
witness's response/record to distinguish a foreign, **observed** checkpoint from an MMR-verified
one — "never present the two as the same guarantee." As of this base_sha, **no such field exists
anywhere** — not on `CheckpointStampResponse`, not on `InclusionResolveResponse`. The closest
existing concept, `CheckpointWitnessInfo.status` (`"first-seen"`/`"witnessed"`/`"already-
registered"`, `router.py:189-204`), is populated only on the *older* `/transparency/register-
statement` `mmr-checkpoint` JSON path, not on the canonical `/checkpoints` route AgenTrust will
actually use.

`check_countersign_grade` in `checker.py` is written to check a caller-supplied `grade_field` name
against an expected value, and reports `UNKNOWN` (not a silent pass) when no field name is given —
because today none exists to give it. Once `[witness-enroll-trace-registry-key]` ships whichever
field name it picks, pass it via `--grade-field` / the `grade_field=` kwarg; no other code change
needed.

## Gap 3 — chain continuity is not enforced server-side, by design (confirmed, not a bug)

`AnchorerService.witness_checkpoint` (`service.py:1091-1120`, what `/checkpoints` calls) explicitly
dispatches a bare digest, never reaching `_check_checkpoint_consistency` — its own docstring says
so: "STAGE 1 is deliberately stateless: no per-`log_id` continuity, no rollback/fork check." That
consistency check only runs on the separate, older `mmr-checkpoint` JSON path. So the witness will
happily countersign a discontinuous or rolled-back checkpoint from any submitter today — which is
exactly why this task's item (4) (external, two-checkpoint continuity checking) is the ONLY thing
that would catch AgenTrust's "fresh chain every 15 minutes" bug pattern before the blog claim ships.
`check_chain_continuity` in `checker.py` is that check, with a mutant test (`test_chain_continuity
_flags_fresh_chain_regression`) pinning exactly this regression shape.

## What's built and tested now, ready to run

- `checker.py`: `check_checkpoint_wire` (item 1: content-type, claim set, `sub` pattern, signature,
  enrolled-key match, enrolled-`iss` match), `check_witness_tie_back` (item 1's "fetch it from the
  witness" — the receipt tie-back, not content retrieval), `check_countersign_grade` (item 2, gap-
  aware), `check_chain_continuity` (item 4, the critical regression check).
- `watcher.py`: a CLI that runs the full pipeline against checkpoint bytes handed to it, persists
  the last-seen checkpoint per log_id so a second run auto-checks continuity against the first.
- `packages/tests/test_cross_witness_conformance.py`: unit tests for every check including mutants
  (wrong content-type, wrong `iss`, valid-signature-wrong-key, bad signature, non-chained second
  checkpoint) plus an in-process integration test (`TestClient`, no live network) proving the full
  `POST /checkpoints` → `GET /v1/inclusion` → offline receipt verify round-trip actually works
  against the real server code path.
- Item (3) (sanity-checking their stated replay model) is NOT separately coded — per Gap 1, we
  cannot observe more than the receipt tie-back from outside; `checker.py`'s module docstring and
  this file record that "no-key-means-no-checkpoint" and "fail-closed on root mismatch" reduce, from
  our vantage point, to `check_witness_tie_back` + `check_checkpoint_wire` both passing. There is no
  additional external signal to check against.
