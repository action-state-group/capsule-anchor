# Notes — building `[trace-registry-first-checkpoint-conformance]` ahead of the trigger event

Written 2026-09-01, base_sha `origin/main` `26083a7bd7720267cdd4e3711e8d76689ea989be`. Updated
2026-09-01 after rebasing onto `origin/main` `ebc440bd1e9d72c2f4f29c448a76cb6650a31c5b` (`#33`,
which merged the enrollment/allowlist work while this was in progress -- see "Gap 2, updated"
below). This task fires when AgenTrust's trace-registry publishes its first REAL checkpoint to
`witness.agentactioncapsule.org`. That hasn't happened yet (Imran's fix PR was still in review as
of the `[cross-witness-synthetic-smoke-first]` amendment). Rather than wait idle, this builds the
conformance + chain-continuity machinery now so it's ready the moment a checkpoint exists.

## Gap 1 — no read-back / discovery surface (still open)

`POST /checkpoints` (`packages/capsule_anchor/anchoring/router.py`) is stateless and its response
(`CheckpointStampResponse`) carries only `receipt_b64`/`entry_hash`/`entry_hash_scheme`/
`leaf_index`/`tree_size`/`grade` — **no claim fields** (no `log_id`/`log_size`/`commitment`/etc).
The underlying store persists only the digest and the COSE Receipt, never the original checkpoint
bytes. There is no `GET`/query-by-`log_id` route anywhere. Consequence: **a third party cannot
recover a submitted checkpoint's claims from any public endpoint** — you have to already hold the
bytes (or know the exact `capsule_id` digest) to ask the witness anything about it.

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

## Gap 2 — countersign "grade" label: RESOLVED by `#33` while this was being built

Originally (base_sha `26083a7`) no grade/status field existed anywhere in the witness API. While
this task was in progress, `#33` (`feat(witness): config-driven allowlist for enrolled checkpoint
submitters, enroll AgenTrust trace-registry/v1`) merged onto `origin/main` and shipped exactly
this: `packages/capsule_anchor/anchoring/submitters.py` (`SubmitterAllowlist`, `GRADE_MMR_VERIFIED`
/ `GRADE_COUNTERSIGNED_OBSERVED`) plus a committed config,
`packages/capsule_anchor/config/checkpoint_submitters.json`, enrolling `trace-registry/v1` with
AgenTrust's real key (`bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90`) and
`accumulator: "foreign"` (→ `grade: "countersigned-observed"`, never `"mmr-verified"`).

`parse_and_verify_checkpoint_cose` now takes an `allowlist` kwarg: for an enrolled `log_id`, it
PINS verification to the config key (the self-asserted COSE `kid` is ignored entirely) and returns
`grade` in its claims dict. **This also closes half of Gap 1's "signed by the wrong key" case at
the server level** — a checkpoint claiming `trace-registry/v1` but signed by any other key now
fails at signature verification itself (401), not merely "self-consistent but not the identity we
enrolled." `checker.check_checkpoint_wire` passes the SAME committed allowlist
(`SubmitterAllowlist.from_env_or_default()`) into the same decoder the live witness uses, so a PASS
here means "the witness would accept this, from this identity, at this grade."

**Residual gap, still real:** `grade` is only ever returned on the ORIGINAL `POST /checkpoints`
response — the submitter (AgenTrust) sees it, we don't, since we're not the one posting. It is NOT
part of `InclusionResolveResponse` (`GET /v1/inclusion/{capsule_id}`), so `check_witness_tie_back`
cannot read it back after the fact. From our external vantage point, "confirm the witness
countersigned under the observed grade" resolves to *recomputing* what grade the witness would
assign, from the same committed config (`check_checkpoint_wire`), not to reading it back from the
live API. If that's judged insufficient (e.g. an auditor wants to see the ACTUAL served grade, not
a recomputation), the remaining fix is small: add `grade` to `InclusionResolveResponse` too — flag
to Steven as an optional follow-up, out of scope for this task (not this coder's lane; enrollment/
allowlist changes belong to `[witness-enroll-trace-registry-key]`'s owner).

## Gap 3 — chain continuity is not enforced server-side, by design (confirmed, not a bug)

`AnchorerService.witness_checkpoint` (what `/checkpoints` calls) explicitly dispatches a bare
digest, never reaching `_check_checkpoint_consistency` — its own docstring says so: "STAGE 1 is
deliberately stateless: no per-`log_id` continuity, no rollback/fork check." That consistency check
only runs on the separate, older `mmr-checkpoint` JSON path. `#33` did not change this (it's purely
about identity/key pinning, not chain state). So the witness will happily countersign a
discontinuous or rolled-back checkpoint from any submitter today — which is exactly why this
task's item (4) (external, two-checkpoint continuity checking) is the ONLY thing that would catch
AgenTrust's "fresh chain every 15 minutes" bug pattern before the blog claim ships.
`check_chain_continuity` in `checker.py` is that check, with a mutant test
(`test_chain_continuity_flags_fresh_chain_regression`) pinning exactly this regression shape.

## What's built and tested now, ready to run

- `checker.py`: `check_checkpoint_wire` (task items 1 + 2 combined: content-type, claim set, `sub`
  pattern, signature verified against the PINNED enrolled key via the real shipped allowlist,
  enrolled-`iss` match, and the `grade` label check — all in one pass, since `#33` made grade a
  direct output of the same decode/verify call), `check_witness_tie_back` (item 1's "fetch it from
  the witness" — the receipt tie-back, not content retrieval), `check_chain_continuity` (item 4,
  the critical regression check).
- `watcher.py`: a CLI that runs the full pipeline against checkpoint bytes handed to it, persists
  the last-seen checkpoint per log_id so a second run auto-checks continuity against the first.
- `packages/tests/test_cross_witness_conformance.py`: unit tests for every check including mutants
  (wrong content-type, wrong `iss`, impostor-signed-under-enrolled-iss, bad signature, wrong
  expected grade, missing enrollment, non-chained second checkpoint) plus a config-drift guard
  (`test_defaults_match_the_real_shipped_config`) and an in-process `TestClient` round-trip (POST
  /checkpoints -> GET /v1/inclusion -> offline receipt verify) proving the tie-back logic works
  against the real server code path. 15 new cases; full suite green (see commit message).
- Item (3) (sanity-checking their stated replay model) is NOT separately coded — per Gap 1, we
  cannot observe more than the receipt tie-back and the recomputed grade from outside; there is no
  additional external signal to check "no-key-means-no-checkpoint" / "fail-closed on root mismatch"
  against beyond `check_witness_tie_back` + `check_checkpoint_wire` both passing.

## 2026-09-02 amendment — JSON-form acceptance + per-submitter declared wire form

Follow-up to `[witness-enroll-trace-registry-key]` (#33) and this task (#34), filed as
`[witness-enrolled-json-checkpoint-form]` once Imran confirmed (2026-09-01 suggested edits) that
trace-registry's pipeline mints checkpoints as deterministic JSON + a bare Ed25519 signature
(`trace_verify._checkpoint.CheckpointRecord`, `agentrust-io/trace-registry`) — COSE_Sign1 alignment
(`trace-registry` PR #51 / `[trace-registry-align-51-cose-envelope]`) is a held, unmerged follow-up,
not what ships today. #33's enrolled path verified COSE only, so an enrolled `trace-registry/v1`
JSON submission 401ed.

**What changed:**

1. `submitters.py`: each enrolled entry now DECLARES a `wire_form` (`cose` default, or
   `json-ed25519`) plus, for `json-ed25519`, a `field_map` (our canonical field name → the
   submitter's own JSON key, identity-filled by default). `POST /checkpoints` dispatches on the
   HTTP `Content-Type` header (`application/cll-checkpoint+json` routes to the new
   `checkpoint_json.py`; anything else — including no header at all — is unchanged, the COSE path).
   JSON acceptance is ADDITIVE and ENROLLED-SUBMITTER-ONLY: a `log_id` with no entry, or an entry
   that hasn't declared `json-ed25519`, gets a named 400, never a fallback to the retired
   fully-open JSON `key_id`-trusting path. The signature is always verified against the entry's
   PINNED `pubkey`, never the submitted `key_id` — mirrors the COSE path's key-pinning exactly, and
   the SAME grade rules apply (`accumulator: foreign` → `countersigned-observed`).
2. `checker.check_checkpoint_wire` now dispatches to the DECODER `expected_log_id` declares
   (`entry.wire_form`) instead of hardcoding COSE — a `json-ed25519`-declared submitter's checkpoint
   is checked as JSON, a `cose`-declared one as COSE, and sending the WRONG form for a submitter's
   declared entry fails `wire_structure` cleanly (never silently checked against the other form's
   rules — "never cross-graded"). A `json-ed25519` checkpoint's `root`/`prev_root` are the
   submitter's own opaque commitment (their bagged MMR root) and are never reconstructed via our
   peak-list fold, matching `checkpoint_json.py`'s parser.
3. `checkpoint_submitters.json`: `trace-registry/v1`'s entry now declares
   `"wire_form": "json-ed25519"` (`field_map` omitted — their `CheckpointRecord` field set is
   byte-identical to ours, verified directly against `src/trace_verify/_checkpoint.py` and their
   live checkpoint 1, not guessed). Config committed, NOT deployed (Steven's click).

**Step 3 — the real live checkpoint, run against this code:** `trace-registry/v1` checkpoint 1
(`mmr_size=1`, `root=3af8ddf2c1f429bb4fc670437e48640887f60de809b18f8ccea55fefb0c6639a`) published
2026-09-01 in `agentrust-io/trace-registry` upstream commit `55e1270`
(`registry/2026/09/01.ndjson`'s `.mmr_checkpoint`) — read directly from their repo, never
retyped/guessed (§7b). `test_step3_live_checkpoint_1_conformance_pass` runs
`check_checkpoint_wire` against these EXACT bytes through the real committed (post-amendment)
config: **PASS** — wire well-formed, signature verifies under the pinned key, `sub`-equivalent
binding holds (log_id/mmr_size are direct signed fields in json-ed25519 form), `grade ==
countersigned-observed`. This is an OFFLINE conformance pass (our own decode/verify code, the
committed allowlist) — a live-witness tie-back (`check_witness_tie_back` against
witness.agentactioncapsule.org) was NOT attempted for checkpoint 1, because the JSON-acceptance
code in this PR is NOT YET DEPLOYED (held, Steven's click) — the live witness today only accepts
COSE, so a JSON POST of checkpoint 1 would 400 against the CURRENT deployment. Once deployed,
re-running the live tie-back (or `watcher.py` against the live witness) is the natural follow-up.
**Checkpoint 2 does not exist yet** (upstream `agentrust-io/trace-registry` `main` is `1e2d0b6`, one
checkpoint total as of 2026-09-02) — `test_step3_chain_continuity_harness_ready_for_checkpoint_2`
pins that the chain-continuity machinery (item 4) is ready and correctly distinguishes a
correctly-chained checkpoint 2 from the reported fresh-chain-every-15-min regression shape, using
checkpoint 1's real claims as the "first" side of the pair. Re-run `watcher.py` (or a direct
`check_chain_continuity` call) the moment a real checkpoint 2 publishes.
