# Witness refusal session — trace-registry/v1 — 2026-09-23

Target: `https://anchor.agentactioncapsule.org` (live production capsule-anchor witness).
Session run: 2026-09-23 21:07-21:08 UTC. Script: `scripts/witness_refusal_session.py`
(committed `b503a72`, base `origin/main @ 0b50cea528d604a47bf31992c5e8dabc790927fa`).

**Not posted anywhere.** This file and the raw logs are the deliverable, held for Steven
to post to `agentrust-io/trace-registry#53`.

## Pre-flight (non-negotiable, run before any claim)

- `GET /health` (21:07:23Z, before session): `tree_size 1980`, `latest_sth_timestamp
  2026-09-23T21:07:23Z`, `signing_key_source: env` (not ephemeral) — live, not stale/cached
  (cross-checked against `/anchor/sth`, which agreed).
- `GET /openapi.json` (39374 bytes, snapshot saved alongside this file): the `/checkpoints`
  docstring **still contains** the phrase *"Wording of record until this ships live"*
  (added by `38455a8` 2026-09-07, removed by `d9908f3` #46 2026-09-16).
  → **Deploy bound confirmed, unchanged from the CORRECTION note: production is
  ≥ 38455a8 and < d9908f3.** Consequences verified directly from the live OpenAPI, not
  assumed: signed `iat` is live (see case 4 below); `/anchor/countersigned-root` exists
  but is **GET-only** (a read of nothing, since the countersign module's write routes
  are absent); no `/countersign` POST route anywhere in the 20-path live surface.
  Stage-2 continuity (label -65538) is NOT live. Do not demo or mention continuity or
  countersign submission as available.

## Dry run on staging (mandatory gate, run first)

No separate deployed staging host exists for capsule-anchor (checked `deploy/DEPLOY.md`).
The gate was: run the exact script logic against an in-process instance of **this
worktree's own code** (FastAPI `TestClient`, in-memory store, ephemeral key — explicit
`CAPSULE_ANCHOR_INSECURE_*` opt-ins, same as the test suite's own `conftest.py`), with
`trace-registry/v1` locally enrolled (`wire_form=json-ed25519`) so all four outcomes
could be proven before touching the network. Full log: `dry-run-staging.log`.

**The dry run caught two real mistakes in the first draft of the script before it ever
went live:**

1. Case 2 (contrast) was first drafted as a JSON-form submission. It came back **400**,
   not 200 — the JSON ingress path (`checkpoint_json.py`) refuses any `log_id` not
   enrolled with `wire_form: json-ed25519`; the "default-open" behavior the task cites
   from `submitters.py`'s module docstring applies to the **COSE** ingress path only.
   Fixed to submit COSE, self-asserted `kid`, before running live.
2. Case 3 (wrong wire form) was expected to be refused **for wire-form reasons**. Reading
   `checkpoint_cose.py` directly (not just the test names) shows
   `parse_and_verify_checkpoint_cose` has **no `wire_form` check at all** — it looks up
   the pinned key for the claimed `log_id` from the same allowlist regardless of that
   entry's declared wire form, and verifies the COSE signature against it. See the
   finding under Case 3 below — this changes what the refusal actually proves.

Dry run results (all four matched the corrected expectations before going live):
Case 1 → 401 (signature). Case 2 → 200, `grade: null`, `continuity_grade: "first-seen"`.
Case 3 → 401 (signature, not wire-form). Case 4 → 200, decoded header showed `iat`
present, `grade` absent (as predicted for an unenrolled submitter).

## Live session — the four cases, in order

Full request/response transcript, verbatim: `live-session.log`. Summary:

### Case 1 — the named case (Imran's ask)

Checkpoint claiming `log_id: trace-registry/v1`, JSON form (`Content-Type:
application/cll-checkpoint+json` — trace-registry's actually-declared wire form), signed
by a freshly-generated, never-enrolled Ed25519 key, self-asserting its own `key_id`.

**Result: `401`, `{"detail": "json checkpoint signature does not verify under its pinned
enrolled key"}`.** The self-asserted `key_id` is ignored for this `iss`; only the
pinned key (config-provisioned for `trace-registry/v1`) is checked, and it doesn't
match. Refused before any log write. Confirmed nothing was written: pre-session
`tree_size` was 1980; after case 1, still 1980 (only cases 2 and 4 below moved it).

### Case 2 — the contrast (default-open)

Same shape, but under a freshly-generated, timestamp+nonce test `log_id` — an
unenrolled, unambiguously test-scoped log id, submitted as COSE_Sign1 (self-signed,
self-asserted `kid`) per the finding above (JSON is enrolled-submitters-only; COSE is
where default-open lives).

**Result: `200`, `grade: null`, `entry_hash`, `leaf_index: 1980`, `tree_size: 1981`.**
Accepted and stamped with no enrollment at all, exactly as `submitters.py`'s module
docstring describes for the COSE path. This is an intentional, expected write to the
live witness for an obviously test-scoped log id — not an error, and not a real party's
log. `tree_size` moved 1980 → 1981, accounted for.

**Case (1) without case (2) would mislead** — read alone, case 1 looks like "the surface
is closed." It isn't; enrollment is narrow (one pinned `log_id`) and additive; every
other `log_id`, including one invented five minutes ago, is accepted by the COSE path
with no signup step.

### Case 3 — wrong wire form

COSE_Sign1 submitted under `log_id: trace-registry/v1` (declared `json-ed25519`),
signed by yet another fresh, unenrolled key.

**Result: `401`, `{"detail": "COSE checkpoint signature does not verify under its
pinned enrolled key"}`.** Refused — but **read the mechanism precisely, because it is
not the one the task text assumed.** `checkpoint_cose.py`'s verification function does
not check the enrolled entry's declared `wire_form` at all; content-type alone routes a
submission to the COSE path (`router.py`'s dispatch: JSON content-type → JSON path,
**anything else** → COSE path, unconditionally), and the COSE path then checks the
signature against whatever key is pinned for that `log_id` — regardless of what wire
form that entry declared. We do not possess AgenTrust's real pinned key, so any COSE
submission we construct fails signature verification and gets refused — but a
correctly-signed COSE submission under `trace-registry/v1`'s real key would **not** be
wire-form-blocked by this code path; there is no code that performs that specific
check on COSE ingress. The refusal is real, but "never silently re-parsed under the
other form's rules" overstates what the code enforces: it is enforced one-directionally
(JSON submissions are wire-form-gated; COSE submissions are not, they just still need
the right key). **Flag this precisely to Imran / whoever reviews this** rather than
letting the transcript imply a symmetric guarantee that doesn't exist in the code today.
No write occurred either way (`tree_size` unaffected by this case).

### Case 4 — fresh receipt, signed `iat` + `grade`

Another accepted checkpoint under the same test log id (COSE, `mmr_size=2`).

**Result: `200`, `tree_size: 1982`** (1981 → 1982, accounted for). Protected header of
the returned `receipt_b64`, base64+CBOR decoded on screen:

```
{1: -8, 395: 1, 15: {6: 1790197677}}
```

- Label `1` (alg) = `-8` (EdDSA/Ed25519); label `395` (vds) = `1` (RFC9162_SHA256).
- Label `15` (CWT claims) contains claim `6` (iat) = `1790197677` =
  `2026-09-23T21:07:57+00:00` — the witness's own observed-registration time, signed
  into the protected header, present.
- Label `-65537` (grade): **absent.** Grade is signed only for an *enrolled* submitter
  (this test log id has none); this is expected, not a defect.

**Supplementary, read-only — not a new submission:** `GET
/checkpoints/trace-registry%2Fv1` (the route's own docstring: "a pure read; it never
registers or mutates anything") returns AgenTrust's actual already-witnessed checkpoint
1 (2026-09-01T21:39:37Z, `mmr_size: 1`, the same bytes as the real
`agentrust-io/trace-registry` commit `55e1270`). Its **signed** protected header is
`{1: -8, 395: 1}` — **no CWT claims, no grade**, because that receipt was minted on
2026-09-01, before `iat`/`grade` shipped, and `/checkpoints`' idempotency rule means a
checkpoint already witnessed is **never re-stamped** on any later read or resubmission
("a checkpoint already witnessed before an upgrade is never re-stamped in the new
format," per the route's own docstring — confirmed live, not just read). The top-level
JSON response *does* carry `"grade": "countersigned-observed"` — computed fresh from
current config at read time — but that value is **not** inside the signed bytes for
this particular receipt. **Do not let a reader conflate the two:** the presence of
`grade` in the JSON envelope of a readback does not mean it is in the cryptographically
signed protected header for every receipt; it depends on when that specific checkpoint
was first witnessed.

## What this session does NOT show

- **Nothing about AgenTrust's own MMR consistency.** Their submitter entry is
  `accumulator: foreign` — this witness observes, timestamps, and countersigns their
  commitment bytes; it does not independently recompute or verify their MMR proofs.
  This is this witness's stated v1 scope, not a judgment on AgenTrust's implementation.
  Their `CheckpointRecord` field set is byte-identical to ours, which is why the
  identity field-mapping applies without translation.
- **Nothing about independence.** `asg-selftest/v1` was not invoked in this session and
  does not appear in any request or response above. If it appears elsewhere, its own
  config comment labels it an engineering proof of the code path — never evidence.
- **One witness does not close omission.** A party can simply never submit a checkpoint;
  this witness cannot detect or speak to that absence, only to what it has actually
  received.
- **Not tested here:** a correctly-signed COSE submission under `trace-registry/v1`'s
  real pinned key (we do not hold that key) — see the Case 3 finding above for why this
  matters: it is the one submission shape this session could not exercise, and it is
  exactly the shape that would show whether wire-form is enforced on the COSE path at
  all (current reading of the code says no).

## Accounting

| point | tree_size |
|---|---|
| pre-session | 1980 |
| after case 1 (refused) | 1980 |
| after case 2 (accepted) | 1981 |
| after case 3 (refused) | 1981 |
| after case 4 (accepted) | 1982 |
| post-session `/health` | 1982 |

Growth (+2) fully accounted for by the two intentional test-log-id acceptances; nothing
unexplained. **This growth is permanent** — `log_entries` in the live production log is
never pruned, so these two entries (and any future rerun's two entries) live in the real
tree forever. There is no delete/undo; that is why the script now refuses `--target live`
without an explicit `--i-understand-this-writes-to-production` flag, and why it generates
a fresh, unique test `log_id` per run instead of the fixed date-stamped one used for this
session (which would have collided had this session been rerun same-day).

## Boundary check

Refusal paths only; no key material printed (public key hex only, e.g. in case
2/4's `kid=` line — never a private key or PEM); no paid-layer vocabulary; nothing
posted, merged, or sent externally by this session.
