# Countersign — an independent recompute over a withheld bundle

This document describes the `countersign/` module in this codebase: an additive,
opt-in extension to the witness that recomputes a set of generic, structural checks
over a *withheld* evidence bundle and returns a signed statement. Anyone can run one
— the module ships no product-specific policy, no branding, and no vocabulary beyond
what is defined here.

**The bundle this module ingests is the donated spec's own shape**
(`draft-mih-zhang-agent-action-capsule-evidence-bundle-00`, wire `bundle_version: "2"`
/ `bundle_kind: "evidence-bundle/v2"`) — the exact bytes `capsulectl bundle` produces,
carrying `completeness.payloads_mode: "none"` and no `disclosures` overlay. This
module never invents its own bundle model: the digest (JCS-canonical,
`sha256(JCS(bundle \ countersignatures))`) and the structural/completeness
verification (graph closure, CLL #13 range proof, per-record inclusion proof) are
computed by the neutral `agent_action_capsule.bundle` reference library, the same one
`capsulectl`'s Go verifier agrees with — never reimplemented here
([countersign-whole-bundle-shape]; a prior ad-hoc bundle model, built ahead of this
reconciliation, rejected 100% of `capsulectl`'s real output).

---

## 1. What this is, and what it is not

The witness (see `OPERATOR_GUIDE.md`) answers one question: *does an entry exist in
this log at this tree size, and has the log been consistent since?* It accepts almost
anything, is permissive by design, and never inspects the content of what it
witnesses.

Countersign answers a different, narrower question: *does a specific bundle of
records — digests only, no payloads — hold together structurally, and does it satisfy
a named profile's own checks?* It is:

- **Additive.** A second, opt-in registration surface in the same codebase, gated
  behind two environment variables (§4). Absent both, this module changes nothing
  about the witness's existing behavior.
- **Generic.** The five checks in §3 are content-agnostic — they recompute structure,
  sequence, and signatures, never the substance of what a record claims. This module
  ships **no policy modules** — `policy.NullPolicyModule` is a test double only.
  A profile's own checks (what a record kind means, what its content must satisfy)
  are supplied by whoever deploys an instance and loaded through the interface in §5.
- **Never a score.** Every check returns one of exactly five words (§2) — never
  pass/fail, never rolled into one aggregate number or grade.

**A pre-existing, unrelated use of the same word.** The witness's own checkpoint
path (`POST /checkpoints`, see `README.md`'s "Witness host" section and
`OPERATOR_GUIDE.md` §"What witnesses check") uses "counter-signed"/"countersigns"
as plain English for the ordinary act of signing and receipting whatever checkpoint
it accepts — including the `countersigned-observed` grade a foreign-accumulator
checkpoint earns when this witness observes and timestamps it without independently
verifying its accumulator math. That is witness behavior: permissive by design, no
registration policy, no issuer allowlist, no distinct signer identity from the
submitter. It predates this module and is not this module — this document is the
only place in this codebase where **Countersign** (capitalized) names a service.

## 2. The five results

Every check — the five generic ones and anything a profile's own policy module adds
— returns exactly one of:

| Result | Means |
|---|---|
| `established` | the check ran and its condition held |
| `failed` | the check ran and its condition did not hold |
| `not present` | the bundle carries nothing this check operates on |
| `not checked` | the check could not run (e.g. nothing to compare against, or no
  policy module covers this record kind) |
| `inconclusive` | the check ran but only partially resolved |

A statement never rolls these into an aggregate. Each check's result stands alone,
next to its own name and a `detail` string naming the thing that makes it true --
always populated internally (every check function, every test). **The wire
projection in `countersignatures[].statement.checks[]` currently carries only
`{name, result}`, no `detail`** ([countersign-whole-bundle-shape], found via the live
request-path round trip): `capsulectl`'s Go `CountersignCheck` struct declares only
`Name`/`Result`, and the CLI's real request path decodes with
`DisallowUnknownFields()` -- an extra `detail` key there is a hard decode failure,
the same class of gap as the missing-`profile` field (§8). Pending the entry-shape's
own ratification (which may add a wire `detail` once capsule-cli grows one to
match), a caller of this Python package directly (not through the wire) still gets
the full `CheckResult.detail` on every check.

## 3. The five generic checks

| Check | Recomputed from | Establishes |
|---|---|---|
| Chain consistency | — | always `not present`: a v2 Evidence Bundle carries exactly one `checkpoint` (the tip), never a checkpoint history, so there is nothing for this check to chain against |
| Range membership | `agent_action_capsule.bundle`'s `interval_coverage` / `per_record_membership` claims | real CLL #13 range-proof and per-record inclusion-proof verification against `bundle.checkpoint` — cryptographic, not merely structural |
| Cadence | — | always `not present`: the v2 bundle declares no attestation-window period for this check to bound record timestamps against |
| Key hygiene | — | always `not present`: an AAC Capsule record carries no per-record signer-key field for this check to recompute rotation against |
| Profile conformance | `action_type` present across records vs. the profile's policy-module coverage | every `action_type` has a policy-module check, or reads `not checked` |

**Scope, stated plainly ([countersign-whole-bundle-shape]):** three of the five
generic checks were originally designed around fields an ad-hoc, pre-reconciliation
bundle model invented (a `checkpoints[]` history, a declared `period`, a per-record
`signer_key_id`) that the donated wire shape simply does not carry. Each reads
`not present` for a v2 bundle, honestly, rather than inventing meaning the wire does
not have. Range membership gained real teeth in exchange: it used to be a
*structural* recompute only (position/count against the tip) because this codebase
had no MMR proof-verification primitives; now it delegates to the neutral
`agent_action_capsule.bundle` verifier, which does real CLL #13 range-proof and
per-record inclusion-proof cryptography. Its result is `inconclusive` (not a bare
`established`) whenever the bundle's checkpoint carries no independently-verifiable
COSE statement — the state a real `capsulectl`-produced bundle is in today (its
`checkpoint.statement` field is not yet the `cose` field this verifier authenticates
— an agent-action-capsule-side gap, out of this module's scope).

**Always excluded, by name, on every statement:** capture coverage (a
declared-count reconciliation, when present in the bundle, is its own named check
and stands alone) and outcome correctness (this module verifies structure,
sequence, and signatures — never the substance of a judgment).

## 4. Turning this module on

Two environment variables, both required:

```
CAPSULE_ANCHOR_REGISTRATION_POLICY=strict
CAPSULE_ANCHOR_COUNTERSIGN=1
```

Either alone leaves the witness's default (permissive) behavior untouched. With both
set, `POST /countersign/register` is mounted.

## 5. Registration policy — the trust anchor

**This is the part that makes a strict instance a Transparency Service in the
RFC 9943 sense, and the open witness surface is not one.** RFC 9943 §5.1.1.1
requires a Transparency Service to authenticate a Signed Statement's issuer under a
Registration Policy, and to publish that policy. This section is that publication.

Under `CAPSULE_ANCHOR_REGISTRATION_POLICY=strict`, every registration is checked
against exactly this, in order — anything failing any step is refused before the
recompute in §3 ever runs:

1. **Shape.** The submission's `bundle` parses as a well-formed v2 Evidence Bundle
   (`bundle_version: "2"`, `bundle_kind: "evidence-bundle/v2"`) carrying
   `completeness.payloads_mode: "none"` and no `disclosures` overlay. Anything with a
   payload present is refused by construction.
2. **Issuer check.** The countersign submission's own `requester.id` (never a bundle
   field — the v2 Evidence Bundle carries no issuer identity of its own) must be
   enrolled in this instance's own issuer allowlist (§6) — a trust anchor configured
   by whoever operates the instance. **The key checked against is always the one this
   instance's policy pins for that issuer, never a key the caller supplies alongside
   the request** — `requester.key_id` must equal the pinned key hex-for-hex. An
   unenrolled issuer is refused outright; there is no self-asserted-key fallback on
   this surface.
3. **Signature.** `requester_signature` over the bundle's digest (recomputed fresh
   from `bundle`'s own content via `agent_action_capsule.bundle.bundle_digest` — the
   v2 shape carries no digest field of its own, so there is no separate
   "declared vs. recomputed" step) must verify under the pinned key.
4. **Profile (optional).** If the submission names a `profile_id`, it must have a
   policy module registered with this instance, or the registration is refused. A
   submission that never names one (the v2 bundle carries no profile object of its
   own, and `capsulectl`'s current `countersignSubmission` wire shape has no
   `profile_id` field to send one with) still succeeds — the five generic checks
   only, no profile-specific coverage, never a refusal.

The witness's permissive surfaces (`/checkpoints`, `/register`) make none of these
claims and are not described as a Transparency Service by this module — they accept
a self-asserted key for any unenrolled identity, by design, and that design is
correct for what they are. Only an instance running under strict policy, with an
issuer allowlist actually configured, satisfies this section.

## 6. The issuer allowlist (trust anchor config)

A JSON array, one entry per enrolled issuer. `ledger_id` here is matched against a
countersign submission's own `requester.id` — never a bundle field:

```json
[
  { "ledger_id": "ledger:example-001", "pubkey_hex": "<64-hex, 32-byte Ed25519 public key>" }
]
```

Loaded from `CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE` if set, else empty. An empty
allowlist is a valid starting state — it refuses every registration, which is the
correct fail-closed default for a strict registration policy. A **present but
malformed** file fails startup closed, the same convention this codebase already
uses for the witness's enrolled checkpoint submitters.

## 7. The policy-module interface

```python
def check(bundle: Bundle, profile_id: str) -> list[CheckResult]: ...
```

Loaded by profile id. This module ships **no** implementations of this interface —
only `NullPolicyModule`, a test double that declares no coverage for any record
kind (every kind then reads `not checked` in profile conformance). A profile's
checks — what a record kind means, what its content must satisfy — are a separate
package, registered against a `PolicyRegistry` by whoever deploys an instance.
`profile_id` is a plain string (the submission's own `profile_id`), never a bundle
field — the v2 Evidence Bundle carries no profile object of its own.

## 8. The statement

```
{
  checks: [ {name, result}, ... ],   // {name, result, detail} internally (§2) --
                                      // the wire projection omits detail, see §2
  exclusions: [ ... ],           // always present, always names capture coverage
                                  // and outcome correctness explicitly
  scope: { ledger_id, closure_depth },
  recomputed_at,
}
```

`scope.ledger_id` is the countersign submission's own `requester.id`;
`scope.closure_depth` is read from the bundle's own `completeness.closure_depth`.
There is no `period` field: the v2 bundle declares no attestation window (the Go
wire's own `CountersignScope.Period` is already optional/`omitempty` for exactly this
reason — this instance simply never emits one).

**No `profile` field, ever ([countersign-whole-bundle-shape], found via the live
request-path round trip).** A prior revision carried one; `capsulectl`'s Go
`CountersignStatement` struct does not declare it, and the CLI's real request path
(`countersign request`, not `countersign verify`) decodes with
`json.Decoder.DisallowUnknownFields()` — an extra field anywhere in the decoded
entry, including nested inside `statement`, is a hard decode failure there. The
wire-shape reconciliation that landed as #47 never caught this: its own entry-interop
test decoded a committed fixture through `verifyCountersignatures`'s own lenient
`json.Unmarshal`, never through the strict `requestCountersignatures`/`decodeJSON`
path a real request actually takes — it proved the entry could be *read*, never that
a request could be *made*. A submission's own `profile_id` is never lost:
`profile_conformance`'s own `detail` string already names which `action_type`s
were/weren't covered.

Signed over its own canonical bytes (sorted-key, compact JSON — so any implementation
reproduces identical bytes from the same fields) by this instance's signing key, and
registered in this instance's own log to attach a receipt.

## 9. The `countersignatures[]` entry

```
{
  signer: { id, key_id },        // id is this instance's own did:web identity;
                                  // key_id is the full 32-byte Ed25519 public
                                  // key, hex-encoded (64 chars) -- never a
                                  // hash -- so a verifier holding only this
                                  // entry can check the signature offline
  over: <bundle digest>,
  statement: { ...the statement above... },
  signature,                     // over the UTF-8 bytes of `over`'s
                                  // 64-hex-character form, never over the
                                  // statement (which accompanies the
                                  // signature but is not what is signed)
  independent: <bool>,           // false iff the signer key equals the
                                  // countersign request's own requester key_id
                                  // -- never a bundle field, the v2 Evidence
                                  // Bundle carries no producer identity of its
                                  // own. A self-countersignature is
                                  // well-formed and never refused, only flagged.
                                  // Self-reported for this instance's own
                                  // bookkeeping; a verifier must never trust it
                                  // without recomputing independence itself
                                  // against the bundle's trusted producer keys.
  receipt: { receipt_b64, entry_hash, leaf_index, tree_size },
}
```

Per the wire-shape reconciliation with `capsule-cli`'s Go verifier
(action-state-ops [countersign-engine-in-capsule-anchor]): `key_id` is
deliberately NOT this repo's internal, truncated `sha256(pubkey)[:16]`
identifier used for the STH/receipt signing root elsewhere in this codebase —
that identifier never appears on this wire. The `type` field the spec's own
base Evidence Bundle draft reserves for `countersignatures[]` entries is an
open cross-lane question still with the spec desk; this module does not emit
one.

A verifier resolving this entry (see `countersign/verify.py`) reads one of five
states: `self-attested` (no entry, and the bundle's own checkpoint carries no
independently-authenticated evidence), `witnessed` (no entry, but the bundle's
checkpoint DOES carry an independently-authenticated COSE statement — the free,
permissive-policy grade), `self-countersigned` (`independent: false`),
`unresolved signer` (independent, but the signer's `key_id` is absent from whatever
countersigner directory the verifier consults), or `countersigned` (independent and
resolved). When `countersignatures[]` carries more than one entry, every entry is
considered and the best-resolved outcome wins (`countersigned` over
`unresolved signer` over `self-countersigned`) — a real, independent
countersignature is never hidden behind a later self-countersigned or unresolved
one.

## 10. Directory row (for a countersigner directory, if one is consulted)

**Resolution is by `signer.key_id`, never `signer.id`** — reconciled here per
[countersign-whole-bundle-shape]: this module previously resolved a directory by the
signer's `did:web` identity, a divergence from `capsule-cli`'s Go verifier
(`resolveSigner` matches a directory row's `key_ids[]`) that a real
cross-implementation lookup would have silently mismatched. A verifier resolving
`signer.key_id` against a public directory reads one row per enrolled signer,
matching the field list the spec item
`[bundle-countersignatures-entry-and-directory]` defines for `witnesses.json`'s
`countersigners[]` extension — same discipline as the witness directory, alphabetical,
one row per operator, a PR template for others:

```
{ name, endpoint, key_ids, statement_types_issued, since, independent_of }
```

`key_ids` is a list of full 64-hex Ed25519 public keys (not a single value) so a
directory row survives its operator's own key rotation without a stale entry, and so
it directly matches `countersignatures[].signer.key_id` — the same full-hex
convention the entry itself already uses. This module does not host or publish that
directory — it only produces entries a directory (and the verifier that reads one)
can resolve.

## 11. Delivery

`POST /countersign/register` always returns `{"countersignatures": [entry]}`
synchronously — matching `capsulectl countersign request`'s own
`countersignSubmissionResponse`, the wire shape `countersign request` expects back.
If a request also carries a webhook subscription, the same entry is additionally
delivered to that URL as a background task (never inline — a slow or unreachable
subscriber must never hold the response open), HMAC-signed over the JSON body, with
three retries on a 1s/4s/16s backoff.

## 12. Tests

`packages/tests/countersign/` builds genuinely self-consistent v2 Evidence Bundles
(real AAC Capsule records, real CLL #13 range/inclusion proofs via
`cll.checkpoint.core`) rather than hand-typed stand-ins, and exercises: a bundle with
any payload present, or carrying a `disclosures` overlay, is refused; a bundle that
isn't a v2 Evidence Bundle is refused; an unenrolled issuer, a requester key mismatch,
or a tampered signature is refused (content changed after signing fails to verify —
there is no separate "declared vs. recomputed digest" step); a submission naming an
unregistered `profile_id` is refused, while one that never names one still succeeds
(matching the real, unmodified `capsulectl` wire, proven end-to-end against a live
instance of this engine using capsule-cli's own real bundle-building and
request/verify code paths — transcript in `COUNTERSIGN_ROUNDTRIP_2026-09-17.md`;
capsule-cli itself is the read-only reference for this proof and carries no
permanent new test of its own from it); each of the five checks
reaches every reachable result with a mutant proving the negative path actually
flips (including `range_membership`'s real cryptographic failure on a corrupted body
digest); a self-countersignature is well-formed and flagged `independent: false`; an
entry with its signer's `key_id` absent from a directory resolves to
`unresolved signer` (and a directory keyed by the OLD `signer.id` convention does
NOT resolve it — the reconciliation itself, proven); a bundle with its
`countersignatures[]` entry removed, but a genuinely COSE-authenticated checkpoint,
resolves to `witnessed`.
