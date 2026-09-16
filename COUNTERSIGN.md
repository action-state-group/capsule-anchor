# Countersign — an independent recompute over a withheld bundle

This document describes the `countersign/` module in this codebase: an additive,
opt-in extension to the witness that recomputes a set of generic, structural checks
over a *withheld* evidence bundle and returns a signed statement. Anyone can run one
— the module ships no product-specific policy, no branding, and no vocabulary beyond
what is defined here.

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
next to its own name and a `detail` string naming the thing that makes it true.

## 3. The five generic checks

| Check | Recomputed from | Establishes |
|---|---|---|
| Chain consistency | the bundle's own checkpoint sequence | each checkpoint extends the one before it (`prev_size` chains, `mmr_size` strictly increases) — the same peak-consistency rule this codebase's checkpoint-aware witness path already applies live, reapplied here blind over a bundle instead of against store state |
| Range membership | record sequence positions against the final checkpoint's `mmr_size` | no interior sequence position is missing or duplicated within the committed range, tip-aligned |
| Cadence | record timestamps against the bundle's declared period | records are not all batched at the window's close |
| Key hygiene | signer-key changes across records vs. rotation records | every key change has a matching rotation record |
| Profile conformance | record kinds present vs. the profile's policy-module coverage | every record kind has a policy-module check, or reads `not checked` |

**Scope, stated plainly:** range membership here is a *structural* recompute
(position and count against the tip), not a cryptographic per-leaf Merkle
audit-path verification — that requires MMR proof-verification primitives that do
not live in this codebase today. Chain consistency recomputes peak monotonicity
only, not a full MMR peak proof. Neither check claims more than this.

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

1. **Shape.** The submission parses as a well-formed, payload-free bundle
   (`payloads: none`). Anything with a payload present is refused by construction.
2. **Digest binding.** The bundle's declared digest is recomputed independently from
   its own content and must match.
3. **Issuer check.** The bundle's `ledger_id` (its issuer identity) must be enrolled
   in this instance's own issuer allowlist (§6) — a trust anchor configured by
   whoever operates the instance. **The key checked against is always the one this
   instance's policy pins for that issuer, never a key the caller supplies alongside
   the bundle.** An unenrolled issuer is refused outright; there is no
   self-asserted-key fallback on this surface.
4. **Signature.** The producer's signature over the (confirmed) digest must verify
   under the pinned key.
5. **Profile.** The bundle's resolved profile id must have a policy module
   registered with this instance, or the registration is refused.

The witness's permissive surfaces (`/checkpoints`, `/register`) make none of these
claims and are not described as a Transparency Service by this module — they accept
a self-asserted key for any unenrolled identity, by design, and that design is
correct for what they are. Only an instance running under strict policy, with an
issuer allowlist actually configured, satisfies this section.

## 6. The issuer allowlist (trust anchor config)

A JSON array, one entry per enrolled issuer:

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
def check(bundle: Bundle, profile: BundleProfile) -> list[CheckResult]: ...
```

Loaded by profile id. This module ships **no** implementations of this interface —
only `NullPolicyModule`, a test double that declares no coverage for any record
kind (every kind then reads `not checked` in profile conformance). A profile's
checks — what a record kind means, what its content must satisfy — are a separate
package, registered against a `PolicyRegistry` by whoever deploys an instance.

## 8. The statement

```
{
  checks: [ {name, result, detail}, ... ],
  exclusions: [ ... ],           // always present, always names capture coverage
                                  // and outcome correctness explicitly
  scope: { ledger_id, period, closure_depth },
  profile: { id, version },
  recomputed_at,
}
```

Signed over its own canonical bytes (sorted-key, compact JSON, alias field names —
so any implementation reproduces identical bytes from the same fields) by this
instance's signing key, and registered in this instance's own log to attach a
receipt.

## 9. The `countersignatures[]` entry

```
{
  signer: { id, key_id },        // id is this instance's own did:web identity
  over: <bundle digest>,
  statement: { ...the statement above... },
  signature,
  independent: <bool>,           // false iff the signer key equals the bundle's
                                  // own producer key -- a self-countersignature is
                                  // well-formed and never refused, only flagged
  receipt: { receipt_b64, entry_hash, leaf_index, tree_size },
}
```

A verifier resolving this entry (see `countersign/verify.py`) reads one of four
states: `self-attested` (no entry, no witness receipt), `witnessed` (no entry, but
the bundle carries a witness receipt), `self-countersigned` (`independent: false`),
`unresolved signer` (independent, but the signer id is absent from whatever
countersigner directory the verifier consults), or `countersigned` (independent and
resolved).

## 10. Directory row (for a countersigner directory, if one is consulted)

A verifier resolving `signer.id` against a public directory reads one row per
enrolled signer:

```
{ id, key_id, name, logo_url, website }
```

`id` matches `countersignatures[].signer.id` exactly (a `did:web:` string). This
module does not host or publish that directory — it only produces entries a
directory (and the verifier that reads one) can resolve.

## 11. Delivery

The entry is always returned synchronously in the `POST /countersign/register`
response. If a request also carries a webhook subscription, the same entry is
additionally delivered to that URL as a background task (never inline — a slow or
unreachable subscriber must never hold the response open), HMAC-signed over the
JSON body, with three retries on a 1s/4s/16s backoff.

## 12. Tests

`packages/tests/countersign/` exercises: a bundle with any payload present is
refused; an unenrolled issuer is refused; a tampered digest or signature is refused;
each of the five checks reaches every reachable result with a mutant proving the
negative path actually flips; a self-countersignature is well-formed and flagged
`independent: false`; an entry with its signer absent from a directory resolves to
`unresolved signer`; a bundle with its `countersignatures[]` entry removed, but a
witness receipt present, resolves to `witnessed`.
