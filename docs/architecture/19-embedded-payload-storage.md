# 19 — Embedded payloads: stored detached, and why receipts are unaffected

This document describes `packages/capsule_anchor/anchoring/payload_policy.py`: what the
service keeps of a Signed Statement's embedded payload when the statement is registered on
`POST /transparency/register-statement` under a CWT `sub`. It also explains why a receipt
verifies the same whichever way the payload is kept. It follows RFC 9943, which leaves the
registration policy to the operator (§5.1.1) and puts the privacy check on issuers (§8.2).

---

## 1. The policy

| The statement | Kept in the subject index | `payload_form` |
|---|---|---|
| made over a hash: the §6.2 hash envelope (protected header 258 `payload_hash_alg` = SHA-256, SHA-384 or SHA-512, with a payload of that digest's length), or a 32-byte `capsule_id` under `application/vnd.agent-action-capsule.capsule-id+octet-stream` | the payload as submitted (it is a digest) | `digest` |
| any other embedded payload (the default) | only its SHA-256 (§8.4): the payload is stored detached | `sha256` |
| any other embedded payload, with `CAPSULE_ANCHOR_STORE_EMBEDDED_PAYLOADS=on` and within `CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES` (default 1024) | the payload as submitted | `embedded` |

- **Look-alikes are not trusted.** These are all stored as `sha256`:
  - a payload of 32 bytes with no marker;
  - header 258 with the wrong length;
  - header 258 with an unknown algorithm.
- **Why the capsule-id convention counts as made over a hash.** Adjudication-witness
  discovery registers the adjudication capsule's `capsule_id` that way and reads it back
  from `GET /transparency/statements`. Hashing it would break that discovery.
- **Rows registered before this policy** keep what was stored then; their `payload_form`
  is `null`. Nothing is rewritten: the policy applies to new registrations only.

`GET /transparency/registration-policy` publishes this policy for the running instance,
together with what it stores and what leaves it. `/health` carries `embedded_payloads`
(`detached` or `as_submitted_up_to_cap`).

## 2. Why receipts are unaffected

- **What a receipt covers:** the entry hash. For a well-formed COSE_Sign1 that is
  `SHA-256(Sig_structure)` (RFC 9052 §4.4): the protected header, an empty external AAD
  and the payload, i.e. the bytes the issuer signed.
- **When it is computed:** the service computes the entry hash from the submitted
  statement at registration, before anything is stored. The value the subject index keeps
  afterwards never enters it.
- **So for a relying party:** holding the statement and its receipt, it verifies the
  receipt offline exactly as before. It recomputes the entry hash from the statement and
  checks the inclusion proof and the service's signature.

**What does change: who can re-check the statement itself.** Recomputing the entry hash,
or verifying the issuer's signature, needs the payload. With the payload stored detached,
the relying party gets the statement, payload included, from its issuer, not from this
service (§5.1.3). The service never served statement bytes (its receipt cache holds
receipts only), so no existing verification path read them from here.

## 3. How this was checked

Three statements were registered through the application in-process, with an ephemeral key
and an in-memory store:

- (a) an embedded JSON payload;
- (b) a §6.2 statement made over a hash of the same JSON;
- (c) a 32-byte capsule-id statement.

Each receipt was verified offline with three verifiers:

- `scitt_cose.verify_receipt` (scitt-cose 0.4.0);
- `cll.checkpoint.emit.verify_receipt_offline` (checkpointed-local-log 0.4.1);
- `capsule_emit.checkpoint.verify_receipt_offline` (capsule-emit 0.8.6).

Each receipt was also bound to its statement by recomputing the entry hash from the
statement's `Sig_structure`.

| Statement | Before this policy: subject index kept | After: subject index kept | Receipt verifies (all three), before and after |
|---|---|---|---|
| (a) embedded JSON | the JSON bytes themselves (hex) | the JSON's SHA-256 (`sha256`) | yes |
| (b) made over a hash | the digest | the digest (`digest`), equal to (a)'s value after | yes |
| (c) capsule-id | the `capsule_id` | the `capsule_id` (`digest`) | yes |

The same check runs in the test suite:
`packages/tests/test_embedded_payload_policy.py::test_receipts_verify_offline_for_a_detached_payload_and_a_statement_over_a_hash`.

## 4. For issuers

- **Submit a statement made over a hash** (§6.2): put the digest in the payload, set
  protected header 258 to the hash algorithm, and keep the preimage yourself.
- **A statement with an embedded payload still registers.** By default the service keeps
  only its SHA-256, so keep the statement, payload included, to hand to whoever checks it.
- **Check before you submit** whether the operator keeps embedded payloads
  (`GET /transparency/registration-policy`).
