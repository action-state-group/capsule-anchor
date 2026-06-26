# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- **GitHub:** use *Security → Report a vulnerability* on this repository
  (GitHub private vulnerability reporting), or
- **Email:** security@actionstate.ai with `[capsule-anchor security]` in the
  subject.

Please do not open a public issue for a suspected vulnerability. We aim to
acknowledge reports within 72 hours.

## Scope (highest-priority classes)

- **Content leakage on the anchor path.** The service MUST accept only digests
  and COSE_Sign1 Signed Statements — never operator or payload content. Any
  path that stores or returns raw business content is the **highest-priority**
  issue.
- **Receipt forgery.** A COSE Receipt that verifies against the authority
  public key but was not issued by the service, or an inclusion proof that
  passes verification for a leaf not in the CT log.
- **CT log tampering.** Any mechanism that allows a log entry to be silently
  removed, reordered, or modified after the fact — the log is append-only by
  design.
- **Key compromise.** Exposure of the Ed25519 authority private key (the
  `CAPSULE_ANCHOR_SIGNING_KEY` value) allows forging receipts for any digest.
  Report immediately; treat as critical.
- **Digest / canonicalization issues.** A collision or canonicalization mismatch
  that lets two different inputs share an `entry_hash` or `leaf_index`.
- **Parser / resource issues** in the CBOR/COSE receipt path or the CT log
  (memory-safety, resource exhaustion, denial of service).

## Out of scope

Verification logic lives in the separate
[`agent-action-capsule`](https://github.com/action-state-group/agent-action-capsule)
package — report verifier bypasses there. Ambiguities or honest-but-misleading
prose about standards status are not security issues — raise those as public
issues or on the SCITT mailing list.

## Supported versions

The latest released version receives fixes.
