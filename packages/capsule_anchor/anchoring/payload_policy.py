"""What this Transparency Service keeps of a Signed Statement's embedded payload.

A transparency service keeps whatever a submitter embeds unless it decides not to, and RFC 9943
puts the privacy check on issuers (section 8.2) while leaving the registration policy to the
operator (section 5.1.1). This module is that policy for embedded payloads, applied when a
statement is registered on ``/transparency/register-statement``:

- A statement made over a HASH keeps its payload as submitted: the payload already is a digest.
  That is either the RFC 9943 section 6.2 hash envelope (protected header 258,
  ``payload_hash_alg``, with a payload of that algorithm's digest length), or the Agent Action
  Capsule convention of a 32-byte ``capsule_id`` under the content type
  ``application/vnd.agent-action-capsule.capsule-id+octet-stream``.
- Any other embedded payload is stored DETACHED: only its SHA-256 is kept (section 8.4), unless
  the operator opts in to keeping embedded payloads, and then only up to a size cap.

The receipt is unaffected either way: it covers the entry hash, the SHA-256 of the statement's
``Sig_structure``, which includes the payload and is computed when the statement is registered.
What a detached payload changes is who can re-check the statement's signature later: anyone
holding the statement from its issuer can; this service no longer holds the bytes to (section
5.1.3, replayability).

Configuration (fail-closed: a malformed value stops startup):

- ``CAPSULE_ANCHOR_STORE_EMBEDDED_PAYLOADS``: ``off`` (the default) or ``on``.
- ``CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES``: the cap for ``on``, a positive integer no larger
  than the statement size limit (default 1024). A larger payload is stored detached.

Existing rows are left as they were stored: this applies to new registrations only.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass

#: COSE algorithm identifiers for SHA-2 and their digest lengths (RFC 9054).
DIGEST_SIZES: dict[int, int] = {-16: 32, -43: 48, -44: 64}

#: Protected-header label of ``payload_hash_alg`` in the RFC 9943 section 6.2 hash envelope.
PAYLOAD_HASH_ALG = 258

#: COSE ``content type`` header label.
CONTENT_TYPE = 3

#: The Agent Action Capsule content type for a bare 32-byte ``capsule_id`` payload.
CAPSULE_ID_MEDIA_TYPE = "application/vnd.agent-action-capsule.capsule-id+octet-stream"

#: How a subject-index row's payload value was stored.
FORM_DIGEST = "digest"  # the statement was made over a hash: the payload as submitted
FORM_SHA256 = "sha256"  # an embedded payload stored detached: its SHA-256
FORM_EMBEDDED = "embedded"  # an embedded payload kept as submitted (operator opt-in, under the cap)

DEFAULT_MAX_BYTES = 1024

ENV_STORE = "CAPSULE_ANCHOR_STORE_EMBEDDED_PAYLOADS"
ENV_MAX_BYTES = "CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES"


@dataclass(frozen=True)
class EmbeddedPayloadPolicy:
    """The operator's registration policy for embedded payloads."""

    store_embedded: bool = False
    max_bytes: int = DEFAULT_MAX_BYTES

    def describe(self) -> dict:
        """The policy as published (``GET /transparency/registration-policy``, ``/health``)."""
        return {
            "digest_payloads": "kept as submitted (a statement made over a hash: RFC 9943 6.2 "
            "payload_hash_alg, or a 32-byte capsule_id under the AAC capsule-id content type)",
            "embedded_payloads": (
                f"kept as submitted up to {self.max_bytes} bytes; larger ones stored detached (SHA-256 only)"
                if self.store_embedded
                else "stored detached: only the payload's SHA-256 is kept"
            ),
            "store_embedded": self.store_embedded,
            "embedded_max_bytes": self.max_bytes if self.store_embedded else None,
            "resubmission_needs_issuer_payload": True,
        }


def policy_from_env(environ: Mapping[str, str] | None = None, *, statement_limit: int) -> EmbeddedPayloadPolicy:
    """Read the policy from the environment; a malformed value raises ``RuntimeError``."""
    env = os.environ if environ is None else environ
    raw = env.get(ENV_STORE, "off").strip().lower()
    if raw not in ("on", "off"):
        raise RuntimeError(f"{ENV_STORE} must be 'on' or 'off'; got {raw!r}")
    raw_max = env.get(ENV_MAX_BYTES, "").strip()
    max_bytes = DEFAULT_MAX_BYTES
    if raw_max:
        try:
            max_bytes = int(raw_max)
        except ValueError:
            raise RuntimeError(f"{ENV_MAX_BYTES} must be a positive integer; got {raw_max!r}") from None
        if not 0 < max_bytes <= statement_limit:
            raise RuntimeError(f"{ENV_MAX_BYTES} must be between 1 and {statement_limit}; got {max_bytes}")
    return EmbeddedPayloadPolicy(store_embedded=raw == "on", max_bytes=max_bytes)


def is_made_over_a_hash(protected: Mapping, payload: bytes) -> bool:
    """Whether the statement's payload is itself a digest (see the module docstring)."""
    alg = protected.get(PAYLOAD_HASH_ALG)
    if isinstance(alg, int) and not isinstance(alg, bool) and DIGEST_SIZES.get(alg) == len(payload):
        return True
    return protected.get(CONTENT_TYPE) == CAPSULE_ID_MEDIA_TYPE and len(payload) == 32


def stored_payload(
    protected: Mapping, payload: bytes | None, policy: EmbeddedPayloadPolicy
) -> tuple[str | None, str | None]:
    """The subject-index value for ``payload`` and how it was stored: ``(hex, form)``.

    ``(None, None)`` for a statement with no embedded payload (a detached-payload submission).
    """
    if payload is None:
        return None, None
    if is_made_over_a_hash(protected, payload):
        return payload.hex(), FORM_DIGEST
    if policy.store_embedded and len(payload) <= policy.max_bytes:
        return payload.hex(), FORM_EMBEDDED
    return hashlib.sha256(payload).hexdigest(), FORM_SHA256
