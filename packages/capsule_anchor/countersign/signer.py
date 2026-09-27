# SPDX-License-Identifier: Apache-2.0
"""The statement signer: signs the bundle digest together with the
recomputed statement (see :func:`countersign_signing_input`), registers the
statement in this instance's own log (reusing the
existing digest-registration path -- the same one ``POST /register``
already uses, ``AnchorerService.register_signed_statement_full``) to attach
a receipt, and assembles the ``countersignatures[]`` entry.

Self-countersignature -- the signer key equals the requester's own key -- is
well-formed and is never refused, but is flagged ``independent: false`` so a
verifier never mistakes an operator vouching for its own bundle as a second
party's check.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Protocol

from agent_action_capsule.canonical import jcs

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.statement import Statement


class StatementRefused(ValueError):
    """The statement has no JCS form, so it cannot be signed or registered --
    for example a string holding a lone surrogate, which has no UTF-8
    encoding. A caller error, refused before anything is signed or logged."""


class Attestor(Protocol):
    """The subset of ``attestation.AttestorService`` this module needs."""

    def attest(self, payload: bytes): ...

    @property
    def key_id(self) -> str: ...

    def authority_pubkey(self) -> bytes: ...


class Registrar(Protocol):
    """The subset of ``anchoring.AnchorerService`` this module needs."""

    def register_signed_statement_full(self, statement_bytes: bytes): ...


def _hex_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# The wire type of the countersignatures[] entry this engine emits, matching
# capsulectl's own ``countersignAPI`` const (internal/cli/countersign.go) --
# required by the AAC Evidence Bundle -00 spec's registered "type" field.
COUNTERSIGN_ENTRY_TYPE = "countersign/v1"


def countersign_signing_input(over: str, statement: dict, entry_type: str = COUNTERSIGN_ENTRY_TYPE) -> bytes:
    """The bytes a ``countersign/v1`` signature covers:
    ``UTF8(JCS({"over": over, "statement": statement, "type": type}))``.

    ``statement`` is the entry's wire ``statement`` member exactly as it is
    put on the wire (``Statement.wire_dict()``). Signing the digest alone
    would leave every check result unauthenticated: anyone holding the
    bundle could rewrite ``failed`` as ``established`` and the signature
    would still verify. Binding ``over``, ``statement`` and ``type`` in one
    JCS object makes any change to any of them break the signature.
    """
    return jcs({"over": over, "statement": statement, "type": entry_type})


def sign_countersignature(
    bundle: Bundle,
    statement: Statement,
    *,
    attestor: Attestor,
    registrar: Registrar,
    signer_id: str,
    requester_key_id: str,
) -> dict:
    """Sign ``statement`` and return the ``countersignatures[]`` entry.

    ``signer_id`` is this instance's own identity string (its
    ``did:web:<host>``, matching the identity already published at
    ``/.well-known/did.json``) -- passed in rather than constructed here so
    this module never reads deployment config directly. ``requester_key_id``
    is the countersign request's own ``requester.key_id`` (full 64-hex
    Ed25519 public key) -- never a bundle field: the v2 Evidence Bundle
    carries no producer identity of its own, so independence is judged
    against who asked, not against anything the bundle content declares.

    Wire-shape note (per the countersign wire-shape reconciliation): the
    entry's ``signer.key_id`` is the full 32-byte Ed25519 public key, hex
    encoded (64 chars) -- self-contained and offline-verifiable by any
    verifier that only has the entry, never a truncated hash. This is
    deliberately NOT ``attestor.key_id`` (this repo's internal, truncated
    ``sha256(pubkey)[:16]`` identifier used elsewhere -- e.g. the STH/receipt
    signing root -- which stays untouched so the live witness/checkpoint
    path never changes shape).
    """
    signer_pubkey = attestor.authority_pubkey()
    signer_key_id = signer_pubkey.hex()
    independent = signer_key_id.lower() != requester_key_id.lower()

    # The signature covers the bundle digest AND the statement (and the
    # entry type), never the digest alone -- see countersign_signing_input.
    wire_statement = statement.wire_dict()
    try:
        signing_input = countersign_signing_input(bundle.digest, wire_statement)
        statement_bytes = statement.canonical_bytes()
    except (TypeError, ValueError) as exc:
        raise StatementRefused(f"statement cannot be canonicalized (JCS): {type(exc).__name__}") from exc
    sig = attestor.attest(signing_input)

    # The receipt registers the STATEMENT's own digest -- SHA-256 of its JCS
    # bytes (never the bundle digest, and never the statement bytes
    # themselves) -- a fixed-size digest leaf, matching every other
    # digest-registration path this service already exposes (POST
    # /register). A verifier recomputes it from the entry's ``statement``.
    statement_digest = _hex_sha256(statement_bytes)
    reg = registrar.register_signed_statement_full(bytes.fromhex(statement_digest))

    return {
        "type": COUNTERSIGN_ENTRY_TYPE,
        "signer": {"id": signer_id, "key_id": signer_key_id},
        "over": bundle.digest,
        "statement": wire_statement,
        "signature": sig.signature,
        "independent": independent,
        "receipt": {
            "receipt_b64": base64.b64encode(reg.receipt).decode("ascii"),
            "entry_hash": reg.entry_hash,
            "leaf_index": reg.leaf_index,
            "tree_size": reg.tree_size,
        },
    }
