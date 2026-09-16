# SPDX-License-Identifier: Apache-2.0
"""The statement signer: signs the recomputed statement over the bundle
digest, registers the signing act in this instance's own log (reusing the
existing digest-registration path -- the same one ``POST /register``
already uses, ``AnchorerService.register_signed_statement_full``) to attach
a receipt, and assembles the ``countersignatures[]`` entry.

Self-countersignature -- the signer key equals the bundle's own producer
key -- is well-formed and is never refused, but is flagged
``independent: false`` so a verifier never mistakes an operator vouching for
its own bundle as a second party's check.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Protocol

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.statement import Statement


class Attestor(Protocol):
    """The subset of ``attestation.AttestorService`` this module needs."""

    def attest(self, payload: bytes): ...

    @property
    def key_id(self) -> str: ...


class Registrar(Protocol):
    """The subset of ``anchoring.AnchorerService`` this module needs."""

    def register_signed_statement_full(self, statement_bytes: bytes): ...


def _hex_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_countersignature(
    bundle: Bundle,
    statement: Statement,
    *,
    attestor: Attestor,
    registrar: Registrar,
    signer_id: str,
) -> dict:
    """Sign ``statement`` and return the ``countersignatures[]`` entry.

    ``signer_id`` is this instance's own identity string (its
    ``did:web:<host>``, matching the identity already published at
    ``/.well-known/did.json``) -- passed in rather than constructed here so
    this module never reads deployment config directly.
    """
    signer_key_id = attestor.key_id
    independent = signer_key_id != bundle.producer_key_id

    statement_bytes = statement.canonical_bytes()
    sig = attestor.attest(statement_bytes)

    # Registering the statement's own digest (not the statement bytes
    # themselves) keeps the receipt's CT-log leaf a fixed-size digest,
    # matching every other digest-registration path this service already
    # exposes (POST /register).
    statement_digest = _hex_sha256(statement_bytes)
    reg = registrar.register_signed_statement_full(bytes.fromhex(statement_digest))

    return {
        "signer": {"id": signer_id, "key_id": signer_key_id},
        "over": bundle.digest,
        "statement": statement.model_dump(mode="json", by_alias=True),
        "signature": sig.signature,
        "independent": independent,
        "receipt": {
            "receipt_b64": base64.b64encode(reg.receipt).decode("ascii"),
            "entry_hash": reg.entry_hash,
            "leaf_index": reg.leaf_index,
            "tree_size": reg.tree_size,
        },
    }
