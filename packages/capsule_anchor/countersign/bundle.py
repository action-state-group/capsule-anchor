# SPDX-License-Identifier: Apache-2.0
"""The withheld bundle this module accepts.

An Evidence Bundle produced with ``payloads: none`` -- every record's
header, digest, and sequence position, the checkpoints and witness
receipts covering the window, and no payload content -- signed by the
producer's own ledger key over the bundle's own digest. This module does
not own that wire format; it is a separate, versioned spec (see the
``bundle-countersignatures-entry-and-directory`` item). What is here is the
minimal shape the five generic checks need, and it refuses
(``BundleRefused``) anything that does not parse into it -- INCLUDING,
always, a bundle that is not payload-free.
"""

from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, Field, ValidationError

from capsule_anchor.countersign.issuers import IssuerAllowlist


class BundleRefused(ValueError):
    """The submitted bundle is refused outright: malformed shape, payloads
    present, or a producer signature that does not verify. None of these
    ever reach the recompute step -- a refused bundle is never scored."""


class BundlePeriod(BaseModel):
    from_: str = Field(alias="from")
    to: str

    model_config = {"populate_by_name": True}


class BundleProfile(BaseModel):
    id: str
    version: str


class BundleRecord(BaseModel):
    """One CLL record's header as carried by a payload-free bundle --
    digest and position only, never content."""

    seq: int
    kind: str
    digest: str  # hex sha256 of the (withheld) payload
    timestamp: str | None = None
    signer_key_id: str | None = None
    # e.g. the method_freeze digest a judgment record cites -- unused by the
    # five generic checks today, carried through for a profile module.
    cites: str | None = None


class BundleRotationRecord(BaseModel):
    seq: int
    old_key_id: str | None = None
    new_key_id: str


class BundleCheckpoint(BaseModel):
    log_id: str
    key_id: str
    mmr_size: int
    prev_size: int
    mmr_root: str
    timestamp: str


class BundleReceipt(BaseModel):
    """One witness's receipt over one of ``bundle.checkpoints``, by index."""

    checkpoint_index: int
    witness_id: str  # did:web:<host>
    grade: str | None = None
    receipt_b64: str


class Bundle(BaseModel):
    schema_: str = Field(alias="schema")
    payloads: str
    ledger_id: str
    period: BundlePeriod
    closure_depth: int
    profile: BundleProfile
    records: list[BundleRecord] = Field(default_factory=list)
    rotations: list[BundleRotationRecord] = Field(default_factory=list)
    checkpoints: list[BundleCheckpoint] = Field(default_factory=list)
    receipts: list[BundleReceipt] = Field(default_factory=list)
    digest: str  # hex sha256 over the canonical bundle bytes (excludes this field + the signature)
    producer_key_id: str
    producer_signature: str  # hex Ed25519 signature over bytes.fromhex(digest)

    model_config = {"populate_by_name": True}


def parse_bundle(raw: dict) -> Bundle:
    """Parse ``raw`` into a :class:`Bundle`, refusing anything that isn't a
    well-formed, payload-free bundle. Never verifies the producer signature
    -- see :func:`accept_bundle` for the full acceptance path."""
    try:
        bundle = Bundle.model_validate(raw)
    except ValidationError as exc:
        raise BundleRefused(f"bundle does not parse: {exc}") from exc
    if bundle.payloads != "none":
        raise BundleRefused(
            f"bundle carries payloads={bundle.payloads!r} -- this module accepts only a "
            "withheld bundle (payloads: none); any bundle with payloads present is refused "
            "by construction"
        )
    return bundle


def compute_bundle_digest(bundle: Bundle) -> str:
    """Recompute the bundle digest independently from its own content --
    every field except ``digest`` and ``producer_signature`` themselves,
    canonical JSON (sorted keys, compact separators), sha256 hex.

    ``by_alias=True`` is required: this bundle's wire form uses ``schema``
    and ``from`` (see the ``Field(alias=...)`` declarations above), and a
    dump keyed on the Python-safe attribute names (``schema_``, ``from_``)
    would silently diverge from what any other implementation -- a
    producer in another language, or a verifier reading the wire JSON
    directly -- canonicalizes over.

    Never trust ``bundle.digest`` as handed to us: a party under test could
    sign a valid signature over an arbitrary string and call it the digest.
    Recomputing it from the content the recompute step actually reads is
    what binds the signature to what gets checked.
    """
    payload = bundle.model_dump(mode="json", by_alias=True, exclude={"digest", "producer_signature"})
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_producer_signature(bundle: Bundle, producer_pubkey: bytes) -> bool:
    """Verify ``bundle.producer_signature`` over ``bundle.digest`` under the
    raw 32-byte Ed25519 ``producer_pubkey``. Returns False on any malformed
    input rather than raising -- callers decide how to report a refusal."""
    try:
        Ed25519PublicKey.from_public_bytes(producer_pubkey).verify(
            bytes.fromhex(bundle.producer_signature), bytes.fromhex(bundle.digest)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def accept_bundle(raw: dict, issuers: IssuerAllowlist) -> Bundle:
    """The full acceptance path -- this instance's registration policy:

    1. Parse, refusing anything that isn't a well-formed, payload-free bundle.
    2. Recompute the digest independently; require it match the declared one.
    3. Resolve the issuer: ``bundle.ledger_id`` must be enrolled in
       ``issuers`` (see ``issuers.py``). The key checked against is the ONE
       this instance's registration policy pins for that ledger -- never a
       key the caller supplies alongside the bundle. An unenrolled ledger is
       refused; there is no self-asserted-key fallback on this surface.
    4. ``producer_key_id`` on the bundle must equal ``sha256(pinned pubkey)[:16]``
       hex -- the same key-id derivation this repo already uses (see
       ``signing_key.StaticKeyProvider``) -- so a bundle cannot claim an
       identity the pinned key doesn't match.
    5. Verify the producer's signature over the (confirmed) digest under the
       pinned key.
    """
    bundle = parse_bundle(raw)
    recomputed = compute_bundle_digest(bundle)
    if recomputed != bundle.digest:
        raise BundleRefused(
            f"declared digest {bundle.digest!r} does not match the digest recomputed from "
            f"the bundle's own content ({recomputed!r})"
        )
    entry = issuers.get(bundle.ledger_id)
    if entry is None:
        raise BundleRefused(
            f"issuer {bundle.ledger_id!r} is not enrolled with this instance's registration "
            "policy -- registration is refused for any ledger this instance has not been "
            "configured to trust"
        )
    expected_key_id = hashlib.sha256(entry.pubkey).hexdigest()[:16]
    if expected_key_id != bundle.producer_key_id:
        raise BundleRefused(
            f"bundle producer_key_id={bundle.producer_key_id!r} does not match the key "
            f"this instance's registration policy pins for issuer {bundle.ledger_id!r}"
        )
    if not verify_producer_signature(bundle, entry.pubkey):
        raise BundleRefused("producer_signature does not verify under the issuer's pinned key")
    return bundle
