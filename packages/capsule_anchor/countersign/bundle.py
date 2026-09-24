# SPDX-License-Identifier: Apache-2.0
"""The withheld bundle this module accepts.

The canonical AAC Evidence Bundle (``draft-mih-zhang-agent-action-capsule-
evidence-bundle-00``, wire ``bundle_version: "2"`` / ``bundle_kind:
"evidence-bundle/v2"``) -- the exact shape ``capsulectl bundle`` produces --
carrying ``completeness.payloads_mode: "none"`` and no ``disclosures``
overlay: every record's full content withheld to digests, checkpoints, and
completeness proofs only. This module does not own that wire format -- it is
the donated spec's own bundle shape, codec'd and verified by the neutral
``agent_action_capsule.bundle`` reference library (never reimplemented here:
a second JCS/MMR implementation in this repo is exactly the divergence that
made the prior ad-hoc bundle model reject 100% of ``capsulectl``'s real
output). This module refuses
(``BundleRefused``) anything that does not parse into a well-formed v2
bundle -- INCLUDING, always, a bundle that is not payload-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING, Any

from agent_action_capsule.bundle import BundleVerificationResult, bundle_digest, verify_bundle

if TYPE_CHECKING:
    from capsule_anchor.countersign.issuers import IssuerAllowlist


class BundleRefused(ValueError):
    """The submitted bundle is refused outright: malformed shape, payloads
    present, or a producer signature that does not verify. None of these
    ever reach the recompute step -- a refused bundle is never scored."""


@dataclass(frozen=True)
class Bundle:
    """A parsed, payload-free v2 Evidence Bundle.

    Wraps the bundle exactly as received (``raw``) -- the neutral library's
    digest and verification functions operate on that dict directly, never
    on a re-serialized copy, so nothing this module does can silently drift
    from what ``capsulectl`` (or any other implementation) canonicalizes.
    ``digest`` is computed once at parse time via
    ``agent_action_capsule.bundle.bundle_digest`` and is this module's own
    convenience cache -- it is not a bundle wire field (the v2 shape carries
    no digest field of its own; a verifier always recomputes it).
    """

    raw: dict
    digest: str

    @cached_property
    def root(self) -> str | None:
        value = self.raw.get("root")
        return value if isinstance(value, str) else None

    @cached_property
    def records(self) -> list[dict]:
        value = self.raw.get("records")
        return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []

    @cached_property
    def completeness(self) -> dict:
        value = self.raw.get("completeness")
        return value if isinstance(value, dict) else {}

    @cached_property
    def completeness_certificate(self) -> dict | None:
        value = self.raw.get("completeness_certificate")
        return value if isinstance(value, dict) else None

    @cached_property
    def checkpoint(self) -> dict | None:
        value = self.raw.get("checkpoint")
        return value if isinstance(value, dict) else None

    @cached_property
    def countersignatures(self) -> list[Any]:
        value = self.raw.get("countersignatures")
        return value if isinstance(value, list) else []

    @cached_property
    def closure_depth(self) -> int:
        depth = self.completeness.get("closure_depth", 2)
        return depth if isinstance(depth, int) and not isinstance(depth, bool) else 2

    @cached_property
    def verification(self) -> BundleVerificationResult:
        """The neutral library's full structural + completeness verdict
        (graph closure, CLL #13 range proof, per-record inclusion proof) --
        computed once and cached, since both ``checks.range_membership`` and
        ``verify.resolve_entry_state`` read it."""
        return verify_bundle(self.raw)


def parse_bundle(raw: dict) -> Bundle:
    """Parse ``raw`` into a :class:`Bundle`, refusing anything that isn't a
    well-formed, payload-free v2 Evidence Bundle. Never verifies a
    requester's signature -- see :func:`accept_bundle` for the full
    acceptance path."""
    if not isinstance(raw, dict):
        raise BundleRefused("bundle must be a JSON object")
    if raw.get("bundle_version") != "2" or raw.get("bundle_kind") != "evidence-bundle/v2":
        raise BundleRefused(
            f"bundle_version={raw.get('bundle_version')!r} bundle_kind={raw.get('bundle_kind')!r} "
            '-- this module accepts only a v2 Evidence Bundle (bundle_version: "2", '
            'bundle_kind: "evidence-bundle/v2")'
        )
    if not isinstance(raw.get("root"), str):
        raise BundleRefused("bundle does not parse: missing or non-string root")
    completeness = raw.get("completeness")
    if not isinstance(completeness, dict):
        raise BundleRefused("bundle does not parse: missing completeness")
    payloads_mode = completeness.get("payloads_mode")
    if payloads_mode != "none":
        raise BundleRefused(
            f"bundle carries payloads present (completeness.payloads_mode={payloads_mode!r}) -- "
            "this module accepts only a withheld bundle (payloads_mode: none); any bundle with "
            "payloads present is refused by construction"
        )
    if "disclosures" in raw:
        raise BundleRefused(
            "bundle carries a disclosures overlay -- only a withheld (payloads_mode none) bundle "
            "may be submitted for countersigning"
        )
    try:
        digest = bundle_digest(raw)
    except (TypeError, ValueError) as exc:
        raise BundleRefused(f"bundle digest could not be computed: {exc}") from exc
    return Bundle(raw=raw, digest=digest)


def compute_bundle_digest(bundle: Bundle) -> str:
    """Recompute the bundle digest independently from its own content,
    delegating to the neutral library's JCS canonicalization -- the same
    function ``capsulectl``'s Go verifier's ``BundleDigest`` agrees with (see
    ``TestCountersignBundleAgreesWithPythonVerifier`` on the capsule-cli
    side). Never trust a caller-supplied digest: this always recomputes from
    ``bundle.raw`` itself."""
    return bundle_digest(bundle.raw)


def accept_bundle(
    raw: dict,
    issuers: "IssuerAllowlist",
    *,
    requester_id: str,
    requester_key_hex: str,
    requester_signature_hex: str,
) -> Bundle:
    """The full acceptance path -- this instance's registration policy:

    1. Parse, refusing anything that isn't a well-formed, payload-free v2
       Evidence Bundle.
    2. Resolve the issuer: ``requester_id`` (the countersign request's own
       ``requester.id``, never a bundle field -- the v2 bundle carries no
       issuer identity of its own) must be enrolled in ``issuers`` (see
       ``issuers.py``). The key checked against is the ONE this instance's
       registration policy pins for that issuer -- never a key the caller
       supplies alongside the bundle.
    3. ``requester_key_hex`` must equal the pinned key, hex-for-hex (the full
       32-byte Ed25519 public key -- the same full-hex convention the
       ``countersignatures[]`` entry's own ``signer.key_id`` already uses,
       per the entry-shape reconciliation) -- so a request cannot claim an
       identity the pinned key doesn't match.
    4. Verify ``requester_signature_hex`` over the (confirmed) digest under
       the pinned key.
    """
    bundle = parse_bundle(raw)
    entry = issuers.get(requester_id)
    if entry is None:
        raise BundleRefused(
            f"issuer {requester_id!r} is not enrolled with this instance's registration "
            "policy -- registration is refused for any issuer this instance has not been "
            "configured to trust"
        )
    if entry.pubkey.hex() != requester_key_hex.lower():
        raise BundleRefused(
            f"requester key_id={requester_key_hex!r} does not match the key this instance's "
            f"registration policy pins for issuer {requester_id!r}"
        )
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(entry.pubkey).verify(
            bytes.fromhex(requester_signature_hex), bundle.digest.encode("ascii")
        )
    except (InvalidSignature, ValueError) as exc:
        raise BundleRefused("requester_signature does not verify under the issuer's pinned key") from exc
    return bundle
