# SPDX-License-Identifier: Apache-2.0
"""The withheld bundle this module accepts.

The canonical AAC Evidence Bundle (``draft-mih-zhang-agent-action-capsule-
evidence-bundle-00``, wire ``bundle_version: "2"`` / ``bundle_kind:
"evidence-bundle/v2"``) -- the exact shape ``capsulectl bundle`` produces --
carrying ``completeness.payloads_mode: "none"`` or ``"selected"``: every
record's full content withheld to digests, checkpoints, and completeness
proofs only. ``selected`` is what capsule-cli and capsulectl write for a
withheld bundle with records (the draft allows either and requires ``none``
for an empty history), and is accepted only when it discloses nothing at all. The one exception, for ``none`` only, is a holder's opt-in ``disclosures`` overlay of the ``agent_input``
of the record kinds the deployer lists as disclosable (``config.disclosable_kinds``,
empty by default), checked against the digest each record sealed. This module does not own that wire format -- it is
the donated spec's own bundle shape, codec'd and verified by the neutral
``agent_action_capsule.bundle`` reference library (never reimplemented here:
a second JCS/MMR implementation in this repo is exactly the divergence that
made the prior ad-hoc bundle model reject 100% of ``capsulectl``'s real
output -- see [countersign-whole-bundle-shape]). This module refuses
(``BundleRefused``) anything that does not parse into a well-formed v2
bundle -- INCLUDING, always, a bundle that is not payload-free apart from that overlay.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING, Any

from agent_action_capsule.bundle import BundleVerificationResult, bundle_digest, verify_bundle
from agent_action_capsule.canonical import json_digest

if TYPE_CHECKING:
    from capsule_anchor.countersign.issuers import IssuerAllowlist


_DISCLOSABLE_MEMBER = "agent_input"
_SEALED_DIGEST_PATH = ("model_attestation", "compute_attestation", "agent_input_digest")


class BundleRefused(ValueError):
    """The submitted bundle is refused outright: malformed shape, payloads
    present, or a producer signature that does not verify. None of these
    ever reach the recompute step -- a refused bundle is never scored."""


@dataclass(frozen=True)
class Bundle:
    """A parsed, withheld v2 Evidence Bundle.

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


def parse_bundle(raw: dict, *, disclosable_kinds: frozenset[str] = frozenset()) -> Bundle:
    """Parse ``raw`` into a :class:`Bundle`, refusing anything that isn't a
    well-formed, withheld v2 Evidence Bundle: ``payloads_mode`` ``none``, plus
    at most an opt-in disclosure of ``agent_input``
    payloads of ``disclosable_kinds``, empty by default; or ``payloads_mode``
    ``selected`` disclosing nothing (see :func:`_check_selected_withheld`). Never verifies a
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
    if payloads_mode == "selected":
        _check_selected_withheld(raw)
    elif payloads_mode != "none":
        raise BundleRefused(
            f"bundle carries payloads present (completeness.payloads_mode={payloads_mode!r}) -- "
            "this module accepts only a withheld bundle (payloads_mode: none, or selected with "
            "nothing disclosed); any bundle with payloads present is refused by construction"
        )
    elif "disclosures" in raw:
        _check_disclosures(raw, disclosable_kinds)
    try:
        digest = bundle_digest(raw)
    except (TypeError, ValueError) as exc:
        raise BundleRefused(f"bundle digest could not be computed: {exc}") from exc
    return Bundle(raw=raw, digest=digest)


#: The members a ``payloads_mode: "selected"`` bundle may carry here: the
#: Evidence Bundle v2 members that hold no payload material (the draft's
#: Evidence Bundle Object). ``disclosures`` and ``disclosure_record`` are not
#: among them, so nothing a record withholds can be revealed.
_SELECTED_MEMBERS = frozenset(
    {
        "bundle_version",
        "bundle_kind",
        "root",
        "records",
        "completeness",
        "completeness_certificate",
        "checkpoint",
        "category_coverage",
        "verification",
        "extensions",
        "countersignatures",
    }
)

#: The extension kinds a ``selected`` bundle may carry: the producer's key
#: declaration, which capsule-cli's digests-only bundle and capsulectl's deal
#: withheld form both write. Any other kind is
#: refused, since some carry payloads (``composed/v1`` nests whole member
#: bundles, disclosures included).
_SELECTED_EXTENSIONS = frozenset({"producer-key/v1"})
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}")


def _check_selected_withheld(raw: dict) -> None:
    """Refuse a ``payloads_mode: "selected"`` bundle unless it discloses
    nothing. A withheld bundle with records may state ``none`` or
    ``selected`` (the draft requires ``none`` only for an empty history); the
    AAC Python reference builder, capsule-cli's digests-only bundle and
    capsulectl's ``deal report --withheld`` write ``selected``. It is accepted here only with no
    ``disclosures`` (not even an empty overlay), no ``disclosure_record``, no
    member outside :data:`_SELECTED_MEMBERS` and no extension outside
    :data:`_SELECTED_EXTENSIONS`, whose one block has exactly the draft's
    shape. This closes every place the draft defines for payload material;
    it cannot show that a producer hid nothing in a free-form value such as
    ``verification``, which is the producer's own statement."""
    extra = sorted(set(raw) - _SELECTED_MEMBERS)
    if extra:
        raise BundleRefused(
            f"a payloads_mode: selected bundle may disclose nothing here, but it carries {extra}"
        )
    extensions = raw.get("extensions", {})
    if not isinstance(extensions, dict):
        raise BundleRefused("extensions must be an object")
    kinds = sorted(set(extensions) - _SELECTED_EXTENSIONS)
    if kinds:
        raise BundleRefused(
            f"a payloads_mode: selected bundle may carry only the {sorted(_SELECTED_EXTENSIONS)} "
            f"extension here, but it carries {kinds}"
        )
    # The draft's producer-key/v1 block is exactly one 64-lowercase-hex
    # public_key, and a producer MUST NOT add other members; anything else
    # in it could carry what the bundle withholds.
    if "producer-key/v1" in extensions:
        block = extensions["producer-key/v1"]
        key = block.get("public_key") if isinstance(block, dict) else None
        if not (
            isinstance(key, str) and _LOWER_HEX_64.fullmatch(key) and set(block) == {"public_key"}
        ):
            raise BundleRefused(
                'the producer-key/v1 extension must be exactly {"public_key": <64 lowercase hex>}'
            )


def _check_disclosures(raw: dict, disclosable_kinds: frozenset[str]) -> None:
    """Refuse any ``disclosures`` overlay that is not an opt-in disclosure of
    the ``agent_input`` of records of a ``disclosable_kinds`` kind, each
    matching the digest its record sealed. Nothing else may ride along, so a
    policy module never receives any other payload."""
    overlay = raw["disclosures"]
    if not isinstance(overlay, dict):
        raise BundleRefused("disclosures must be an object keyed by capsule_id")
    records = raw.get("records")
    by_id = {
        r["capsule_id"]: r
        for r in (records if isinstance(records, list) else [])
        if isinstance(r, dict) and isinstance(r.get("capsule_id"), str)
    }
    for capsule_id, members in overlay.items():
        record = by_id.get(capsule_id)
        if record is None:
            raise BundleRefused(f"disclosures names {capsule_id!r}, which is not a record in the bundle")
        kind = record.get("action_type")
        if not isinstance(kind, str) or kind not in disclosable_kinds:
            raise BundleRefused(
                f"disclosures[{capsule_id}] discloses a {kind!r} record; only "
                f"{sorted(disclosable_kinds)} payloads may be disclosed to a countersigner"
            )
        if not isinstance(members, dict) or set(members) != {_DISCLOSABLE_MEMBER}:
            raise BundleRefused(
                f"disclosures[{capsule_id}] must carry exactly the {_DISCLOSABLE_MEMBER!r} member"
            )
        sealed: Any = record
        for part in _SEALED_DIGEST_PATH:
            sealed = sealed.get(part) if isinstance(sealed, dict) else None
        if not isinstance(sealed, str):
            raise BundleRefused(f"disclosures[{capsule_id}]: the record seals no agent_input_digest")
        try:
            disclosed = json_digest(members[_DISCLOSABLE_MEMBER])
        except (TypeError, ValueError) as exc:
            raise BundleRefused(f"disclosures[{capsule_id}] payload cannot be digested: {exc}") from exc
        if disclosed != sealed:
            raise BundleRefused(
                f"disclosures[{capsule_id}] payload does not match the agent_input_digest sealed in the record"
            )


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
    disclosable_kinds: frozenset[str] = frozenset(),
) -> Bundle:
    """The full acceptance path -- this instance's registration policy:

    1. Parse, refusing anything that isn't a well-formed, withheld v2
       Evidence Bundle (see :func:`parse_bundle`).
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
    bundle = parse_bundle(raw, disclosable_kinds=disclosable_kinds)
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
