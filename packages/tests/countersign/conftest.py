"""Shared fixtures for the countersign test suite: a requester keypair and a
minimal, genuinely self-consistent v2 Evidence Bundle builder that tests
mutate from.

Every fixture bundle here is a REAL v2 Evidence Bundle -- real AAC Capsule
records (self-verifying under ``agent_action_capsule.verify.verify``), real
CLL #13 range/inclusion proofs (via ``cll.checkpoint.core``, the same
primitives ``checkpointed-local-log`` ships and
``agent_action_capsule.bundle.verify_bundle`` verifies against) -- not the
retired ad-hoc bundle model's hand-typed stand-ins. This is deliberate: a
fixture that only looks like a bundle can hide exactly the kind of shape
divergence [countersign-whole-bundle-shape] exists to fix.
"""

from __future__ import annotations

import base64

import pytest
from agent_action_capsule.bundle import bundle_digest
from agent_action_capsule.canonical import compute_capsule_id
from cll.checkpoint.core import add_leaf, inclusion_proof, leaf_hash, peaks, range_proof, root_from_peaks
from cll.checkpoint.cose_wire import checkpoint_to_cose
from cll.checkpoint.emit import CheckpointRecord
from cll.checkpoint.store import MemoryNodeStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from capsule_anchor.countersign.issuers import IssuerAllowlist

#: The ``requester.id`` every submission fixture in this file carries --
#: shared so ``issuer_allowlist`` enrolls the SAME identity ``requester_key``
#: signs a submission with.
TEST_LEDGER_ID = "ledger:test-001"


class RequesterKey:
    """The countersign REQUEST's own signing key -- the wire's
    ``requester.key_id`` (full 64-hex Ed25519 public key), never a bundle
    field: the v2 Evidence Bundle carries no producer/issuer identity of its
    own."""

    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.pubkey_hex = self.private.public_key().public_bytes_raw().hex()

    def sign_hex(self, data: bytes) -> str:
        return self.private.sign(data).hex()


@pytest.fixture()
def requester_key() -> RequesterKey:
    return RequesterKey()


@pytest.fixture()
def issuer_allowlist(requester_key: RequesterKey) -> IssuerAllowlist:
    """A registration-policy trust anchor enrolling ``requester_key`` under
    ``TEST_LEDGER_ID`` -- the issuer identity a submission fixture's
    ``requester.id`` carries."""
    return IssuerAllowlist.from_list([{"ledger_id": TEST_LEDGER_ID, "pubkey_hex": requester_key.pubkey_hex}])


def make_capsule(number: int, action_type: str = "decide") -> dict:
    """A minimal, genuinely self-verifying AAC Capsule record -- real enough
    to pass ``agent_action_capsule.verify.verify()``, the gate the neutral
    bundle verifier's own record ingestion requires before it will bind
    anything to a completeness proof."""
    capsule = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-04",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": f"countersign-test-{number}",
        "action_type": action_type,
        "operator": "TEST-OP",
        "developer": "agent@v1",
        "timestamp": f"2026-09-01T00:00:0{number}Z",
        "assurance": {
            "effect_mode": "not_applicable",
            "attestation_mode": "self_attested",
            "ledger_mode": "standalone",
        },
        "disposition": {
            "verdict_class": "blocked",
            "decision": "reject",
            "approver": "policy",
            "human_disposed": False,
        },
    }
    capsule["capsule_id"] = compute_capsule_id(capsule)
    return capsule


def _proof(p) -> dict:
    return {
        "v": p.v,
        "kind": p.kind,
        "size": p.size,
        "leaf_index": p.leaf_index,
        "witness": list(p.witness),
        "peaks_left": list(p.peaks_left),
        "peaks_right": list(p.peaks_right),
    }


class _CoseCheckpointSigner:
    """Minimal in-memory Ed25519 signer implementing just ``key_id`` +
    ``sign_cose_statement`` -- everything ``cll.checkpoint.cose_wire.
    checkpoint_to_cose`` needs from a signer, and nothing else. Mirrors
    checkpointed-local-log's own ``tests/checkpoint/conftest.py::
    Ed25519TestSigner`` (a test-only helper, not public API), reimplemented
    here rather than imported across a package boundary."""

    def __init__(self) -> None:
        self._private_key = Ed25519PrivateKey.generate()
        self.key_id = self._private_key.public_key().public_bytes_raw().hex()

    def sign_cose_statement(self, payload: bytes, *, content_type, issuer, subject, extra_cwt_claims=None) -> bytes:
        from scitt_cose.statement import build_signed_statement

        pem = self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        return build_signed_statement(
            payload,
            alg="EdDSA",
            private_key_pem=pem,
            issuer=issuer,
            subject=subject,
            content_type=content_type,
            extra_cwt_claims=extra_cwt_claims,
            kid=bytes.fromhex(self.key_id),
        )


def bundle_with_records(records: list[dict], *, authenticated_checkpoint: bool = False) -> dict:
    """Assemble a real v2 Evidence Bundle over ``records``: a genuine
    checkpoint and completeness certificate built from real CLL #13
    range/inclusion proofs.

    By default the checkpoint carries no ``cose`` field (this is the common
    case), so ``interval_coverage``/``per_record_membership`` always carry
    the honest ``checkpoint_unverified`` finding -- the same "structurally
    sound, checkpoint authenticity unconfirmed" state a real
    ``capsulectl``-produced bundle is in today (its ``checkpoint.statement``
    field is not yet the ``cose`` field this verifier authenticates -- an
    agent-action-capsule-side gap, out of this module's scope).

    ``authenticated_checkpoint=True`` additionally signs a genuine COSE
    checkpoint statement (``cll.checkpoint.cose_wire.checkpoint_to_cose``)
    over the same MMR state, proving the "fully verified" branch
    (``checkpoint_unverified`` absent) is reachable too -- not merely
    asserted.
    """
    nodes = MemoryNodeStore()
    for record in records:
        add_leaf(nodes, leaf_hash(bytes.fromhex(record["capsule_id"])))
    size = nodes.size()
    peak_hashes = [nodes.node(pos) for pos in peaks(size)]
    root_hash = root_from_peaks(peak_hashes)
    proofs = [inclusion_proof(nodes, index, size) for index in range(len(records))]
    range_p = range_proof(nodes, 0, len(records) - 1, size)
    certificate = {
        "log_id": TEST_LEDGER_ID,
        "range_root": root_hash.hex(),
        "first_seq": 1,
        "last_seq": len(records),
        "body_digests": [record["capsule_id"] for record in records],
        "range_proof": {
            "from_seq": 1,
            "to_seq": len(records),
            "size": size,
            "from_index": range_p.from_index,
            "to_index": range_p.to_index,
            "witness": list(range_p.witness),
        },
        "memberships": {
            record["capsule_id"]: {
                "log_coordinates": {"log_id": TEST_LEDGER_ID, "seq": index + 1, "leaf_index": index},
                "inclusion_proof": _proof(proofs[index]),
            }
            for index, record in enumerate(records)
        },
    }
    checkpoint = {"root": root_hash.hex(), "mmr_size": size}
    if authenticated_checkpoint:
        signer = _CoseCheckpointSigner()
        cp = CheckpointRecord(
            v=1,
            kind="mmr_checkpoint",
            log_id=TEST_LEDGER_ID,
            mmr_size=size,
            root=root_hash.hex(),
            prev_size=0,
            prev_root="",
            key_id=signer.key_id,
            timestamp="2026-09-01T00:00:00Z",
            signature="",
        )
        cose_bytes = checkpoint_to_cose(cp, signer, peak_hashes)
        checkpoint["cose"] = base64.urlsafe_b64encode(cose_bytes).rstrip(b"=").decode("ascii")
    root = records[-1]
    return {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": root["capsule_id"],
        "records": records,
        "completeness": {
            "closure_depth": 2,
            "records_mode": "complete",
            "payloads_mode": "none",
            "suppressed_fields": [],
            "missing": [],
        },
        "completeness_certificate": certificate,
        "checkpoint": checkpoint,
        "verification": {
            "producer": "test-fixture",
            "checks": ["graph_closure", "interval_coverage", "per_record_membership"],
        },
    }


def base_bundle_raw(record_count: int = 1, *, authenticated_checkpoint: bool = False) -> dict:
    """A minimal, structurally valid, genuinely self-consistent v2 Evidence
    Bundle with ``record_count`` real capsule records."""
    return bundle_with_records(
        [make_capsule(i + 1) for i in range(record_count)], authenticated_checkpoint=authenticated_checkpoint
    )


def sign_submission(
    bundle_raw: dict, key: RequesterKey, *, requester_id: str = TEST_LEDGER_ID
) -> tuple[str, str, str]:
    """Digest ``bundle_raw`` and sign it with ``key`` -- returns
    ``(requester_id, requester_key_hex, requester_signature_hex)``, the three
    values a countersign submission's ``requester``/``requester_signature``
    carry alongside the bundle itself (never fields ON the bundle -- the v2
    shape has no producer identity of its own)."""
    digest = bundle_digest(bundle_raw)
    signature = key.sign_hex(digest.encode("ascii"))
    return requester_id, key.pubkey_hex, signature


@pytest.fixture()
def valid_bundle_raw() -> dict:
    return base_bundle_raw()
