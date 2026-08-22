"""ECDSA signature malleability against the LIVE registration entry_hash.

An ECDSA signature is not a function of the act it signs: for any valid
``(r, s)``, ``(r, n-s)`` also verifies (SEC1 v2.0 SS4.1.3), and no private key
is needed to compute the twin from a public (payload, signature) pair. See
entry-identity-second-rule-sweep census: ``register_signed_statement`` /
``POST /transparency/register-statement`` computes
``entry_hash = SHA256(statement_bytes).hex()`` over the FULL COSE_Sign1
envelope (signature included), and that value is the dedup/idempotency key
("submitting the same bytes twice returns the original receipt" — the docstring
on ``register_statement``) and is returned to the caller as an entry
identifier.

This was measured, not argued: two malleated encodings of ONE signing act used
to register as TWO distinct entries.

capsule-anchor is a LIVE public service (anchor.agentactioncapsule.org).
Changing entry_hash's derivation changes what every past registration's
identifier means — a data-migration question, not a code fix — so this test
was deliberately left ``xfail(strict=True)`` rather than "fixed" until the
``## Needs decision`` entry resolved.

**FIXED (entry-identity-second-rule-sweep Option 1, bundled into
anchor-peaks-endpoint):** ``entry_hash`` now derives from the RFC9052 SS4.4
``Sig_structure`` (excludes the signature field) when the submitted bytes are
a parseable COSE_Sign1 with an embedded payload -- see
``compute_entry_hash``/``register_signed_statement_full`` in ``service.py``.
The xfail mark is dropped; this is now a plain, must-pass assertion. A
dual-lookup window keeps statements registered under the old (legacy,
full-envelope) scheme resolving as the SAME entry after this migration --
see ``test_dual_lookup_window`` in ``test_checkpoint_witness.py``.
"""
from __future__ import annotations

import base64

import cbor2
import pytest
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from fastapi.testclient import TestClient

# NIST P-256 (secp256r1) group order (SEC2 SS2.4.2).
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

_COSE_ALG_ES256 = -7
_COSE_SIGN1_TAG = 18


def _sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    """RFC 9052 SS4.4 Sig_structure for COSE_Sign1 with external_aad == b""."""
    return cbor2.dumps(["Signature1", protected_bstr, b"", payload])


def _build_statement_and_twin(payload: bytes, key: ec.EllipticCurvePrivateKey) -> tuple[bytes, bytes]:
    """Build a COSE_Sign1 ES256 statement over ``payload`` and its malleated twin.

    Both signatures are verified against the same key + payload before
    returning, so the twin is a REAL malleated signature, not a synthetic
    stand-in — same Sig_structure, same validity, different signature bytes.
    """
    protected_bstr = cbor2.dumps({1: _COSE_ALG_ES256})
    tbs = _sig_structure(protected_bstr, payload)

    der = key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    s_twin = _P256_N - s
    der_twin = encode_dss_signature(r, s_twin)

    pub = key.public_key()
    pub.verify(der, tbs, ec.ECDSA(hashes.SHA256()))
    pub.verify(der_twin, tbs, ec.ECDSA(hashes.SHA256()))
    assert s != s_twin, "malleation produced no change — test setup is broken"

    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_twin = r.to_bytes(32, "big") + s_twin.to_bytes(32, "big")
    assert sig != sig_twin

    statement = cbor2.dumps(
        cbor2.CBORTag(_COSE_SIGN1_TAG, [protected_bstr, {}, payload, sig])
    )
    statement_twin = cbor2.dumps(
        cbor2.CBORTag(_COSE_SIGN1_TAG, [protected_bstr, {}, payload, sig_twin])
    )
    return statement, statement_twin


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


def _register(client, statement_bytes: bytes) -> dict:
    resp = client.post(
        "/transparency/register-statement",
        json={"signed_statement_b64": base64.b64encode(statement_bytes).decode("ascii")},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_malleated_twin_registers_as_same_entry(client):
    """One signing act must yield one entry_hash — currently FAILS (2 entries)."""
    key = ec.generate_private_key(ec.SECP256R1())
    payload = b"a" * 32  # a capsule_id-shaped 32-byte payload

    statement, statement_twin = _build_statement_and_twin(payload, key)
    assert statement != statement_twin  # different envelope bytes, same act

    original = _register(client, statement)
    twin = _register(client, statement_twin)

    assert original["entry_hash"] == twin["entry_hash"]


def test_negative_control_different_payload_is_a_different_entry(client):
    """A genuinely different act (1-bit payload change) MUST produce a
    different entry_hash — without this, the assertion above would also
    pass for a constant function and prove nothing."""
    key = ec.generate_private_key(ec.SECP256R1())
    payload_a = b"a" * 32
    payload_b = b"b" + b"a" * 31  # one-byte change

    statement_a, _ = _build_statement_and_twin(payload_a, key)
    statement_b, _ = _build_statement_and_twin(payload_b, key)

    entry_a = _register(client, statement_a)
    entry_b = _register(client, statement_b)

    assert entry_a["entry_hash"] != entry_b["entry_hash"]
