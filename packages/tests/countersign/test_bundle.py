"""accept_bundle: parse, payloads-none enforcement, digest binding, and the
registration-policy issuer check -- the key checked against is always the
one THIS instance's issuer allowlist pins for the requester id, never one a
caller supplies. Each negative case is a mutant of ``valid_bundle_raw`` -- the
fixture must accept cleanly (asserted first) so a broken mutant can't hide
behind a fixture that never worked."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capsule_anchor.countersign.bundle import Bundle, BundleRefused, accept_bundle, parse_bundle
from capsule_anchor.countersign.issuers import IssuerAllowlist

from .conftest import TEST_LEDGER_ID, sign_submission


def _accept(raw, issuer_allowlist, requester_key):
    rid, rkey, rsig = sign_submission(raw, requester_key)
    return accept_bundle(raw, issuer_allowlist, requester_id=rid, requester_key_hex=rkey, requester_signature_hex=rsig)


def test_valid_bundle_is_accepted(valid_bundle_raw, issuer_allowlist, requester_key):
    bundle = _accept(valid_bundle_raw, issuer_allowlist, requester_key)
    assert isinstance(bundle, Bundle)
    assert bundle.completeness["payloads_mode"] == "none"


def test_payloads_present_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    """A required case: any payload present -> refused."""
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["completeness"]["payloads_mode"] = "all"

    with pytest.raises(BundleRefused, match="payloads present"):
        parse_bundle(mutated)
    with pytest.raises(BundleRefused, match="payloads present"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_payloads_present_mutant_red_then_green(valid_bundle_raw, issuer_allowlist, requester_key):
    """The mutant check: flip the condition, confirm the check actually
    flips to failure, then restore and re-verify green."""

    # RED: mutate payloads_mode away from "none" -- must raise.
    red = copy.deepcopy(valid_bundle_raw)
    red["completeness"]["payloads_mode"] = "selected"
    with pytest.raises(BundleRefused):
        _accept(red, issuer_allowlist, requester_key)
    # GREEN: restore -- must accept.
    _accept(valid_bundle_raw, issuer_allowlist, requester_key)


def test_disclosures_present_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    """A payloads_mode:none bundle that ALSO carries a disclosures overlay
    is refused -- only a fully withheld bundle may be submitted."""

    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["disclosures"] = {}
    with pytest.raises(BundleRefused, match="disclosures"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_bad_bundle_version_or_kind_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["bundle_version"] = "1"
    with pytest.raises(BundleRefused, match="v2 Evidence Bundle"):
        _accept(mutated, issuer_allowlist, requester_key)

    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["bundle_kind"] = "evidence-bundle/v1"
    with pytest.raises(BundleRefused, match="v2 Evidence Bundle"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_missing_root_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    mutated = copy.deepcopy(valid_bundle_raw)
    del mutated["root"]
    with pytest.raises(BundleRefused, match="root"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_content_tampered_after_signing_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    """A requester's signature is over the digest at signing time -- if the
    bundle content changes afterward (even a field the requester didn't
    touch), the freshly recomputed digest no longer matches what was signed
    and the signature fails to verify. There is no separate 'declared vs
    recomputed digest' step: the v2 bundle carries no digest field of its
    own, so every acceptance recomputes it fresh."""

    rid, rkey, rsig = sign_submission(valid_bundle_raw, requester_key)
    tampered = copy.deepcopy(valid_bundle_raw)
    tampered["completeness"]["closure_depth"] = 99
    with pytest.raises(BundleRefused, match="does not verify"):
        accept_bundle(tampered, issuer_allowlist, requester_id=rid, requester_key_hex=rkey, requester_signature_hex=rsig)


def test_tampered_signature_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    rid, rkey, _ = sign_submission(valid_bundle_raw, requester_key)
    with pytest.raises(BundleRefused, match="does not verify"):
        accept_bundle(
            valid_bundle_raw, issuer_allowlist, requester_id=rid, requester_key_hex=rkey, requester_signature_hex="ff" * 64
        )


def test_unenrolled_issuer_is_refused(valid_bundle_raw, requester_key):
    """A requester id this instance's registration policy has never
    enrolled is refused -- there is no self-asserted-key fallback on this
    surface."""
    empty = IssuerAllowlist()
    with pytest.raises(BundleRefused, match="not enrolled"):
        _accept(valid_bundle_raw, empty, requester_key)


def test_issuer_pinned_to_a_different_key_is_refused(valid_bundle_raw, requester_key):
    """The allowlist enrolls TEST_LEDGER_ID, but under a key that is NOT the
    one that actually signed the submission -- refused on key mismatch,
    never falling back to whatever the requester claims."""
    other_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    mismatched = IssuerAllowlist.from_list([{"ledger_id": TEST_LEDGER_ID, "pubkey_hex": other_pub.hex()}])
    with pytest.raises(BundleRefused, match="does not match the key"):
        _accept(valid_bundle_raw, mismatched, requester_key)


def test_malformed_bundle_shape_is_refused():
    with pytest.raises(BundleRefused):
        parse_bundle({"not": "a bundle"})
    with pytest.raises(BundleRefused):
        parse_bundle("not even a dict")  # type: ignore[arg-type]
