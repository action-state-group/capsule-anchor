"""accept_bundle: parse, payloads-none enforcement, digest binding, and the
registration-policy issuer check -- the key checked against is always the
one THIS instance's issuer allowlist pins for the bundle's ledger_id, never
one a caller supplies. Each negative case is a mutant of ``valid_bundle_raw``
-- the fixture must accept cleanly (asserted first) so a broken mutant can't
hide behind a fixture that never worked."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capsule_anchor.countersign.bundle import Bundle, BundleRefused, accept_bundle, parse_bundle
from capsule_anchor.countersign.issuers import IssuerAllowlist

from .conftest import TEST_LEDGER_ID


def test_valid_bundle_is_accepted(valid_bundle_raw, issuer_allowlist):
    bundle = accept_bundle(valid_bundle_raw, issuer_allowlist)
    assert isinstance(bundle, Bundle)
    assert bundle.payloads == "none"


def test_payloads_present_is_refused(valid_bundle_raw, issuer_allowlist):
    """A required case: any payload present -> refused."""
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["payloads"] = "all"
    with pytest.raises(BundleRefused, match="payloads present"):
        parse_bundle(mutated)
    with pytest.raises(BundleRefused, match="payloads present"):
        accept_bundle(mutated, issuer_allowlist)


def test_payloads_present_mutant_red_then_green(valid_bundle_raw, issuer_allowlist):
    """The mutant check: flip the condition, confirm the
    check actually flips to failure, then restore and re-verify green."""
    # RED: mutate payloads away from "none" -- must raise.
    red = copy.deepcopy(valid_bundle_raw)
    red["payloads"] = "some"
    with pytest.raises(BundleRefused):
        accept_bundle(red, issuer_allowlist)
    # GREEN: restore -- must accept.
    accept_bundle(valid_bundle_raw, issuer_allowlist)


def test_tampered_digest_is_refused(valid_bundle_raw, issuer_allowlist):
    """A bundle whose declared digest doesn't match its own recomputed
    content digest is refused -- the signature alone is not enough."""
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["closure_depth"] = 99  # content changes, digest field stays stale
    with pytest.raises(BundleRefused, match="does not match"):
        accept_bundle(mutated, issuer_allowlist)


def test_tampered_signature_is_refused(valid_bundle_raw, issuer_allowlist):
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["producer_signature"] = "ff" * 64
    with pytest.raises(BundleRefused, match="does not verify"):
        accept_bundle(mutated, issuer_allowlist)


def test_unenrolled_issuer_is_refused(valid_bundle_raw):
    """A ledger_id this instance's registration policy has never enrolled
    is refused -- there is no self-asserted-key fallback on this surface."""
    empty = IssuerAllowlist()
    with pytest.raises(BundleRefused, match="not enrolled"):
        accept_bundle(valid_bundle_raw, empty)


def test_issuer_pinned_to_a_different_key_is_refused(valid_bundle_raw):
    """The allowlist enrolls TEST_LEDGER_ID, but under a key that is NOT
    the one that actually signed the bundle -- refused on key mismatch,
    never falling back to whatever the bundle itself claims."""
    other_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    mismatched = IssuerAllowlist.from_list(
        [{"ledger_id": TEST_LEDGER_ID, "pubkey_hex": other_pub.hex()}]
    )
    with pytest.raises(BundleRefused, match="does not match the key"):
        accept_bundle(valid_bundle_raw, mismatched)


def test_malformed_bundle_shape_is_refused():
    with pytest.raises(BundleRefused):
        parse_bundle({"not": "a bundle"})
