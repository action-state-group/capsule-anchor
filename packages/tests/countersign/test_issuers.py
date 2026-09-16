"""IssuerAllowlist: the registration-policy trust anchor. Empty by default
(fail-closed -- nothing enrolled means everything refused), fails closed on
a malformed config rather than silently dropping bad entries."""

from __future__ import annotations

import json

import pytest

from capsule_anchor.countersign.issuers import IssuerAllowlist, IssuerConfigError

_GOOD_PUBKEY_HEX = "11" * 32


def test_empty_allowlist_resolves_nothing():
    allowlist = IssuerAllowlist()
    assert allowlist.get("ledger:anything") is None
    assert len(allowlist) == 0


def test_from_list_enrolls_by_ledger_id():
    allowlist = IssuerAllowlist.from_list(
        [{"ledger_id": "ledger:a", "pubkey_hex": _GOOD_PUBKEY_HEX}]
    )
    entry = allowlist.get("ledger:a")
    assert entry is not None
    assert entry.pubkey == bytes.fromhex(_GOOD_PUBKEY_HEX)
    assert allowlist.get("ledger:unknown") is None


def test_from_list_rejects_missing_field():
    with pytest.raises(IssuerConfigError, match="missing required field"):
        IssuerAllowlist.from_list([{"ledger_id": "ledger:a"}])


def test_from_list_rejects_bad_hex():
    with pytest.raises(IssuerConfigError, match="not valid hex"):
        IssuerAllowlist.from_list([{"ledger_id": "ledger:a", "pubkey_hex": "not-hex"}])


def test_from_list_rejects_wrong_length():
    with pytest.raises(IssuerConfigError, match="32 bytes"):
        IssuerAllowlist.from_list([{"ledger_id": "ledger:a", "pubkey_hex": "aa" * 16}])


def test_from_list_rejects_duplicate_ledger_id():
    with pytest.raises(IssuerConfigError, match="duplicate"):
        IssuerAllowlist.from_list(
            [
                {"ledger_id": "ledger:a", "pubkey_hex": _GOOD_PUBKEY_HEX},
                {"ledger_id": "ledger:a", "pubkey_hex": _GOOD_PUBKEY_HEX},
            ]
        )


def test_from_env_or_default_is_empty_when_unset(monkeypatch):
    monkeypatch.delenv("CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE", raising=False)
    allowlist = IssuerAllowlist.from_env_or_default()
    assert len(allowlist) == 0


def test_from_env_or_default_fails_closed_on_malformed_present_file(tmp_path, monkeypatch):
    bad_file = tmp_path / "issuers.json"
    bad_file.write_text(json.dumps({"not": "a list"}))
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE", str(bad_file))
    with pytest.raises(IssuerConfigError, match="must be a JSON array"):
        IssuerAllowlist.from_env_or_default()


def test_from_env_or_default_loads_a_valid_present_file(tmp_path, monkeypatch):
    good_file = tmp_path / "issuers.json"
    good_file.write_text(json.dumps([{"ledger_id": "ledger:a", "pubkey_hex": _GOOD_PUBKEY_HEX}]))
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE", str(good_file))
    allowlist = IssuerAllowlist.from_env_or_default()
    assert allowlist.get("ledger:a") is not None
