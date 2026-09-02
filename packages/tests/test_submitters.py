# SPDX-License-Identifier: Apache-2.0
"""Unit tests for ``submitters.SubmitterAllowlist`` config parsing --
independent of the HTTP layer (see
``test_checkpoints_and_register_witness_host.py`` for end-to-end coverage of
how an enrolled entry changes ``/checkpoints`` behavior)."""
from __future__ import annotations

import json

import pytest
from capsule_anchor.anchoring.submitters import (
    ACCUMULATOR_FOREIGN,
    ACCUMULATOR_NATIVE_MMR,
    DEFAULT_SUBMITTER_RATE_LIMIT_PER_MIN,
    GRADE_COUNTERSIGNED_OBSERVED,
    GRADE_MMR_VERIFIED,
    WIRE_FORM_COSE_SIGN1,
    WIRE_FORM_JSON_ED25519,
    SubmitterAllowlist,
    SubmitterConfigError,
)

_VALID_HEX = "bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90"


def test_empty_list_yields_empty_allowlist():
    allowlist = SubmitterAllowlist.from_list([])
    assert len(allowlist) == 0
    assert allowlist.get("anything") is None


def test_foreign_entry_grades_countersigned_observed():
    allowlist = SubmitterAllowlist.from_list(
        [{"log_id": "trace-registry/v1", "pubkey_hex": _VALID_HEX, "accumulator": ACCUMULATOR_FOREIGN}]
    )
    entry = allowlist.get("trace-registry/v1")
    assert entry.grade == GRADE_COUNTERSIGNED_OBSERVED
    assert entry.rate_limit_per_min == DEFAULT_SUBMITTER_RATE_LIMIT_PER_MIN


def test_native_mmr_entry_grades_mmr_verified():
    allowlist = SubmitterAllowlist.from_list(
        [{"log_id": "our-log", "pubkey_hex": _VALID_HEX, "accumulator": ACCUMULATOR_NATIVE_MMR}]
    )
    assert allowlist.get("our-log").grade == GRADE_MMR_VERIFIED


def test_accumulator_defaults_to_foreign_when_omitted():
    """Absent accumulator is treated as the MORE CONSERVATIVE (not
    over-claiming) case -- foreign/countersigned-observed, never silently
    assumed to be our own verified MMR."""
    allowlist = SubmitterAllowlist.from_list([{"log_id": "x", "pubkey_hex": _VALID_HEX}])
    assert allowlist.get("x").accumulator == ACCUMULATOR_FOREIGN


def test_log_id_containing_slash_round_trips():
    allowlist = SubmitterAllowlist.from_list(
        [{"log_id": "trace-registry/v1", "pubkey_hex": _VALID_HEX}]
    )
    assert allowlist.get("trace-registry/v1") is not None
    assert allowlist.get("trace-registry") is None


@pytest.mark.parametrize(
    "entry",
    [
        {"pubkey_hex": _VALID_HEX},
        {"log_id": "x"},
        {"log_id": "", "pubkey_hex": _VALID_HEX},
        {"log_id": "x", "pubkey_hex": "not-hex"},
        {"log_id": "x", "pubkey_hex": "ab"},  # too short (1 byte, not 32)
        {"log_id": "x", "pubkey_hex": _VALID_HEX + "ab"},  # too long
        {"log_id": "x", "pubkey_hex": _VALID_HEX, "accumulator": "quantum"},
        {"log_id": "x", "pubkey_hex": _VALID_HEX, "rate_limit_per_min": 0},
        {"log_id": "x", "pubkey_hex": _VALID_HEX, "rate_limit_per_min": -5},
        {"log_id": "x", "pubkey_hex": _VALID_HEX, "rate_limit_per_min": "60"},
    ],
)
def test_malformed_entry_fails_closed(entry):
    with pytest.raises(SubmitterConfigError):
        SubmitterAllowlist.from_list([entry])


def test_duplicate_log_id_fails_closed():
    with pytest.raises(SubmitterConfigError, match="duplicate"):
        SubmitterAllowlist.from_list(
            [
                {"log_id": "x", "pubkey_hex": _VALID_HEX},
                {"log_id": "x", "pubkey_hex": _VALID_HEX},
            ]
        )


def test_load_rejects_non_array_json(tmp_path):
    path = tmp_path / "submitters.json"
    path.write_text(json.dumps({"not": "a list"}))
    with pytest.raises(SubmitterConfigError, match="array"):
        SubmitterAllowlist.load(path)


def test_from_env_or_default_absent_file_is_empty_not_an_error(tmp_path, monkeypatch):
    missing = tmp_path / "does-not-exist.json"
    monkeypatch.setenv("CAPSULE_ANCHOR_CHECKPOINT_SUBMITTERS_FILE", str(missing))
    with pytest.raises(FileNotFoundError):
        # An EXPLICIT override pointing at a missing file is a real
        # misconfiguration (unlike the unset-env in-package-default path) --
        # fails loudly, not silently empty.
        SubmitterAllowlist.from_env_or_default()


def test_from_env_or_default_loads_override_file(tmp_path, monkeypatch):
    path = tmp_path / "submitters.json"
    path.write_text(json.dumps([{"log_id": "y", "pubkey_hex": _VALID_HEX}]))
    monkeypatch.setenv("CAPSULE_ANCHOR_CHECKPOINT_SUBMITTERS_FILE", str(path))
    allowlist = SubmitterAllowlist.from_env_or_default()
    assert allowlist.get("y") is not None


# --- wire_form / field_map (per-entry DECLARED checkpoint wire form) ---------


def test_wire_form_defaults_to_cose_with_no_field_map():
    allowlist = SubmitterAllowlist.from_list([{"log_id": "x", "pubkey_hex": _VALID_HEX}])
    entry = allowlist.get("x")
    assert entry.wire_form == WIRE_FORM_COSE_SIGN1
    assert entry.field_map is None


def test_json_ed25519_wire_form_gets_identity_field_map_by_default():
    allowlist = SubmitterAllowlist.from_list(
        [{"log_id": "x", "pubkey_hex": _VALID_HEX, "wire_form": WIRE_FORM_JSON_ED25519}]
    )
    entry = allowlist.get("x")
    assert entry.wire_form == WIRE_FORM_JSON_ED25519
    assert entry.field_map == {
        "v": "v",
        "kind": "kind",
        "log_id": "log_id",
        "mmr_size": "mmr_size",
        "root": "root",
        "prev_size": "prev_size",
        "prev_root": "prev_root",
        "key_id": "key_id",
        "timestamp": "timestamp",
        "signature": "signature",
    }


def test_json_ed25519_wire_form_with_partial_field_map_overrides_only_named_keys():
    allowlist = SubmitterAllowlist.from_list(
        [
            {
                "log_id": "x",
                "pubkey_hex": _VALID_HEX,
                "wire_form": WIRE_FORM_JSON_ED25519,
                "field_map": {"log_id": "registryId", "root": "mmrRoot"},
            }
        ]
    )
    fm = allowlist.get("x").field_map
    assert fm["log_id"] == "registryId"
    assert fm["root"] == "mmrRoot"
    assert fm["mmr_size"] == "mmr_size"  # untouched keys stay identity-mapped


def test_invalid_wire_form_fails_closed():
    with pytest.raises(SubmitterConfigError, match="wire_form"):
        SubmitterAllowlist.from_list([{"log_id": "x", "pubkey_hex": _VALID_HEX, "wire_form": "yaml"}])


def test_field_map_on_a_cose_entry_fails_closed():
    """field_map is only meaningful for json-ed25519 -- a cose entry that
    sets one is a config mistake that would otherwise be silently ignored,
    which fails closed instead."""
    with pytest.raises(SubmitterConfigError, match="field_map"):
        SubmitterAllowlist.from_list(
            [
                {
                    "log_id": "x",
                    "pubkey_hex": _VALID_HEX,
                    "wire_form": WIRE_FORM_COSE_SIGN1,
                    "field_map": {"log_id": "registryId"},
                }
            ]
        )


def test_field_map_unknown_canonical_field_fails_closed():
    with pytest.raises(SubmitterConfigError, match="unknown canonical field"):
        SubmitterAllowlist.from_list(
            [
                {
                    "log_id": "x",
                    "pubkey_hex": _VALID_HEX,
                    "wire_form": WIRE_FORM_JSON_ED25519,
                    "field_map": {"not_a_real_field": "whatever"},
                }
            ]
        )


def test_field_map_duplicate_target_key_fails_closed():
    """Two canonical fields reading from the SAME submitted key would be
    ambiguous (which one wins?) -- fails closed rather than picking one
    silently."""
    with pytest.raises(SubmitterConfigError, match="distinct"):
        SubmitterAllowlist.from_list(
            [
                {
                    "log_id": "x",
                    "pubkey_hex": _VALID_HEX,
                    "wire_form": WIRE_FORM_JSON_ED25519,
                    "field_map": {"log_id": "same_key", "root": "same_key"},
                }
            ]
        )


def test_field_map_non_string_value_fails_closed():
    with pytest.raises(SubmitterConfigError, match="non-empty string"):
        SubmitterAllowlist.from_list(
            [
                {
                    "log_id": "x",
                    "pubkey_hex": _VALID_HEX,
                    "wire_form": WIRE_FORM_JSON_ED25519,
                    "field_map": {"log_id": 5},
                }
            ]
        )
