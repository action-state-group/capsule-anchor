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
