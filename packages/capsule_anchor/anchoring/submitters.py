# SPDX-License-Identifier: Apache-2.0
"""Config-driven allowlist for NAMED external CLL checkpoint submitters on
``POST /checkpoints``.

``/checkpoints`` (see ``checkpoint_cose.py`` / ``router.py``) was built as a
fully open existence-timestamp surface: any COSE_Sign1 checkpoint verifying
under its OWN self-asserted ``kid`` gets counter-signed, for any ``log_id``
(CWT ``iss``) -- this stays TRUE and UNCHANGED for every ``log_id`` that has
no entry here. That default-open behavior is what a default ``capsule-emit``
client relies on and is deliberately not gated by this module.

Enrolling a NAMED external log (e.g. a partner's own trace registry) is a
narrower, additive claim: for that SPECIFIC ``log_id``, the witness PINS the
verification key to a config-provisioned value, so a stranger can no longer
mint a stamp for someone else's enrolled identity just by self-signing with
an arbitrary key and claiming that ``iss`` (see
``checkpoint_cose.parse_and_verify_checkpoint_cose``, which uses this
allowlist to decide whose key to trust for a given ``iss``).

NOT a signup system and NOT open enrollment -- entries are added by a
committed config change + deploy (`_ops/QUEUE_PROTOCOL.md`), one per external
partner, never hand-edited on the box.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

#: A submitter's commitment scheme is either OUR OWN CLL MMR (peaks-and-root,
#: fully understood by this witness) or a FOREIGN accumulator this witness
#: cannot independently verify -- it only observes, timestamps, and publishes
#: the submitted commitment bytes. See the grade constants below.
ACCUMULATOR_NATIVE_MMR = "native_mmr"
ACCUMULATOR_FOREIGN = "foreign"
_VALID_ACCUMULATORS = (ACCUMULATOR_NATIVE_MMR, ACCUMULATOR_FOREIGN)

#: A submitter's DECLARED checkpoint wire form -- what ``POST /checkpoints``
#: dispatches a submission from this ``log_id`` as. ``cose`` (default) is
#: the [cll-checkpoint-cose-wire] COSE_Sign1 envelope (``checkpoint_cose.py``,
#: unchanged). ``json-ed25519`` is the CLL ``CheckpointRecord`` JSON shape
#: signed with a bare Ed25519 signature (``checkpoint_json.py``) -- for a
#: submitter whose own pipeline mints that shape directly. This is a
#: per-``log_id`` DECLARATION read from config, never sniffed from the
#: request body: a submission in the wrong form for its declared entry is
#: rejected, never silently accepted under the other form's rules (see
#: ``checkpoint_json.py`` / ``checkpoint_cose.py`` and
#: ``cross_witness_conformance.checker.check_checkpoint_wire``, which checks
#: each submitter against exactly its declared form -- never a single
#: hardcoded wire, and never cross-graded against the other form's fields).
WIRE_FORM_COSE_SIGN1 = "cose"
WIRE_FORM_JSON_ED25519 = "json-ed25519"
_VALID_WIRE_FORMS = (WIRE_FORM_COSE_SIGN1, WIRE_FORM_JSON_ED25519)

#: The canonical (our-side) CLL ``CheckpointRecord`` field names a
#: ``json-ed25519`` checkpoint's signing body covers, plus the detached
#: ``signature`` field itself (never part of the signing body). A
#: ``json-ed25519`` entry's ``field_map`` (below) names, for each of these,
#: the key the SUBMITTER actually uses in their JSON -- explicit per entry,
#: never guessed/assumed to match ours.
_JSON_CHECKPOINT_SIGNING_FIELDS = (
    "v",
    "kind",
    "log_id",
    "mmr_size",
    "root",
    "prev_size",
    "prev_root",
    "key_id",
    "timestamp",
)
_JSON_CHECKPOINT_SIGNATURE_FIELD = "signature"
_JSON_CHECKPOINT_ALL_FIELDS = (*_JSON_CHECKPOINT_SIGNING_FIELDS, _JSON_CHECKPOINT_SIGNATURE_FIELD)

#: Identity mapping -- the default for a ``json-ed25519`` entry whose config
#: omits ``field_map`` (or omits individual keys from it): "the submitter's
#: JSON already uses our field name for this one." Verified true for
#: ``trace-registry/v1`` (``trace_verify._checkpoint.CheckpointRecord`` uses
#: this exact field set) as of 2026-09-01 -- see ``checkpoint_submitters.json``.
_IDENTITY_FIELD_MAP = {k: k for k in _JSON_CHECKPOINT_ALL_FIELDS}

#: Grade label served on the checkpoint stamp for an enrolled submitter.
#: These two MUST stay textually distinct -- never let a foreign-accumulator
#: entry read as if it carried the same guarantee as a native one (see the
#: module docstring on ``checkpoint_cose.py`` and the cross-witness launch
#: brief's "foreign-accumulator honesty" requirement).
GRADE_MMR_VERIFIED = "mmr-verified"
GRADE_COUNTERSIGNED_OBSERVED = "countersigned-observed"

#: Default per-submitter rate limit when a config entry doesn't override it.
DEFAULT_SUBMITTER_RATE_LIMIT_PER_MIN = 60

#: In-package default config, shipped inside the installed wheel/image
#: (``[tool.setuptools.package-data]`` in pyproject.toml) -- so "enroll a
#: submitter" is a normal committed-file PR + deploy, never a box-side edit.
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "checkpoint_submitters.json"

#: Overrides the config file location -- used by tests and non-default
#: deployments. Unset means "use DEFAULT_CONFIG_PATH if it exists, else no
#: enrolled submitters."
_ENV_CONFIG_PATH = "CAPSULE_ANCHOR_CHECKPOINT_SUBMITTERS_FILE"


@dataclass(frozen=True)
class SubmitterEntry:
    """One enrolled external checkpoint submitter: a pinned (``iss``, key) pair."""

    log_id: str  # CWT iss, matched exactly (case-sensitive, may contain "/")
    pubkey: bytes  # raw 32-byte Ed25519 public key -- the ONLY key trusted for log_id
    accumulator: str  # ACCUMULATOR_NATIVE_MMR | ACCUMULATOR_FOREIGN
    rate_limit_per_min: int = DEFAULT_SUBMITTER_RATE_LIMIT_PER_MIN
    wire_form: str = WIRE_FORM_COSE_SIGN1  # WIRE_FORM_COSE_SIGN1 | WIRE_FORM_JSON_ED25519
    # our canonical field name -> submitter's field name; always fully
    # populated (identity-filled) for a json-ed25519 entry, always None for
    # a cose entry (see SubmitterAllowlist.from_list).
    field_map: dict[str, str] | None = None

    @property
    def grade(self) -> str:
        return (
            GRADE_COUNTERSIGNED_OBSERVED
            if self.accumulator == ACCUMULATOR_FOREIGN
            else GRADE_MMR_VERIFIED
        )


class SubmitterConfigError(ValueError):
    """The submitters config file is malformed -- fail closed at startup
    rather than silently running with a partial/wrong allowlist."""


class SubmitterAllowlist:
    """Loaded (``log_id`` -> :class:`SubmitterEntry`) allowlist.

    An EMPTY allowlist (the default when no config file is present) is not
    an error -- it just means no external log has been enrolled yet, and
    every ``log_id`` continues through ``/checkpoints``' pre-existing
    self-asserted-``kid`` behavior unchanged.
    """

    def __init__(self, entries: dict[str, SubmitterEntry] | None = None) -> None:
        self._entries: dict[str, SubmitterEntry] = dict(entries or {})

    def get(self, log_id: str) -> SubmitterEntry | None:
        return self._entries.get(log_id)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, log_id: str) -> bool:
        return log_id in self._entries

    def entries_by_wire_form(self, wire_form: str) -> list[SubmitterEntry]:
        """Every enrolled entry declaring ``wire_form`` -- used by
        ``checkpoint_json.py`` to resolve WHICH entry's ``field_map`` a raw
        JSON submission's ``log_id`` belongs to, before that submission is
        otherwise identified."""
        return [e for e in self._entries.values() if e.wire_form == wire_form]

    @classmethod
    def from_list(cls, raw: list[dict]) -> SubmitterAllowlist:
        entries: dict[str, SubmitterEntry] = {}
        for i, item in enumerate(raw):
            try:
                log_id = item["log_id"]
                pubkey_hex = item["pubkey_hex"]
            except KeyError as exc:
                raise SubmitterConfigError(
                    f"submitters config entry {i}: missing required field {exc}"
                ) from exc
            if not isinstance(log_id, str) or not log_id:
                raise SubmitterConfigError(
                    f"submitters config entry {i}: log_id must be a non-empty string"
                )
            accumulator = item.get("accumulator", ACCUMULATOR_FOREIGN)
            if accumulator not in _VALID_ACCUMULATORS:
                raise SubmitterConfigError(
                    f"submitters config entry {i} ({log_id!r}): accumulator must be one "
                    f"of {_VALID_ACCUMULATORS}, got {accumulator!r}"
                )
            if not isinstance(pubkey_hex, str):
                raise SubmitterConfigError(
                    f"submitters config entry {i} ({log_id!r}): pubkey_hex must be a string"
                )
            try:
                pubkey = bytes.fromhex(pubkey_hex)
            except ValueError as exc:
                raise SubmitterConfigError(
                    f"submitters config entry {i} ({log_id!r}): pubkey_hex is not valid hex: {exc}"
                ) from exc
            if len(pubkey) != 32:
                raise SubmitterConfigError(
                    f"submitters config entry {i} ({log_id!r}): pubkey_hex must decode to "
                    f"32 bytes (raw Ed25519 public key), got {len(pubkey)}"
                )
            rate_limit = item.get("rate_limit_per_min", DEFAULT_SUBMITTER_RATE_LIMIT_PER_MIN)
            if not isinstance(rate_limit, int) or isinstance(rate_limit, bool) or rate_limit <= 0:
                raise SubmitterConfigError(
                    f"submitters config entry {i} ({log_id!r}): rate_limit_per_min must be "
                    "a positive integer"
                )
            wire_form = item.get("wire_form", WIRE_FORM_COSE_SIGN1)
            if wire_form not in _VALID_WIRE_FORMS:
                raise SubmitterConfigError(
                    f"submitters config entry {i} ({log_id!r}): wire_form must be one of "
                    f"{_VALID_WIRE_FORMS}, got {wire_form!r}"
                )
            raw_field_map = item.get("field_map")
            if wire_form == WIRE_FORM_COSE_SIGN1:
                if raw_field_map is not None:
                    raise SubmitterConfigError(
                        f"submitters config entry {i} ({log_id!r}): field_map is only "
                        f"meaningful for wire_form={WIRE_FORM_JSON_ED25519!r}, not {wire_form!r}"
                    )
                field_map = None
            else:
                if raw_field_map is not None and not isinstance(raw_field_map, dict):
                    raise SubmitterConfigError(
                        f"submitters config entry {i} ({log_id!r}): field_map must be an object"
                    )
                field_map = dict(_IDENTITY_FIELD_MAP)
                for our_key, their_key in (raw_field_map or {}).items():
                    if our_key not in _JSON_CHECKPOINT_ALL_FIELDS:
                        raise SubmitterConfigError(
                            f"submitters config entry {i} ({log_id!r}): field_map names "
                            f"unknown canonical field {our_key!r}, expected one of "
                            f"{_JSON_CHECKPOINT_ALL_FIELDS}"
                        )
                    if not isinstance(their_key, str) or not their_key:
                        raise SubmitterConfigError(
                            f"submitters config entry {i} ({log_id!r}): field_map[{our_key!r}] "
                            "must be a non-empty string"
                        )
                    field_map[our_key] = their_key
                if len(set(field_map.values())) != len(field_map):
                    raise SubmitterConfigError(
                        f"submitters config entry {i} ({log_id!r}): field_map values must be "
                        f"distinct (no two canonical fields reading the same submitted field), "
                        f"got {field_map!r}"
                    )
            if log_id in entries:
                raise SubmitterConfigError(f"duplicate submitter log_id {log_id!r} in config")
            entries[log_id] = SubmitterEntry(
                log_id=log_id,
                pubkey=pubkey,
                accumulator=accumulator,
                rate_limit_per_min=rate_limit,
                wire_form=wire_form,
                field_map=field_map,
            )
        return cls(entries)

    @classmethod
    def load(cls, path: str | Path) -> SubmitterAllowlist:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise SubmitterConfigError("submitters config must be a JSON array")
        return cls.from_list(data)

    @classmethod
    def from_env_or_default(cls) -> SubmitterAllowlist:
        """Load from ``CAPSULE_ANCHOR_CHECKPOINT_SUBMITTERS_FILE`` if set,
        else the in-package default file if it exists, else empty.

        Fails closed (raises) on a PRESENT-but-malformed file -- an explicit
        misconfiguration should stop startup, not silently drop entries. A
        genuinely ABSENT file (no submitters enrolled yet) is not an error.
        """
        override = os.environ.get(_ENV_CONFIG_PATH)
        if override:
            return cls.load(override)
        if DEFAULT_CONFIG_PATH.exists():
            return cls.load(DEFAULT_CONFIG_PATH)
        return cls({})
