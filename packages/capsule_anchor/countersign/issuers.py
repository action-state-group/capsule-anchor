# SPDX-License-Identifier: Apache-2.0
"""The registration-policy trust anchor: which ledger (issuer) identities
this strict instance accepts a withheld bundle from, and the one key
pinned for each.

A Transparency Service authenticates a Signed Statement's issuer under a
published Registration Policy -- it does not accept a self-asserted key
from the request. This is that trust anchor: a ``ledger_id`` (the bundle's
issuer identity) resolves to exactly the pubkey configured here, never one
a caller supplies alongside the bundle. This is the same config-driven,
fail-closed-on-malformed-config pattern this repo already uses for the
witness's enrolled checkpoint submitters (see
``anchoring.submitters.SubmitterAllowlist``), applied to this instance's
own registration surface.

An unenrolled ``ledger_id`` is refused, not defaulted open -- the opposite
of the permissive witness's ``/checkpoints`` surface, by design: that
default-deny is what makes a strict registration policy strict, and what
this document publishes as the policy (see COUNTERSIGN.md).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

_ENV_CONFIG_PATH = "CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE"


class IssuerConfigError(ValueError):
    """The issuer trust-anchor config is malformed -- fail closed at
    startup rather than silently running with a partial/wrong allowlist."""


@dataclass(frozen=True)
class IssuerEntry:
    """One enrolled issuer: a pinned (``ledger_id``, key) pair."""

    ledger_id: str
    pubkey: bytes  # raw 32-byte Ed25519 public key -- the ONLY key trusted for this ledger_id


class IssuerAllowlist:
    """Loaded (``ledger_id`` -> :class:`IssuerEntry`) trust anchor.

    Empty by default -- an instance with nothing enrolled refuses every
    registration, the correct fail-closed state for a strict registration
    policy. "No config" must never mean "open"; that is the witness's
    surface, not this one.
    """

    def __init__(self, entries: dict[str, IssuerEntry] | None = None) -> None:
        self._entries: dict[str, IssuerEntry] = dict(entries or {})

    def get(self, ledger_id: str) -> IssuerEntry | None:
        return self._entries.get(ledger_id)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, ledger_id: str) -> bool:
        return ledger_id in self._entries

    @classmethod
    def from_list(cls, raw: list[dict]) -> IssuerAllowlist:
        entries: dict[str, IssuerEntry] = {}
        for i, item in enumerate(raw):
            try:
                ledger_id = item["ledger_id"]
                pubkey_hex = item["pubkey_hex"]
            except KeyError as exc:
                raise IssuerConfigError(
                    f"issuers config entry {i}: missing required field {exc}"
                ) from exc
            if not isinstance(ledger_id, str) or not ledger_id:
                raise IssuerConfigError(
                    f"issuers config entry {i}: ledger_id must be a non-empty string"
                )
            if not isinstance(pubkey_hex, str):
                raise IssuerConfigError(
                    f"issuers config entry {i} ({ledger_id!r}): pubkey_hex must be a string"
                )
            try:
                pubkey = bytes.fromhex(pubkey_hex)
            except ValueError as exc:
                raise IssuerConfigError(
                    f"issuers config entry {i} ({ledger_id!r}): pubkey_hex is not valid hex: {exc}"
                ) from exc
            if len(pubkey) != 32:
                raise IssuerConfigError(
                    f"issuers config entry {i} ({ledger_id!r}): pubkey_hex must decode to "
                    f"32 bytes (raw Ed25519 public key), got {len(pubkey)}"
                )
            if ledger_id in entries:
                raise IssuerConfigError(f"duplicate issuer ledger_id {ledger_id!r} in config")
            entries[ledger_id] = IssuerEntry(ledger_id=ledger_id, pubkey=pubkey)
        return cls(entries)

    @classmethod
    def load(cls, path: str | Path) -> IssuerAllowlist:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise IssuerConfigError("issuers config must be a JSON array")
        return cls.from_list(data)

    @classmethod
    def from_env_or_default(cls) -> IssuerAllowlist:
        """Load from ``CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE`` if set,
        else empty. A genuinely absent file means nothing is enrolled yet
        -- every registration is refused, never silently accepted. Fails
        closed (raises) on a PRESENT-but-malformed file.
        """
        override = os.environ.get(_ENV_CONFIG_PATH)
        if override:
            return cls.load(override)
        return cls({})
