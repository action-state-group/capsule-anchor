"""Signed reads of ``GET /checkpoints/{log_id}`` (capsule-anchor#110, ruling u226).

A log's checkpoint size, root, time and receipt answer only a read signed
with that log's own checkpoint key; ``equivocations`` stays public. A reader
proves it holds the key by sending two headers:

    Checkpoint-Read-Time: <unix seconds, unsigned decimal, no leading zeros>
    Checkpoint-Read-Signature: <base64url, no padding, Ed25519 signature>

over the UTF-8 bytes of::

    capsule-anchor/checkpoint-read/v1 LF <log_id> LF <time>

``log_id`` is the decoded id the route receives, so how a client
percent-encodes its ``/`` segments does not matter. The domain line keeps a
read signature from being mistaken for any other signature by the same key.
The witness accepts a time within ``READ_WINDOW_SECONDS`` of its own clock in
either direction; inside that window a captured header pair can be replayed,
so the headers must not be logged.

This is not RFC 9421 HTTP Message Signatures: nothing in this stack signs
HTTP requests, and the one value worth binding here is the log id.
"""

from __future__ import annotations

import base64
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

READ_TIME_HEADER = "Checkpoint-Read-Time"
READ_SIGNATURE_HEADER = "Checkpoint-Read-Signature"
READ_DOMAIN = b"capsule-anchor/checkpoint-read/v1"
READ_WINDOW_SECONDS = 300

# Stable refusal codes a reader can branch on (the 403 body's ``code``).
CODE_MALFORMED = "read_signature_malformed"
CODE_TIME_SKEW = "read_time_skew"
CODE_KEY_MISMATCH = "read_key_mismatch"

_DECIMAL = re.compile(r"(0|[1-9][0-9]{0,18})")
_B64URL = re.compile(r"[A-Za-z0-9_-]+")


class ReadRefused(Exception):
    """A read that carried the headers but is not a valid read by the log's key."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def read_message(log_id: str, time_value: str) -> bytes:
    """The exact bytes a reader signs."""
    return READ_DOMAIN + b"\n" + log_id.encode("utf-8") + b"\n" + time_value.encode("ascii")


def verify_read(
    log_id: str,
    time_values: list[str],
    signature_values: list[str],
    key: bytes | None,
    now: float,
) -> bool:
    """Return False for an unsigned read (neither header), True for a valid
    read by ``key``; raise ``ReadRefused`` for anything else.

    ``key`` is the raw 32-byte Ed25519 key the log's checkpoints are verified
    under, or ``None`` when the witness holds none usable for this log, in
    which case no signature can pass.
    """
    if not time_values and not signature_values:
        return False
    if len(time_values) != 1 or len(signature_values) != 1:
        raise ReadRefused(
            CODE_MALFORMED,
            f"a signed read sends exactly one {READ_TIME_HEADER} and one {READ_SIGNATURE_HEADER} header",
        )
    time_value, signature_value = time_values[0].strip(), signature_values[0].strip()
    if not _DECIMAL.fullmatch(time_value):
        raise ReadRefused(CODE_MALFORMED, f"{READ_TIME_HEADER} must be unix seconds in decimal")
    # 64 bytes encode to exactly 86 unpadded base64url characters; checking
    # the length first means the decode below cannot fail on padding.
    if len(signature_value) != 86 or not _B64URL.fullmatch(signature_value):
        raise ReadRefused(
            CODE_MALFORMED,
            f"{READ_SIGNATURE_HEADER} must be a 64-byte Ed25519 signature in unpadded base64url",
        )
    signature = base64.urlsafe_b64decode(signature_value + "==")
    if abs(now - int(time_value)) > READ_WINDOW_SECONDS:
        raise ReadRefused(
            CODE_TIME_SKEW,
            f"{READ_TIME_HEADER} is more than {READ_WINDOW_SECONDS} seconds from this witness's clock",
        )
    try:
        if key is None:
            raise InvalidSignature
        Ed25519PublicKey.from_public_bytes(key).verify(signature, read_message(log_id, time_value))
    except (InvalidSignature, ValueError):
        raise ReadRefused(
            CODE_KEY_MISMATCH, "the read is not signed by this log's checkpoint key"
        ) from None
    return True
