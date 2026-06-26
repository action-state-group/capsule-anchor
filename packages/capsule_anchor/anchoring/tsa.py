"""RFC3161 timestamp-authority client (stdlib-only).

A timestamp authority (TSA) accepts a hash and returns a CMS SignedData
TimeStampToken proving "this hash existed at time T" — signed by the TSA's
private key. This is independent of, and complementary to, the AS Authority's
own countersignature: a regulator who doesn't trust us can re-verify the time
claim against a third party (FreeTSA, DigiCert, Sectigo, ...) without trusting
our log.

Design:
* Opt-in via ``CAPSULE_ANCHOR_TSA_ENABLED=1`` — default off so existing tests
  don't hit the network.
* TSA URL configurable via ``CAPSULE_ANCHOR_TSA_URL`` (default: FreeTSA).
* Pure stdlib: ``urllib`` for HTTP, hand-rolled DER for the TimeStampReq
  envelope. We deliberately do NOT parse the response — we store the raw
  TimeStampToken bytes so an auditor can hand them to ``openssl ts -verify``
  or any RFC3161 client of their choosing.

Why hand-rolled DER: RFC3161 requests are small (a hash + a few flags) and
adding an ASN.1 library (pyasn1 / asn1crypto) for one writer-only envelope
is more dependency surface than the value justifies. Response parsing is
explicitly out of scope; the bytes are opaque to us by design.
"""

from __future__ import annotations

import hashlib
import os
import urllib.error
import urllib.request
from typing import Final

DEFAULT_TSA_URL: Final[str] = "https://freetsa.org/tsr"
TSA_REQUEST_CONTENT_TYPE: Final[str] = "application/timestamp-query"
TSA_RESPONSE_CONTENT_TYPE: Final[str] = "application/timestamp-reply"

# OID for SHA-256: 2.16.840.1.101.3.4.2.1
_SHA256_OID_DER: Final[bytes] = bytes.fromhex(
    "06 09 60 86 48 01 65 03 04 02 01".replace(" ", "")
)


def tsa_enabled() -> bool:
    """Return True iff the operator has opted into TSA signing."""
    return os.environ.get("CAPSULE_ANCHOR_TSA_ENABLED") == "1"


def tsa_url() -> str:
    return os.environ.get("CAPSULE_ANCHOR_TSA_URL", DEFAULT_TSA_URL).strip() or DEFAULT_TSA_URL


# ---------------------------------------------------------------------------
# Minimal DER encoder for the TimeStampReq envelope (RFC3161 §2.4.1).
# ---------------------------------------------------------------------------


def _der_length(n: int) -> bytes:
    """ASN.1 DER length octets for a value of length ``n``."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(body)) + body


def _der_integer(value: int) -> bytes:
    # Minimal two's-complement encoding (always positive here).
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der(0x02, raw)


def _der_octet_string(value: bytes) -> bytes:
    return _der(0x04, value)


def _der_null() -> bytes:
    return _der(0x05, b"")


def _der_sequence(*children: bytes) -> bytes:
    return _der(0x30, b"".join(children))


def _der_boolean_true() -> bytes:
    return _der(0x01, b"\xff")


def build_timestamp_request(message_hash: bytes, *, request_cert: bool = True) -> bytes:
    """Build an RFC3161 TimeStampReq DER blob for ``message_hash`` (SHA-256).

    TimeStampReq ::= SEQUENCE {
        version            INTEGER (v1=1),
        messageImprint     MessageImprint,
        reqPolicy          OBJECT IDENTIFIER OPTIONAL,
        nonce              INTEGER OPTIONAL,
        certReq            BOOLEAN DEFAULT FALSE
    }

    MessageImprint ::= SEQUENCE {
        hashAlgorithm      AlgorithmIdentifier,
        hashedMessage      OCTET STRING
    }
    """
    if len(message_hash) != 32:
        raise ValueError("message_hash must be a 32-byte SHA-256 digest")
    algorithm_identifier = _der_sequence(_SHA256_OID_DER, _der_null())
    message_imprint = _der_sequence(algorithm_identifier, _der_octet_string(message_hash))

    children = [_der_integer(1), message_imprint]
    if request_cert:
        children.append(_der_boolean_true())
    return _der_sequence(*children)


# ---------------------------------------------------------------------------
# HTTP roundtrip
# ---------------------------------------------------------------------------


class TsaError(RuntimeError):
    """TSA request failed (network, HTTP, or empty response)."""


def post_timestamp_request(
    request_der: bytes, *, url: str | None = None, timeout: float = 10.0
) -> bytes:
    """POST a TimeStampReq to the TSA and return the raw TimeStampResp bytes.

    Raises ``TsaError`` on any HTTP / network failure. The bytes are opaque
    to us; a verifier uses ``openssl ts -verify`` or equivalent to validate.
    """
    target = url or tsa_url()
    req = urllib.request.Request(
        target,
        data=request_der,
        headers={
            "Content-Type": TSA_REQUEST_CONTENT_TYPE,
            "Accept": TSA_RESPONSE_CONTENT_TYPE,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read()
    except (urllib.error.URLError, OSError) as exc:
        raise TsaError(f"TSA request failed: {exc}") from exc
    if not body:
        raise TsaError("TSA returned empty body")
    return body


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def timestamp_root_hash(root_hash: str, *, url: str | None = None) -> bytes:
    """Request an RFC3161 timestamp signature over ``root_hash`` (hex string).

    Returns the raw TimeStampResp bytes. Caller is responsible for storing /
    base64-encoding for transport. Raises ``TsaError`` on failure.

    ``root_hash`` is the anchor's Merkle root in hex (the same value the AS
    Authority countersigns). We re-hash it under SHA-256 so the bytes the
    TSA sees match what a verifier would compute from the receipt — i.e. the
    SHA-256 of the ASCII-hex root_hash string. This convention is documented
    on AnchorReceipt so downstream verifiers compute the same input.
    """
    # We hash the ASCII-hex form so the verification recipe is "sha256 over
    # the same ASCII bytes the receipt carries" — no off-by-one decode rules.
    message_hash = hashlib.sha256(root_hash.encode("ascii")).digest()
    request_der = build_timestamp_request(message_hash, request_cert=True)
    return post_timestamp_request(request_der, url=url)
