# SPDX-License-Identifier: Apache-2.0
"""End-to-end example: build, submit, fetch back, and independently verify a
CLL (Checkpointed Local Log) checkpoint against the witness's POST /checkpoints
route -- the [cll-checkpoint-cose-wire] wire form (single-host witness ruling,
2026-08-27).

This is the "reproduce it yourself" script for a foreign log operator (e.g. an
external trace-registry) integrating with witness.agentactioncapsule.org. It
uses ONLY the public wire-level libraries a stranger would use -- ``scitt_cose``
(generic SCITT Signed Statement build/verify), ``cbor2`` (canonical CBOR),
``cryptography`` (Ed25519), and ``httpx`` (HTTP) -- never anything from
``capsule_anchor`` itself. That mirrors the actual trust boundary: the witness
verifies what a stranger's COSE bytes claim from scratch, and a stranger
verifies the witness's receipt from scratch, with no shared library in
between (see ``capsule_anchor.anchoring.checkpoint_cose``'s own docstring for
the server-side half of this same rule).

Five steps, each printed to stdout so a run's stdout IS a readable transcript:

  1. Generate (or load) an Ed25519 test key and build a CLL checkpoint claims
     map (log_size, commitment, prev_size, prev_commitment, issued_at).
  2. Wrap it as a COSE_Sign1 Signed Statement (content type
     application/cll-checkpoint+cbor, CWT iss/sub, kid = raw public key).
  3. POST the raw COSE bytes to {host}/checkpoints.
  4. Independently FETCH BACK the same record via GET /v1/inclusion/{digest}
     -- a second, separate request, not just trusting the POST's own reply.
  5. Verify the returned COSE Receipt OFFLINE against the witness's published
     authority public key (GET /anchor/authority-pubkey) using
     ``scitt_cose.verify_receipt`` -- no trust in the operator's own claims.

Usage:
    python submit_checkpoint.py [--host URL] [--log-id ID] [--mmr-size N] [--out DIR]

The default --log-id is a clearly-synthetic test identity (NOT a real
submitter identity) -- this script is for exercising the wire format and the
witness's currently-OPEN registration policy, not for claiming an enrolled
identity. Swap in your own log_id/key when adapting this for a real log.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import cbor2
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from scitt_cose.receipt import verify_receipt
from scitt_cose.statement import build_signed_statement

CLL_CONTENT_TYPE = "application/cll-checkpoint+cbor"
WIRE_KIND = "cll-checkpoint"
DEFAULT_HOST = "https://witness.agentactioncapsule.org"
DEFAULT_LOG_ID = "asg-smoke-test/v1"


def log(msg: str) -> None:
    print(msg, flush=True)


# --- checkpoint construction (mirrors capsule_anchor's independent reimplementation) ---


def root_from_peaks(peak_hashes: list[bytes]) -> bytes:
    """Right-to-left pairwise fold, no domain-separator byte -- MUST match
    ``capsule_anchor.anchoring.checkpoint_cose._root_from_peaks`` exactly, or
    the witness will reconstruct a different root than the one this script
    means to claim."""
    if not peak_hashes:
        return bytes(32)
    hashes = list(peak_hashes)
    while len(hashes) > 1:
        right = hashes.pop()
        left = hashes.pop()
        hashes.append(hashlib.sha256(right + left).digest())
    return hashes[0]


def commitment_bytes(peak_hashes: list[bytes]) -> bytes:
    """MMRIVER-conformant commitment object: canonical CBOR ``[ *bstr ]``."""
    return cbor2.dumps(peak_hashes, canonical=True)


def build_checkpoint_cose(
    key: Ed25519PrivateKey,
    *,
    log_id: str,
    mmr_size: int,
    new_peaks: list[bytes],
    prev_size: int = 0,
    prev_peaks: list[bytes] | None = None,
    issued_at: str,
) -> bytes:
    claims = {
        "kind": WIRE_KIND,
        "log_size": mmr_size,
        "commitment": commitment_bytes(new_peaks),
        "prev_size": prev_size,
        "prev_commitment": commitment_bytes(prev_peaks) if prev_peaks else b"",
        "issued_at": issued_at,
    }
    payload = cbor2.dumps(claims, canonical=True)
    kid = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    subject = f"{log_id}#{mmr_size}"
    private_key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=private_key_pem,
        issuer=log_id,
        subject=subject,
        content_type=CLL_CONTENT_TYPE,
        kid=kid,
    )


def checkpoint_digest_hex(
    *,
    log_id: str,
    mmr_size: int,
    new_peaks: list[bytes],
    prev_size: int,
    prev_peaks: list[bytes] | None,
    key_id_hex: str,
    issued_at: str,
) -> str:
    """Independently recompute the 64-hex digest the witness will register
    for this checkpoint -- ``sha256`` of the sorted-key compact-JSON 9-field
    signing body (``v, kind, log_id, mmr_size, root, prev_size, prev_root,
    key_id, timestamp``). MUST match
    ``capsule_anchor.anchoring.service._checkpoint_digest`` exactly; this is
    what lets step 4 (fetch-back) look the record up independently instead of
    trusting the POST response's own claimed ``entry_hash``."""
    body = {
        "v": 1,
        "kind": "mmr_checkpoint",
        "log_id": log_id,
        "mmr_size": mmr_size,
        "root": root_from_peaks(new_peaks).hex(),
        "prev_size": prev_size,
        "prev_root": root_from_peaks(prev_peaks).hex() if prev_peaks else "",
        "key_id": key_id_hex,
        "timestamp": issued_at,
    }
    signing_body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(signing_body).hexdigest()


def entry_hash_hex(digest_hex: str) -> str:
    """The CT-log entry hash for a bare-digest registration: sha256 of the
    raw digest bytes (the "legacy" entry_hash_scheme)."""
    return hashlib.sha256(bytes.fromhex(digest_hex)).hexdigest()


def authority_pubkey_pem(host: str, client: httpx.Client) -> tuple[bytes, str]:
    resp = client.get(f"{host}/anchor/authority-pubkey")
    resp.raise_for_status()
    body = resp.json()
    raw = bytes.fromhex(body["pubkey_hex"])
    pem = Ed25519PublicKey.from_public_bytes(raw).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return pem, body["key_id"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=DEFAULT_HOST, help=f"witness base URL (default: {DEFAULT_HOST})")
    ap.add_argument("--log-id", default=DEFAULT_LOG_ID, help=f"CWT iss / log_id (default: {DEFAULT_LOG_ID!r} -- a synthetic test identity, not a real submitter)")
    ap.add_argument("--mmr-size", type=int, default=1, help="log_size claim for this checkpoint (default: 1)")
    ap.add_argument("--out", type=Path, default=None, help="directory to write artifacts (key, COSE bytes, receipt) -- optional")
    args = ap.parse_args()

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)

    log("=== cross-witness checkpoint smoke: LEG 1 (synthetic test identity) ===")
    log(f"host:    {args.host}")
    log(f"log_id:  {args.log_id}")
    log(f"mmr_size: {args.mmr_size}")
    log("")

    # --- 1. generate test key + checkpoint claims ---------------------------
    key = Ed25519PrivateKey.generate()
    key_id_hex = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_peaks = [hashlib.sha256(f"{args.log_id}-{args.mmr_size}-{i}".encode()).digest() for i in range(1)]

    log(f"[1] generated Ed25519 test key, kid={key_id_hex}")
    log(f"    issued_at={issued_at}")
    if args.out:
        (args.out / "test_key.pem").write_bytes(
            key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        log(f"    private key written to {args.out / 'test_key.pem'}")

    # --- 2. build + sign the COSE_Sign1 checkpoint statement ----------------
    cose_bytes = build_checkpoint_cose(
        key,
        log_id=args.log_id,
        mmr_size=args.mmr_size,
        new_peaks=new_peaks,
        prev_size=0,
        prev_peaks=None,
        issued_at=issued_at,
    )
    log(f"[2] built COSE_Sign1 checkpoint statement, {len(cose_bytes)} bytes")
    log(f"    content_type={CLL_CONTENT_TYPE}")
    if args.out:
        (args.out / "checkpoint.cose").write_bytes(cose_bytes)
        log(f"    COSE bytes written to {args.out / 'checkpoint.cose'}")
    log("")

    digest_hex = checkpoint_digest_hex(
        log_id=args.log_id,
        mmr_size=args.mmr_size,
        new_peaks=new_peaks,
        prev_size=0,
        prev_peaks=None,
        key_id_hex=key_id_hex,
        issued_at=issued_at,
    )
    expected_entry_hash = entry_hash_hex(digest_hex)
    log(f"    locally-computed digest:     {digest_hex}")
    log(f"    locally-computed entry_hash: {expected_entry_hash}")
    log("")

    with httpx.Client(timeout=30.0) as client:
        # --- 3. POST to the live witness ------------------------------------
        log(f"[3] POST {args.host}/checkpoints")
        resp = client.post(
            f"{args.host}/checkpoints",
            content=cose_bytes,
            headers={"Content-Type": CLL_CONTENT_TYPE},
        )
        log(f"    -> HTTP {resp.status_code}")
        log(f"    -> {resp.text}")
        resp.raise_for_status()
        submit_body = resp.json()
        assert submit_body["entry_hash"] == expected_entry_hash, (
            f"witness entry_hash {submit_body['entry_hash']!r} != locally-computed "
            f"{expected_entry_hash!r} -- our reimplementation of the signing body "
            "disagrees with the server's"
        )
        log("    OK: witness entry_hash matches our independent computation")
        log("")

        # --- 4. independently FETCH BACK via a separate GET ------------------
        log(f"[4] GET {args.host}/v1/inclusion/{digest_hex} (independent fetch-back, NOT reusing the POST response)")
        fetch_resp = client.get(f"{args.host}/v1/inclusion/{digest_hex}")
        log(f"    -> HTTP {fetch_resp.status_code}")
        fetch_resp.raise_for_status()
        fetch_body = fetch_resp.json()
        log(f"    -> entry_hash={fetch_body['entry_hash']} leaf_index={fetch_body['leaf_index']} tree_size={fetch_body['tree_size']}")
        assert fetch_body["entry_hash"] == expected_entry_hash
        assert fetch_body["receipt_b64"] == submit_body["receipt_b64"], (
            "fetched-back receipt differs from the POST response's receipt for the same entry_hash"
        )
        log("    OK: fetched-back record matches the POST response")
        log("")

        # --- 5. verify the receipt OFFLINE against the published authority key ---
        log(f"[5] GET {args.host}/anchor/authority-pubkey, then verify the receipt OFFLINE")
        pubkey_pem, key_id = authority_pubkey_pem(args.host, client)
        log(f"    authority key_id={key_id}")
        receipt_bytes = base64.b64decode(fetch_body["receipt_b64"])
        if args.out:
            (args.out / "receipt.cose").write_bytes(receipt_bytes)
            log(f"    receipt written to {args.out / 'receipt.cose'}")
        result = verify_receipt(receipt_bytes, leaf_entry_hex=expected_entry_hash, log_public_key_pem=pubkey_pem)
        log(f"    verify_receipt(...).ok = {result.ok}")
        if not result.ok:
            log(f"    errors: {result.errors}")
            log("")
            log("=== LEG 1: FAILED (offline receipt verification did not pass) ===")
            return 1
        log(f"    root={result.root} tree_size={result.tree_size} leaf_index={result.leaf_index}")
        log("")

    log("=== LEG 1: PASSED -- checkpoint submitted, fetched back independently, receipt verifies offline ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
