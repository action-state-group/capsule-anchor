# SPDX-License-Identifier: Apache-2.0
"""Four-case refusal/acceptance transcript against the trace-registry/v1 witness
surface, for [witness-refusal-session-trace-registry-53].

Independently reimplements the JSON and COSE checkpoint wire shapes rather than
importing capsule-emit or the test suite's helpers directly, so this script
exercises the same boundary the live server enforces against a genuine
stranger's bytes -- matching packages/tests/test_checkpoints_and_register_witness_host.py's
own stated rationale for doing the same.

Two modes:
  --target local   Run against an in-process FastAPI TestClient with a
                    locally-enrolled trace-registry/v1 key (the "staging" dry
                    run gate -- never touches the network).
  --target live     Run against https://anchor.agentactioncapsule.org (no local
                    enrollment possible or needed -- we are an outside caller).

Only case 2 and case 4 write anything (both against an obviously-scoped test
log_id, never trace-registry/v1). Cases 1 and 3 are refusals; nothing is
mutated by a refused submission.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone

import cbor2
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

LIVE_BASE = "https://anchor.agentactioncapsule.org"
TRACE_REGISTRY_LOG_ID = "trace-registry/v1"
TEST_LOG_ID = "asg-refusal-check-2026-09-23/v1"

JSON_CONTENT_TYPE = "application/cll-checkpoint+json"
COSE_CONTENT_TYPE = "application/cll-checkpoint+cbor"

_CWT_IAT_LABEL = 6
_CWT_CLAIMS_HDR = 15
_GRADE_LABEL = -65537


# ---------------------------------------------------------------------------
# JSON (json-ed25519) wire form -- independently reimplemented from the
# server's own documented signing recipe (packages/capsule_anchor/anchoring/
# checkpoint_json.py + the test file's _json_signing_body/_json_checkpoint).
# ---------------------------------------------------------------------------

def json_signing_body(cp: dict) -> bytes:
    fields = ("v", "kind", "log_id", "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp")
    body = {k: cp[k] for k in fields}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def build_json_checkpoint(
    key: Ed25519PrivateKey,
    *,
    log_id: str,
    mmr_size: int,
    root: str | None = None,
    prev_size: int = 0,
    prev_root: str = "",
    key_id: str | None = None,
    timestamp: str | None = None,
) -> dict:
    cp = {
        "v": 1,
        "kind": "mmr_checkpoint",
        "log_id": log_id,
        "mmr_size": mmr_size,
        "root": root or ("a" * 64),
        "prev_size": prev_size,
        "prev_root": prev_root,
        "key_id": key_id or key.public_key().public_bytes_raw().hex(),
        "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    digest = hashlib.sha256(json_signing_body(cp)).hexdigest()
    cp["signature"] = key.sign(digest.encode("ascii")).hex()
    return cp


# ---------------------------------------------------------------------------
# COSE_Sign1 wire form -- for case 3 (wrong wire form under an enrolled
# json-ed25519 log_id). Any signing key is fine; this must be refused before
# signature verification per the route's own docstring.
# ---------------------------------------------------------------------------

def peaks_for(seed: str, n: int = 1) -> list[bytes]:
    return [hashlib.sha256(f"{seed}-{i}".encode()).digest() for i in range(n)]


def commitment(peak_hashes: list[bytes]) -> bytes:
    return cbor2.dumps(peak_hashes, canonical=True)


def build_cose_checkpoint(key: Ed25519PrivateKey, *, log_id: str, mmr_size: int) -> bytes:
    from scitt_cose.statement import build_signed_statement

    claims = {
        "kind": "cll-checkpoint",
        "log_size": mmr_size,
        "commitment": commitment(peaks_for(f"{log_id}-{mmr_size}")),
        "prev_size": 0,
        "prev_commitment": b"",
        "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return build_signed_statement(
        cbor2.dumps(claims, canonical=True),
        alg="EdDSA",
        private_key_pem=key_pem,
        issuer=log_id,
        subject=f"{log_id}#{mmr_size}",
        content_type=COSE_CONTENT_TYPE,
        kid=key.public_key().public_bytes_raw(),
    )


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class LiveTransport:
    def __init__(self, base: str = LIVE_BASE):
        self.base = base

    def post(self, path: str, *, content: bytes, content_type: str) -> tuple[int, dict, bytes]:
        resp = requests.post(self.base + path, data=content, headers={"Content-Type": content_type}, timeout=15)
        raw = resp.content
        try:
            body = resp.json()
        except ValueError:
            body = {}
        return resp.status_code, body, raw

    def get(self, path: str) -> dict:
        return requests.get(self.base + path, timeout=15).json()


class LocalTransport:
    """Wraps a FastAPI TestClient against this worktree's own app, with
    trace-registry/v1 enrolled locally (json-ed25519) so the dry run can
    prove all four outcomes before anything touches the network."""

    def __init__(self, enrolled_key: Ed25519PrivateKey):
        from capsule_anchor.anchoring.submitters import SubmitterAllowlist, WIRE_FORM_JSON_ED25519
        from capsule_anchor.anchoring.router import configure_submitters
        from capsule_anchor.app import create_app
        from fastapi.testclient import TestClient

        allow = SubmitterAllowlist.from_list(
            [
                {
                    "log_id": TRACE_REGISTRY_LOG_ID,
                    "pubkey_hex": enrolled_key.public_key().public_bytes_raw().hex(),
                    "accumulator": "foreign",
                    "wire_form": WIRE_FORM_JSON_ED25519,
                }
            ]
        )
        configure_submitters(allow)
        self.client = TestClient(create_app())

    def post(self, path: str, *, content: bytes, content_type: str) -> tuple[int, dict, bytes]:
        resp = self.client.post(path, content=content, headers={"Content-Type": content_type})
        raw = resp.content
        body = resp.json() if resp.content else {}
        return resp.status_code, body, raw

    def get(self, path: str) -> dict:
        return self.client.get(path).json()


# ---------------------------------------------------------------------------
# The four cases
# ---------------------------------------------------------------------------

def run_session(transport, *, label: str) -> dict:
    results = {}
    print(f"\n{'=' * 70}\nSESSION: {label}\n{'=' * 70}")

    # --- pre-flight tree_size, if available ---
    try:
        before = transport.get("/health")
        print(f"pre-session /health: {before}")
    except Exception as exc:  # local TestClient has /health too
        before = None
        print(f"pre-session /health unavailable: {exc}")

    # Case 1: named case -- wrong key claiming trace-registry/v1, JSON form.
    impostor_key = Ed25519PrivateKey.generate()
    cp1 = build_json_checkpoint(impostor_key, log_id=TRACE_REGISTRY_LOG_ID, mmr_size=999001)
    print(f"\n--- CASE 1: named case (wrong key, log_id={TRACE_REGISTRY_LOG_ID}) ---")
    print(f"REQUEST POST /checkpoints Content-Type: {JSON_CONTENT_TYPE}\nBODY: {json.dumps(cp1, indent=2)}")
    status1, body1, _ = transport.post("/checkpoints", content=json.dumps(cp1).encode(), content_type=JSON_CONTENT_TYPE)
    print(f"RESPONSE status={status1} body={json.dumps(body1, indent=2)}")
    results["case1"] = {"request": cp1, "status": status1, "response": body1}

    # Case 2: contrast -- unenrolled test log_id. The default-open behavior lives
    # ONLY on the COSE ingress path (checkpoint_cose.py has no wire_form check at
    # all; the JSON path refuses any log_id not enrolled with wire_form=json-ed25519
    # -- confirmed by reading router.py's dispatch + checkpoint_cose.py directly, and
    # by the local dry run below, which caught this: an earlier JSON-form draft of
    # this case was refused 400, not accepted). So case 2 MUST use COSE, self-signed,
    # self-asserted kid -- exactly test_non_enrolled_log_id_stays_open_even_with_allowlist_configured's shape.
    fresh_key = Ed25519PrivateKey.generate()
    cose_bytes2 = build_cose_checkpoint(fresh_key, log_id=TEST_LOG_ID, mmr_size=1)
    print(f"\n--- CASE 2: contrast (unenrolled log_id={TEST_LOG_ID}, COSE self-asserted kid) ---")
    print(f"REQUEST POST /checkpoints Content-Type: {COSE_CONTENT_TYPE}\nBODY: <{len(cose_bytes2)} raw COSE bytes, kid={fresh_key.public_key().public_bytes_raw().hex()}>")
    status2, body2, _ = transport.post("/checkpoints", content=cose_bytes2, content_type=COSE_CONTENT_TYPE)
    print(f"RESPONSE status={status2} body={json.dumps(body2, indent=2)}")
    results["case2"] = {"request_len": len(cose_bytes2), "status": status2, "response": body2}

    # Case 3: wrong wire form -- COSE under trace-registry/v1 (declared json-ed25519).
    # IMPORTANT (found during code reading, not assumed): checkpoint_cose.py's
    # parse_and_verify_checkpoint_cose does NOT check the enrolled entry's declared
    # wire_form at all -- it looks up the pinned key for this log_id from the SAME
    # allowlist and verifies the COSE signature against it, unconditionally. The
    # "declared form gates it" property (submitters.py's docstring, and the existing
    # test_json_form_refused_for_a_cose_declared_enrolled_submitter) is proven only in
    # the JSON direction (JSON submissions refused for a non-JSON-declared log_id).
    # There is no code path that refuses a COSE submission FOR WIRE-FORM REASONS.
    # We cannot sign with AgenTrust's real pinned key, so this submission is refused
    # for signature mismatch (401) -- refused either way, but the CORRECTION note's
    # framing ("refused ... never silently re-parsed under the other form's rules")
    # overstates what's actually enforced: a correctly-signed COSE submission under
    # trace-registry/v1 would not be wire-form-blocked at all. This is a real finding,
    # reported as such below, not silently reframed as confirming the claimed gate.
    cose_bytes3 = build_cose_checkpoint(Ed25519PrivateKey.generate(), log_id=TRACE_REGISTRY_LOG_ID, mmr_size=999002)
    print(f"\n--- CASE 3: wrong wire form (COSE under log_id={TRACE_REGISTRY_LOG_ID}, declared json-ed25519) ---")
    print(f"REQUEST POST /checkpoints Content-Type: {COSE_CONTENT_TYPE}\nBODY: <{len(cose_bytes3)} raw COSE bytes>")
    status3, body3, _ = transport.post("/checkpoints", content=cose_bytes3, content_type=COSE_CONTENT_TYPE)
    print(f"RESPONSE status={status3} body={json.dumps(body3, indent=2)}")
    results["case3"] = {"request_len": len(cose_bytes3), "status": status3, "response": body3}

    # Case 4: fresh receipt -- another accepted checkpoint under the test log_id
    # (COSE, same reasoning as case 2), decode protected header (iat + grade).
    fresh_key2 = Ed25519PrivateKey.generate()
    cose_bytes4 = build_cose_checkpoint(fresh_key2, log_id=TEST_LOG_ID, mmr_size=2)
    print(f"\n--- CASE 4: fresh receipt (log_id={TEST_LOG_ID}, mmr_size=2, COSE) ---")
    print(f"REQUEST POST /checkpoints Content-Type: {COSE_CONTENT_TYPE}\nBODY: <{len(cose_bytes4)} raw COSE bytes, kid={fresh_key2.public_key().public_bytes_raw().hex()}>")
    status4, body4, _ = transport.post("/checkpoints", content=cose_bytes4, content_type=COSE_CONTENT_TYPE)
    print(f"RESPONSE status={status4} body={json.dumps(body4, indent=2)}")
    results["case4"] = {"request_len": len(cose_bytes4), "status": status4, "response": body4}

    decoded_header = None
    if status4 == 200 and body4.get("receipt_b64"):
        receipt_bytes = base64.b64decode(body4["receipt_b64"])
        cose_arr = cbor2.loads(receipt_bytes)
        # COSE_Sign1 = [protected(bstr), unprotected(map), payload, signature]
        protected_bytes = cose_arr.value[0] if hasattr(cose_arr, "value") else cose_arr[0]
        protected = cbor2.loads(protected_bytes)
        cwt_claims = protected.get(_CWT_CLAIMS_HDR)
        iat = cwt_claims.get(_CWT_IAT_LABEL) if isinstance(cwt_claims, dict) else None
        grade = protected.get(_GRADE_LABEL)
        decoded_header = {"protected_header_raw": {str(k): v for k, v in protected.items()}, "cwt_claims": cwt_claims, "iat": iat, "grade": grade}
        print(f"\nDECODED PROTECTED HEADER: {decoded_header}")
    results["case4_decoded_header"] = decoded_header

    try:
        after = transport.get("/health")
        print(f"\npost-session /health: {after}")
    except Exception as exc:
        after = None
        print(f"post-session /health unavailable: {exc}")

    results["tree_size_before"] = before.get("tree_size") if before else None
    results["tree_size_after"] = after.get("tree_size") if after else None

    # Supplementary, read-only: readback of trace-registry/v1's OWN already-witnessed
    # checkpoint (never a new submission -- pure GET, "never registers or mutates
    # anything" per the route's own docstring). Included because it is the only way
    # to observe a REAL enrolled-submitter receipt without possessing AgenTrust's
    # pinned key -- and it turns out to matter: see the decoded header below.
    print(f"\n--- SUPPLEMENTARY (read-only): GET /checkpoints/{TRACE_REGISTRY_LOG_ID} ---")
    readback = transport.get(f"/checkpoints/{TRACE_REGISTRY_LOG_ID.replace('/', '%2F')}")
    print(f"RESPONSE: {json.dumps(readback, indent=2)}")
    results["trace_registry_readback"] = readback
    if readback.get("receipt_b64"):
        rb = cbor2.loads(base64.b64decode(readback["receipt_b64"]))
        rb_protected = cbor2.loads(rb.value[0] if hasattr(rb, "value") else rb[0])
        rb_cwt = rb_protected.get(_CWT_CLAIMS_HDR)
        rb_decoded = {
            "protected_header_raw": {str(k): v for k, v in rb_protected.items()},
            "cwt_claims": rb_cwt,
            "iat": rb_cwt.get(_CWT_IAT_LABEL) if isinstance(rb_cwt, dict) else None,
            "grade_in_signed_header": rb_protected.get(_GRADE_LABEL),
            "grade_in_json_body": readback.get("grade"),
        }
        print(f"DECODED (trace-registry/v1's own receipt): {rb_decoded}")
        results["trace_registry_readback_decoded"] = rb_decoded

    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=["local", "live"], required=True)
    args = ap.parse_args()

    if args.target == "local":
        enrolled_key = Ed25519PrivateKey.generate()
        transport = LocalTransport(enrolled_key)
        run_session(transport, label="LOCAL DRY RUN (staging gate)")
    else:
        transport = LiveTransport()
        run_session(transport, label="LIVE anchor.agentactioncapsule.org")


if __name__ == "__main__":
    main()
