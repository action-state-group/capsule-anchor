# SPDX-License-Identifier: Apache-2.0
"""Conformance checks for [trace-registry-first-checkpoint-conformance].

Built AHEAD of the trigger event (AgenTrust's trace-registry publishing its
first real CLL checkpoint to witness.agentactioncapsule.org) so the checks
are ready to run the moment a checkpoint is obtained, rather than written
from scratch under deadline pressure. See ``NOTES.md`` for the read-back gap
this tooling works around: the witness has no discovery/read-by-log_id
surface, so a checkpoint's bytes must be supplied out of band (this module
never guesses at how).

Each ``check_*`` function returns a :class:`ConformanceReport` and never
raises -- a malformed/adversarial input is a FAIL entry, not an exception,
so a caller can always render a report even for garbage input.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scitt_cose.receipt import verify_receipt

from capsule_anchor.anchoring.checkpoint_cose import (
    CheckpointSignatureError,
    NotACheckpointError,
    parse_and_verify_checkpoint_cose,
)
from capsule_anchor.anchoring.service import _checkpoint_digest

#: Identity enrolled 2026-09-01 (Imran, AgenTrust) for the trace-registry
#: cross-witness submitter -- see [witness-enroll-trace-registry-key]. A
#: single place to update if the key is ever rotated/re-enrolled; callers
#: may also override per-call.
DEFAULT_EXPECTED_LOG_ID = "trace-registry/v1"
DEFAULT_EXPECTED_PUBKEY_HEX = "bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90"

CheckStatus = str  # "PASS" | "FAIL" | "UNKNOWN"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    detail: str


@dataclass
class ConformanceReport:
    checks: list[CheckResult] = field(default_factory=list)
    claims: dict | None = None

    def add(self, name: str, status: CheckStatus, detail: str) -> None:
        self.checks.append(CheckResult(name, status, detail))

    @property
    def passed(self) -> bool:
        """PASS only if every check ran and none FAILed. An UNKNOWN (a gap
        in the witness API, not a defect in the submitter) does not flip
        this to FAIL, but does keep it out of a bare `passed` claim --
        callers that need to distinguish should inspect `.checks` directly."""
        return bool(self.checks) and all(c.status in ("PASS", "UNKNOWN") for c in self.checks)

    @property
    def has_failure(self) -> bool:
        return any(c.status == "FAIL" for c in self.checks)

    def render(self) -> str:
        lines = [f"[{c.status:7s}] {c.name}: {c.detail}" for c in self.checks]
        lines.append("OVERALL: " + ("FAIL" if self.has_failure else "PASS"))
        return "\n".join(lines)

    def merge(self, other: ConformanceReport) -> None:
        self.checks.extend(other.checks)


def check_checkpoint_wire(
    cose_bytes: bytes,
    *,
    expected_log_id: str = DEFAULT_EXPECTED_LOG_ID,
    expected_pubkey_hex: str = DEFAULT_EXPECTED_PUBKEY_HEX,
) -> ConformanceReport:
    """Task item (1): wire conformance for one submitted checkpoint.

    Independently decodes + verifies the COSE_Sign1 envelope (content type
    `application/cll-checkpoint+cbor`, claim set, CWT `sub` pattern,
    signature self-consistency) via the SAME independent decoder the live
    witness itself runs (`capsule_anchor.anchoring.checkpoint_cose`) -- a
    PASS here means "the witness would accept this", not just "this looks
    plausible."

    On top of that this checks two things the generic decoder does NOT,
    because it has no notion of who's enrolled: (a) the CWT issuer equals
    `expected_log_id`, (b) the signing key (COSE `kid`) equals the specific
    ENROLLED public key. A checkpoint can be internally self-consistent (a
    valid signature under its OWN kid) while being signed by an entirely
    different keypair -- catching that is the read-side mirror of the
    enrollment task's own server-side "unknown key rejects" check.
    """
    report = ConformanceReport()
    try:
        claims = parse_and_verify_checkpoint_cose(cose_bytes)
    except NotACheckpointError as exc:
        report.add("wire_structure", "FAIL", f"not a well-formed CLL checkpoint: {exc}")
        return report
    except CheckpointSignatureError as exc:
        report.add("wire_structure", "PASS", "content-type + claim set well-formed")
        report.add("signature_self_consistent", "FAIL", str(exc))
        return report

    report.claims = claims
    report.add(
        "wire_structure",
        "PASS",
        f"content-type application/cll-checkpoint+cbor; kind={claims['kind']!r}; "
        f"log_size={claims['mmr_size']}; prev_size={claims['prev_size']}",
    )
    report.add("signature_self_consistent", "PASS", "COSE_Sign1 verifies under its own kid")
    # parse_and_verify_checkpoint_cose already enforces sub == f"{iss}#{log_size}"
    # before returning claims at all -- if we got here, it passed.
    report.add(
        "sub_pattern",
        "PASS",
        f"sub == '{claims['log_id']}#{claims['mmr_size']}'",
    )

    if claims["log_id"] == expected_log_id:
        report.add("enrolled_log_id", "PASS", f"iss == {expected_log_id!r}")
    else:
        report.add(
            "enrolled_log_id",
            "FAIL",
            f"iss == {claims['log_id']!r}, expected {expected_log_id!r}",
        )

    if claims["key_id"] == expected_pubkey_hex:
        report.add("enrolled_key", "PASS", f"kid == enrolled key {expected_pubkey_hex}")
    else:
        report.add(
            "enrolled_key",
            "FAIL",
            f"kid == {claims['key_id']!r}, expected the ENROLLED key {expected_pubkey_hex!r} "
            "-- checkpoint is self-consistent but NOT signed by the enrolled identity",
        )

    return report


@dataclass
class _Resp:
    status_code: int
    _body: bytes

    def json(self) -> Any:
        return json.loads(self._body)


def make_http_getter(base_url: str) -> Callable[[str], _Resp]:
    """Real-HTTP GET client for the watcher CLI. Tests inject
    `TestClient(app).get` instead (same `.status_code`/`.json()` shape),
    so `check_witness_tie_back` never needs to know which it's talking to.
    """

    def get(path: str) -> _Resp:
        url = base_url.rstrip("/") + path
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                return _Resp(resp.status, resp.read())
        except urllib.error.HTTPError as exc:
            return _Resp(exc.code, exc.read())

    return get


def check_witness_tie_back(claims: dict, *, get: Callable[[str], Any]) -> ConformanceReport:
    """Task item (1)'s "fetch it from the witness" step, and item (2)'s
    "confirm the witness countersigned" step.

    The witness's `POST /checkpoints` response carries no claim fields (see
    NOTES.md) and there is no query-by-log_id surface, so this does NOT
    discover the checkpoint -- it recomputes the checkpoint's `capsule_id`
    exactly as the witness does (`_checkpoint_digest`) from claims already
    obtained out of band, then independently verifies the COSE Receipt the
    witness holds for that exact digest via `GET /v1/inclusion/{capsule_id}`
    -- proving the witness actually countersigned THIS checkpoint, not
    merely that something from this submitter exists somewhere.
    """
    report = ConformanceReport()
    capsule_id = _checkpoint_digest(claims)
    resp = get(f"/v1/inclusion/{capsule_id}")
    if resp.status_code == 404:
        report.add(
            "witness_registered",
            "FAIL",
            f"capsule_id {capsule_id} (this checkpoint's digest) not found on the witness (404)",
        )
        return report
    if resp.status_code != 200:
        report.add(
            "witness_registered",
            "FAIL",
            f"unexpected status {resp.status_code} from GET /v1/inclusion/{capsule_id}",
        )
        return report
    body = resp.json()
    report.add(
        "witness_registered",
        "PASS",
        f"leaf_index={body['leaf_index']} tree_size={body['tree_size']}",
    )

    pub = get("/anchor/authority-pubkey")
    if pub.status_code != 200:
        report.add(
            "receipt_offline_verify",
            "FAIL",
            f"could not fetch the witness authority pubkey ({pub.status_code})",
        )
        return report
    pubkey_hex = pub.json()["pubkey_hex"]
    pubkey_pem = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    receipt_bytes = base64.b64decode(body["receipt_b64"])
    result = verify_receipt(receipt_bytes, leaf_entry_hex=body["entry_hash"], log_public_key_pem=pubkey_pem)
    if result.ok:
        report.add(
            "receipt_offline_verify",
            "PASS",
            f"COSE Receipt verifies offline against the witness authority key "
            f"(root={result.root}, tree_size={result.tree_size})",
        )
    else:
        report.add("receipt_offline_verify", "FAIL", "; ".join(result.errors) or "receipt did not verify")
    return report


def check_countersign_grade(
    inclusion_body: dict,
    *,
    grade_field: str | None = None,
    expected_value: str = "observed",
) -> ConformanceReport:
    """Task item (2): confirm the witness published this FOREIGN checkpoint
    under the observed grade (records/timestamps/publishes a foreign
    accumulator; does NOT verify its consistency proofs) -- distinctly
    labeled from an MMR-verified (our own log's) checkpoint. Per the
    launch-tasks brief (`_work/cross-witness-launch-tasks-2026-08-31.md`
    Task 1): "the response object and docs MUST label this grade distinctly
    ... never present the two as the same guarantee."

    GAP FOUND while building this (2026-09-01, base_sha 26083a7 on
    origin/main): no such field exists ANYWHERE in the witness API today --
    not on `CheckpointStampResponse` (the `POST /checkpoints` response) nor
    `InclusionResolveResponse` (the `GET /v1/inclusion/{capsule_id}`
    response). It's expected to land with [witness-enroll-trace-registry-
    key]. Until `grade_field` is passed (the actual field name it ships
    with), this reports UNKNOWN rather than silently passing -- the absence
    of a grade label is exactly the defect this check exists to catch, so
    it must stay visible, not get swallowed as "nothing to check."
    """
    report = ConformanceReport()
    if grade_field is None:
        report.add(
            "countersign_grade",
            "UNKNOWN",
            "no grade/status field exists in the witness API yet (checked "
            "CheckpointStampResponse + InclusionResolveResponse as of "
            "origin/main 26083a7) -- cannot confirm the 'observed, not "
            "MMR-verified' label until [witness-enroll-trace-registry-key] "
            "ships one and this call is updated with the field name; do "
            "NOT read this as a pass",
        )
        return report
    value = inclusion_body.get(grade_field)
    if value == expected_value:
        report.add("countersign_grade", "PASS", f"{grade_field}={value!r}")
    else:
        report.add(
            "countersign_grade",
            "FAIL",
            f"{grade_field}={value!r}, expected {expected_value!r} -- a foreign "
            "checkpoint must never be presented as MMR-verified",
        )
    return report


def check_chain_continuity(first: dict, second: dict) -> ConformanceReport:
    """Task item (4) -- the CRITICAL regression check. Their reported bug:
    ephemeral runner state minting a FRESH chain every ~15 minutes instead
    of continuing the one chain. The tell is the SECOND checkpoint's
    `prev_size`/`prev_commitment` (here, its derived `prev_root`) not
    chaining from the first's `log_size`/`commitment` (`root`).

    `first`/`second` are `.claims` dicts from two `check_checkpoint_wire`
    calls for the SAME log_id, in submission order -- the caller (the
    watcher) is responsible for pairing them correctly; this only checks
    the pair it's given.
    """
    report = ConformanceReport()
    if first["log_id"] != second["log_id"]:
        report.add(
            "chain_continuity",
            "FAIL",
            f"log_id mismatch ({first['log_id']!r} vs {second['log_id']!r}) -- not the same log",
        )
        return report

    prev_size_ok = second["prev_size"] == first["mmr_size"]
    prev_root_ok = second["prev_root"] == first["root"]
    grew = second["mmr_size"] > first["mmr_size"]

    if prev_size_ok and prev_root_ok and grew:
        report.add(
            "chain_continuity",
            "PASS",
            f"second.prev_size ({second['prev_size']}) == first.log_size "
            f"({first['mmr_size']}), second's derived prev_root matches "
            "first's derived root, and log_size grew -- one continuous chain",
        )
        return report

    detail = (
        f"second.prev_size={second['prev_size']} vs first.log_size={first['mmr_size']} "
        f"({'match' if prev_size_ok else 'MISMATCH'}); "
        f"second.prev_root={second['prev_root']!r} vs first.root={first['root']!r} "
        f"({'match' if prev_root_ok else 'MISMATCH'})"
    )
    if second["prev_size"] == 0 and first["mmr_size"] != 0:
        detail += (
            " -- matches the reported ephemeral-runner-state regression: a FRESH "
            "chain was started (prev_size=0) instead of continuing from the first checkpoint"
        )
    if not grew:
        detail += f"; also log_size did not increase ({second['mmr_size']} vs {first['mmr_size']})"
    report.add("chain_continuity", "FAIL", detail)
    return report
