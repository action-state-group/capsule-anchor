# SPDX-License-Identifier: Apache-2.0
"""The five generic checks. Every profile shares these; a profile's own
policy module contributes additional, kind-specific checks alongside them
(see ``policy.py``). Each function is pure: bundle in, one
``CheckResult`` out, never a side effect.
"""

from __future__ import annotations

from datetime import datetime

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.policy import PolicyModule
from capsule_anchor.countersign.results import CheckResult


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def chain_consistency(bundle: Bundle) -> CheckResult:
    """Every checkpoint in the window chains from the one before it:
    ``checkpoints[i].prev_size == checkpoints[i-1].mmr_size`` and
    ``checkpoints[i].mmr_size`` strictly increasing.

    This is the same peak-consistency chain-linkage rule the checkpoint-aware
    witness already enforces live, per submission, in
    ``anchoring.service.AnchorerService._check_checkpoint_consistency`` --
    reapplied here blind, over the checkpoint sequence a bundle carries,
    instead of against live per-``log_id`` store state. A full MMR
    peak/audit-path recomputation is a further integration point this check
    does not attempt (see ``range_membership`` below and COUNTERSIGN.md).
    """
    cps = bundle.checkpoints
    if not cps:
        return CheckResult(name="chain consistency", result="not present", detail="no checkpoints in the window")
    if len(cps) == 1:
        return CheckResult(
            name="chain consistency",
            result="not checked",
            detail="a single checkpoint in the window has nothing to chain against",
        )
    for i in range(1, len(cps)):
        prev, cur = cps[i - 1], cps[i]
        if cur.prev_size != prev.mmr_size or cur.mmr_size <= prev.mmr_size:
            return CheckResult(
                name="chain consistency",
                result="failed",
                detail=(
                    f"checkpoint {i} does not extend checkpoint {i - 1} "
                    f"(prior mmr_size={prev.mmr_size}, submitted prev_size={cur.prev_size}, "
                    f"mmr_size={cur.mmr_size}) -- rollback or fork"
                ),
            )
    return CheckResult(
        name="chain consistency",
        result="established",
        detail=f"{len(cps)} checkpoints, chain-linked in order, no rollback or fork",
    )


def range_membership(bundle: Bundle) -> CheckResult:
    """Recomputed from record sequence positions against the final
    checkpoint's ``mmr_size``: every ``seq`` in ``[0, mmr_size)`` present
    exactly once, no gap, no duplicate.

    This is a structural (position/count) recompute, not a cryptographic
    per-leaf Merkle audit-path verification -- that requires the MMR
    peak/audit-path primitives that live with the CLL implementation, not in
    this repo, and is the integration point named in COUNTERSIGN.md. This
    check never claims more than it does: it establishes that no interior
    sequence position is missing or duplicated against the window's tip, not
    that each leaf's bytes are bound to the root by a verified audit path.
    """
    if not bundle.records:
        return CheckResult(name="range membership", result="not present", detail="no records in the bundle")
    if not bundle.checkpoints:
        return CheckResult(
            name="range membership",
            result="not checked",
            detail="no checkpoint in the bundle to align the range's tip against",
        )
    tip = bundle.checkpoints[-1].mmr_size
    seqs = sorted(r.seq for r in bundle.records)
    seen: set[int] = set()
    for s in seqs:
        if s in seen:
            return CheckResult(
                name="range membership", result="failed", detail=f"duplicate sequence position {s}"
            )
        seen.add(s)
    if seqs[0] < 0 or seqs[-1] >= tip:
        return CheckResult(
            name="range membership",
            result="failed",
            detail=f"record sequence range [{seqs[0]}, {seqs[-1]}] is not within the tip mmr_size={tip}",
        )
    expected = set(range(seqs[0], seqs[-1] + 1))
    missing = sorted(expected - seen)
    if missing:
        return CheckResult(
            name="range membership",
            result="failed",
            detail=f"interior sequence position(s) missing from the committed interval: {missing[:5]}",
        )
    return CheckResult(
        name="range membership",
        result="established",
        detail=f"{len(seqs)} records span [{seqs[0]}, {seqs[-1]}] with no gap or duplicate, tip mmr_size={tip}",
    )


def cadence(bundle: Bundle) -> CheckResult:
    """Record timestamps bounded by receipts, not batched at window close.

    Fails when every record timestamp falls inside the final tenth of the
    declared window -- the "sealed everything at close" pattern a strict
    profile exists to catch -- rather than spread across the window as the
    checkpoints progressed.
    """
    dated = [r for r in bundle.records if r.timestamp]
    if not dated:
        return CheckResult(name="cadence", result="not present", detail="no dated records in the bundle")
    period_from = _parse_ts(bundle.period.from_)
    period_to = _parse_ts(bundle.period.to)
    if period_from is None or period_to is None or period_to <= period_from:
        return CheckResult(
            name="cadence", result="not checked", detail="bundle period is missing or not a valid interval"
        )
    ts = sorted(t for t in (_parse_ts(r.timestamp) for r in dated) if t is not None)
    if not ts:
        return CheckResult(name="cadence", result="not present", detail="record timestamps did not parse")
    window_span = (period_to - period_from).total_seconds()
    record_span = (ts[-1] - ts[0]).total_seconds()
    tail_start = period_to.timestamp() - (window_span * 0.10)
    all_in_tail = ts[0].timestamp() >= tail_start
    if all_in_tail and record_span < window_span * 0.10:
        return CheckResult(
            name="cadence",
            result="failed",
            detail=(
                f"all {len(ts)} dated records fall within the final 10% of the "
                f"{window_span:.0f}s window -- batched at close, not at cadence"
            ),
        )
    return CheckResult(
        name="cadence",
        result="established",
        detail=f"{len(ts)} dated records span {record_span:.0f}s of a {window_span:.0f}s window",
    )


def key_hygiene(bundle: Bundle) -> CheckResult:
    """Every signing-key change seen across records in sequence order has a
    matching rotation record; a key change with none is a hygiene failure.
    """
    keyed = [r for r in bundle.records if r.signer_key_id]
    if not keyed:
        return CheckResult(name="key hygiene", result="not present", detail="no signer_key_id present on any record")
    keyed.sort(key=lambda r: r.seq)
    rotations_by_new_key: dict[str, list[int]] = {}
    for rot in bundle.rotations:
        rotations_by_new_key.setdefault(rot.new_key_id, []).append(rot.seq)

    current_key = keyed[0].signer_key_id
    for r in keyed[1:]:
        if r.signer_key_id == current_key:
            continue
        candidates = rotations_by_new_key.get(r.signer_key_id, [])
        if not any(seq <= r.seq for seq in candidates):
            return CheckResult(
                name="key hygiene",
                result="failed",
                detail=(
                    f"record seq={r.seq} signs with key {r.signer_key_id!r}, a change from "
                    f"{current_key!r}, with no rotation record at or before seq={r.seq}"
                ),
            )
        current_key = r.signer_key_id
    return CheckResult(
        name="key hygiene",
        result="established",
        detail=f"every key change among {len(keyed)} keyed records has a matching rotation record",
    )


def profile_conformance(bundle: Bundle, policy_module: PolicyModule) -> CheckResult:
    """Every record kind present in the bundle has a policy-module check
    named after it, or reads ``not checked``. Calls ``policy_module.check``
    once; never interprets what a covered kind's own result says -- only
    whether the kind was covered at all.
    """
    kinds = sorted({r.kind for r in bundle.records})
    if not kinds:
        return CheckResult(name="profile conformance", result="not present", detail="no records in the bundle")
    covered = {cr.name for cr in policy_module.check(bundle, bundle.profile)}
    missing = [k for k in kinds if k not in covered]
    if not missing:
        return CheckResult(
            name="profile conformance",
            result="established",
            detail=f"every record kind ({', '.join(kinds)}) has a policy-module check",
        )
    if len(missing) == len(kinds):
        return CheckResult(
            name="profile conformance",
            result="not checked",
            detail=f"no policy module coverage for any record kind present: {', '.join(kinds)}",
        )
    return CheckResult(
        name="profile conformance",
        result="inconclusive",
        detail=f"record kind(s) with no policy-module coverage: {', '.join(missing)}",
    )
