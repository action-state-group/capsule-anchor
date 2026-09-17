# SPDX-License-Identifier: Apache-2.0
"""The five generic checks. Every profile shares these; a profile's own
policy module contributes additional, kind-specific checks alongside them
(see ``policy.py``). Each function is pure: bundle in, one
``CheckResult`` out, never a side effect.

Recomputed over the canonical v2 Evidence Bundle
([countersign-whole-bundle-shape]): three of the five generic checks were
designed around fields the ad-hoc bundle model invented
(``checkpoints[]`` history, a declared ``period``, per-record
``signer_key_id``) that the donated wire shape simply does not carry -- a v2
bundle has exactly one checkpoint (the tip, not a history), no attestation
window, and no per-record signing-key field on an AAC Capsule record. Each
of those checks now reads ``not present`` for a v2 bundle, honestly, rather
than inventing meaning the wire does not have (the same ``not present``
vocabulary this module already used for "the bundle carries nothing this
check operates on"). ``range_membership`` gains real teeth in exchange: it
now delegates to the neutral ``agent_action_capsule.bundle`` verifier's CLL
#13 range-proof and per-record inclusion-proof recompute -- the
cryptographic audit-path verification the prior structural-only check
explicitly said was "a further integration point this check does not
attempt".
"""

from __future__ import annotations

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.policy import PolicyModule
from capsule_anchor.countersign.results import CheckResult


def chain_consistency(bundle: Bundle) -> CheckResult:
    """The v2 Evidence Bundle carries exactly one ``checkpoint`` (the tip),
    never a checkpoint sequence -- there is nothing here for this check to
    chain against. Always ``not present``."""
    return CheckResult(
        name="chain consistency",
        result="not present",
        detail="the v2 Evidence Bundle carries a single checkpoint, not a checkpoint history -- nothing to chain",
    )


def range_membership(bundle: Bundle) -> CheckResult:
    """Delegates to the neutral library's ``interval_coverage`` /
    ``per_record_membership`` claims: real CLL #13 range-proof and
    per-record inclusion-proof verification against ``bundle.checkpoint``,
    not a structural position/count recompute.
    """
    if not bundle.records:
        return CheckResult(name="range membership", result="not present", detail="no records in the bundle")
    if bundle.completeness_certificate is None or bundle.checkpoint is None:
        return CheckResult(
            name="range membership",
            result="not checked",
            detail="no completeness certificate/checkpoint in the bundle to verify membership against",
        )
    membership = bundle.verification.per_record_membership
    detail = "; ".join(membership.findings)
    if membership.status == "fail":
        return CheckResult(name="range membership", result="failed", detail=detail or "membership verification failed")
    if membership.status == "withheld":
        return CheckResult(
            name="range membership", result="not checked", detail=detail or "completeness evidence withheld"
        )
    if membership.findings:
        return CheckResult(name="range membership", result="inconclusive", detail=detail)
    return CheckResult(
        name="range membership",
        result="established",
        detail=f"{len(bundle.records)} record(s) independently verified (CLL #13 range proof + per-record inclusion proof) against the checkpointed interval",
    )


def cadence(bundle: Bundle) -> CheckResult:
    """The v2 Evidence Bundle declares no attestation-window period -- there
    is nothing to bound record timestamps against. Always ``not present``."""
    return CheckResult(
        name="cadence",
        result="not present",
        detail="the v2 Evidence Bundle declares no period for this check to bound record timestamps against",
    )


def key_hygiene(bundle: Bundle) -> CheckResult:
    """An AAC Capsule record carries no per-record signer-key field -- there
    is nothing here for this check to recompute rotation against. Always
    ``not present``."""
    return CheckResult(
        name="key hygiene",
        result="not present",
        detail="AAC capsule records carry no per-record signer-key field for this check to recompute rotation against",
    )


def profile_conformance(bundle: Bundle, profile_id: str, policy_module: PolicyModule) -> CheckResult:
    """Every ``action_type`` present in the bundle's records has a
    policy-module check named after it, or reads ``not checked``. Calls
    ``policy_module.check`` once; never interprets what a covered kind's own
    result says -- only whether the kind was covered at all.
    """
    kinds = sorted({r["action_type"] for r in bundle.records if isinstance(r.get("action_type"), str)})
    if not kinds:
        return CheckResult(name="profile conformance", result="not present", detail="no records in the bundle")
    covered = {cr.name for cr in policy_module.check(bundle, profile_id)}
    missing = [k for k in kinds if k not in covered]
    if not missing:
        return CheckResult(
            name="profile conformance",
            result="established",
            detail=f"every action_type ({', '.join(kinds)}) has a policy-module check",
        )
    if len(missing) == len(kinds):
        return CheckResult(
            name="profile conformance",
            result="not checked",
            detail=f"no policy module coverage for any action_type present: {', '.join(kinds)}",
        )
    return CheckResult(
        name="profile conformance",
        result="inconclusive",
        detail=f"action_type(s) with no policy-module coverage: {', '.join(missing)}",
    )
