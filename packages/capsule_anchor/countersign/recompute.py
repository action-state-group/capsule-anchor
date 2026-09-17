# SPDX-License-Identifier: Apache-2.0
"""The recompute skeleton -- the shape ported from this project's existing
blind-verification reference (a function that verifies a signed package
over hashes and signatures only, never plaintext): run every check
independently, never short-circuit on the first failure, collect every
result, then assemble the verdict. Nothing else from that reference is
reused -- the package format it verified is retired, and this recomputes a
withheld bundle instead.
"""

from __future__ import annotations

from datetime import datetime, timezone

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.checks import (
    cadence,
    chain_consistency,
    key_hygiene,
    profile_conformance,
    range_membership,
)
from capsule_anchor.countersign.policy import PolicyModule
from capsule_anchor.countersign.results import CheckResult
from capsule_anchor.countersign.statement import Scope, Statement

#: Always present on a statement -- named every time, never implied by
#: absence. Capture coverage and outcome correctness are exactly what this
#: recompute never claims: it establishes structure and signatures, never
#: that everything that happened was captured or that the judged outcome
#: was correct.
EXCLUSIONS: tuple[str, ...] = (
    "capture coverage: not checked by this statement -- a declared-count "
    "reconciliation, when present in the bundle, is reported as its own "
    "named check and stands on its own, never folded into another check's "
    "result",
    "outcome correctness: not checked by this statement -- this recompute "
    "verifies structure, sequence, and signatures, never the substance of a "
    "judgment",
)


def recompute_statement(
    bundle: Bundle, *, policy_module: PolicyModule, ledger_id: str, profile_id: str
) -> Statement:
    """Recompute every check for ``bundle`` and assemble the resulting
    statement. Mirrors ``verify_package_blind``'s collect-everything shape:
    each check function below is called unconditionally, in order, and its
    result recorded regardless of what came before it.

    ``ledger_id`` and ``profile_id`` come from the countersign request
    itself (``requester.id`` and ``profile_id``), never from the bundle: the
    v2 Evidence Bundle carries no issuer identity and no profile object of
    its own.
    """
    checks: list[CheckResult] = []
    checks.append(chain_consistency(bundle))
    checks.append(range_membership(bundle))
    checks.append(cadence(bundle))
    checks.append(key_hygiene(bundle))
    checks.append(profile_conformance(bundle, profile_id, policy_module))
    checks.extend(policy_module.check(bundle, profile_id))

    return Statement(
        checks=checks,
        exclusions=list(EXCLUSIONS),
        scope=Scope(ledger_id=ledger_id, closure_depth=bundle.closure_depth),
        recomputed_at=datetime.now(timezone.utc),
    )
