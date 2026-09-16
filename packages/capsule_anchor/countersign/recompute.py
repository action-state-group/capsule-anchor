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
from capsule_anchor.countersign.statement import Scope, Statement, StatementProfile

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


def recompute_statement(bundle: Bundle, *, policy_module: PolicyModule) -> Statement:
    """Recompute every check for ``bundle`` and assemble the resulting
    statement. Mirrors ``verify_package_blind``'s collect-everything shape:
    each check function below is called unconditionally, in order, and its
    result recorded regardless of what came before it.
    """
    checks: list[CheckResult] = []
    checks.append(chain_consistency(bundle))
    checks.append(range_membership(bundle))
    checks.append(cadence(bundle))
    checks.append(key_hygiene(bundle))
    checks.append(profile_conformance(bundle, policy_module))
    checks.extend(policy_module.check(bundle, bundle.profile))

    return Statement(
        checks=checks,
        exclusions=list(EXCLUSIONS),
        scope=Scope(
            ledger_id=bundle.ledger_id,
            period=bundle.period,
            closure_depth=bundle.closure_depth,
        ),
        profile=StatementProfile(id=bundle.profile.id, version=bundle.profile.version),
        recomputed_at=datetime.now(timezone.utc),
    )
