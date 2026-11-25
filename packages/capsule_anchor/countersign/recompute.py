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

from collections.abc import Mapping
from datetime import datetime, timezone

from pydantic import ValidationError

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.checks import (
    cadence,
    chain_consistency,
    key_hygiene,
    profile_conformance,
    range_membership,
)
from capsule_anchor.countersign.policy import PolicyModule
from capsule_anchor.countersign.results import RESULTS, CheckResult
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


class ModuleResultInvalid(ValueError):
    """A policy module returned a check result that is not a valid
    ``CheckResult`` (a result word outside the five-word vocabulary, a foreign
    type). The fault is the module's, not the request's: the router answers
    it with a 502 naming the check and the offending value, never a bare 500."""


def _module_results(policy_module: PolicyModule, bundle: Bundle, profile_id: str) -> list[CheckResult]:
    """The module's results, each a valid ``CheckResult`` (the contract the
    rest of the engine reads by attribute), or ``ModuleResultInvalid``.

    ``PolicyModule.check`` returns ``[{name, result, detail}]``: each item is a
    ``CheckResult`` or a mapping with those keys (a module package need not
    import this one's model; capsule-engine's countersign module returns a
    ``dict`` subclass). Either form is validated the same way."""
    out: list[CheckResult] = []
    returned = policy_module.check(bundle, profile_id)
    try:
        items = list(returned)
    except TypeError as exc:  # not iterable, e.g. a missing ``return`` gave None
        raise ModuleResultInvalid(
            f"the policy module for profile {profile_id!r} returned a non-iterable check result"
        ) from exc
    for item in items:
        try:
            if isinstance(item, CheckResult):
                fields = item.model_dump()
            elif isinstance(item, Mapping):
                fields = dict(item)
            else:
                raise TypeError(type(item).__name__)
            out.append(CheckResult.model_validate(fields))
        except (TypeError, ValidationError) as exc:
            # Bounded: a module may build these values from requester-supplied data.
            if isinstance(item, Mapping):
                name, result = repr(item.get("name"))[:80], repr(item.get("result"))[:80]
            else:
                name = repr(getattr(item, "name", None))[:80]
                result = repr(getattr(item, "result", None))[:80]
            raise ModuleResultInvalid(
                f"the policy module for profile {profile_id!r} returned an invalid result for "
                f"check {name}: {type(item).__name__} with result {result} "
                f"is not a CheckResult with a string name and one of "
                f"{', '.join(repr(r) for r in RESULTS)}"
            ) from exc
    return out


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
    module_results = _module_results(policy_module, bundle, profile_id)
    checks: list[CheckResult] = []
    checks.append(chain_consistency(bundle))
    checks.append(range_membership(bundle))
    checks.append(cadence(bundle))
    checks.append(key_hygiene(bundle))
    checks.append(profile_conformance(bundle, profile_id, policy_module, module_results))
    checks.extend(module_results)

    return Statement(
        checks=checks,
        exclusions=list(EXCLUSIONS),
        scope=Scope(ledger_id=ledger_id, closure_depth=bundle.closure_depth),
        recomputed_at=datetime.now(timezone.utc),
    )
