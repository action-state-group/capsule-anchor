# SPDX-License-Identifier: Apache-2.0
"""The policy-module interface every profile's checks are loaded through.

This engine ships NO policy modules. ``check()`` is profile-specific
vocabulary -- what a record kind means, what its content must satisfy --
and that is exactly the boundary this repo does not cross.
``NullPolicyModule`` below is a test double only: it exists so the five
generic checks and statement assembly can be exercised without a real
module, and so "no coverage" has one defined, testable behavior (every
record kind reads ``not checked`` in ``checks.profile_conformance``, never
silently passes).

``profile`` is a plain profile id string, not a bundle field: the v2
Evidence Bundle carries no ``profile`` object of its own (that was the ad-hoc
bundle model's invention) -- a countersign request names its profile
explicitly (``CountersignRequest.profile_id``), so that is what a policy
module resolves against.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from capsule_anchor.countersign.results import CheckResult

if TYPE_CHECKING:
    from capsule_anchor.countersign.bundle import Bundle


class DisclosureRefused(ValueError):
    """Base of the refusal a policy module raises from ``check`` for a
    disclosed payload it must not read (digest mismatch, non-closed shape).
    The router answers it with a 422, never a 500. A module package defines
    its own refusal as a subclass of this."""


class PolicyModule(Protocol):
    """``check(bundle, profile_id) -> [{name, result, detail}]``.

    An implementation owns its vocabulary entirely: what a record kind
    means, what its content must satisfy, what counts as
    established/failed for THAT profile. This package calls ``check`` and
    folds the results into the statement unchanged -- it never inspects or
    reinterprets a module's verdicts.

    ``reads_disclosed_kinds`` (optional, default: none) names the record
    kinds (``action_type``) whose disclosed ``agent_input`` this module reads.
    A countersign request's ``disclosures`` overlay is refused unless every
    disclosed record's kind is named here (data minimisation: nothing is
    disclosed that the named profile does not read). A module that does not
    define it reads no disclosure.
    """

    reads_disclosed_kinds: frozenset[str]

    def check(self, bundle: "Bundle", profile_id: str) -> list[CheckResult]: ...


def reads_disclosed_kinds(module: object) -> frozenset[str]:
    """The kinds ``module`` declares it reads a disclosure of (none if it
    declares nothing or something that is not a set of strings)."""
    kinds = getattr(module, "reads_disclosed_kinds", None)
    if isinstance(kinds, (set, frozenset)) and all(isinstance(k, str) for k in kinds):
        return frozenset(kinds)
    return frozenset()


class NullPolicyModule:
    """Test double. Declares no coverage for any record kind -- every kind
    in a bundle reads ``not checked`` via ``checks.profile_conformance``.
    Ships with this package because the engine must be exercisable with
    zero real policy modules; a concrete module is always a separate
    package, loaded by profile id through :class:`PolicyRegistry`."""

    def check(self, bundle: "Bundle", profile_id: str) -> list[CheckResult]:
        return []


class PolicyRegistry:
    """Maps a profile id to the :class:`PolicyModule` that implements it.

    Populated by whoever deploys an instance; starts with only the
    ``NullPolicyModule`` test double registered, under ``test/v0``.
    """

    def __init__(self) -> None:
        self._modules: dict[str, PolicyModule] = {}

    def register(self, profile_id: str, module: PolicyModule) -> None:
        self._modules[profile_id] = module

    def get(self, profile_id: str) -> PolicyModule | None:
        return self._modules.get(profile_id)


_DEFAULT_REGISTRY = PolicyRegistry()
_DEFAULT_REGISTRY.register("test/v0", NullPolicyModule())


def default_registry() -> PolicyRegistry:
    return _DEFAULT_REGISTRY
