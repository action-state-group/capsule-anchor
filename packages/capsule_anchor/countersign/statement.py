# SPDX-License-Identifier: Apache-2.0
"""The statement: what a recompute establishes, what it excludes, and over
what scope -- the object the signer signs and the ``countersignatures[]``
entry carries.
"""

from __future__ import annotations

import json
from datetime import datetime

from pydantic import BaseModel

from capsule_anchor.countersign.bundle import BundlePeriod
from capsule_anchor.countersign.results import CheckResult


class Scope(BaseModel):
    ledger_id: str
    period: BundlePeriod
    closure_depth: int


class StatementProfile(BaseModel):
    id: str
    version: str


class Statement(BaseModel):
    checks: list[CheckResult]
    #: Always present, always names capture coverage and outcome
    #: correctness explicitly -- never implied by an absent entry.
    exclusions: list[str]
    scope: Scope
    profile: StatementProfile
    recomputed_at: datetime

    def canonical_bytes(self) -> bytes:
        """Deterministic JSON the signer signs over -- sorted keys, compact
        separators, ``by_alias=True`` (``scope.period`` carries the same
        ``from``/``schema`` aliasing as :class:`bundle.Bundle` -- see
        ``bundle.compute_bundle_digest``) -- so any implementation
        reproduces identical bytes from the same statement fields."""
        return json.dumps(
            self.model_dump(mode="json", by_alias=True), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
