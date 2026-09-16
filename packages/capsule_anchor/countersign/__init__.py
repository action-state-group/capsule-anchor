# SPDX-License-Identifier: Apache-2.0
"""The countersign module: strict registration, generic recompute checks,
the statement, the signer, and the webhook deliverer.

Additive to the witness this repo already ships. Mounted only when the
operator sets BOTH ``CAPSULE_ANCHOR_REGISTRATION_POLICY=strict`` and
``CAPSULE_ANCHOR_COUNTERSIGN=1`` (see ``config.py``); the default
(permissive) witness instance is unchanged by this package's presence.

This package ships NO policy modules -- ``policy.NullPolicyModule`` is a
test double only. A profile's checks (what a record kind means, what its
content must satisfy) are supplied by whoever deploys an instance; this
package only defines the interface they are loaded through and the five
generic checks every profile shares.
"""

from __future__ import annotations

from .bundle import Bundle, BundleRefused, accept_bundle, compute_bundle_digest, parse_bundle
from .config import strict_countersign_active
from .issuers import IssuerAllowlist
from .recompute import recompute_statement
from .results import CheckResult, Result
from .signer import sign_countersignature
from .statement import Statement
from .verify import resolve_entry_state

__all__ = [
    "Bundle",
    "BundleRefused",
    "CheckResult",
    "IssuerAllowlist",
    "Result",
    "Statement",
    "accept_bundle",
    "compute_bundle_digest",
    "parse_bundle",
    "recompute_statement",
    "resolve_entry_state",
    "sign_countersignature",
    "strict_countersign_active",
]
