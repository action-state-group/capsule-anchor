# SPDX-License-Identifier: Apache-2.0
"""Env-driven gating for the countersign module.

Two independent switches, both required. Either alone leaves the witness's
default (permissive) behavior untouched -- this module never activates by
accident.
"""

from __future__ import annotations

import os

#: The only accepted value of CAPSULE_ANCHOR_REGISTRATION_POLICY that
#: activates this module. Any other value (including unset) leaves the
#: instance on the witness's existing permissive registration behavior.
REGISTRATION_POLICY_STRICT = "strict"

_ENV_POLICY = "CAPSULE_ANCHOR_REGISTRATION_POLICY"
_ENV_ENABLED = "CAPSULE_ANCHOR_COUNTERSIGN"


def registration_policy() -> str | None:
    return os.environ.get(_ENV_POLICY) or None


def countersign_enabled() -> bool:
    return os.environ.get(_ENV_ENABLED) == "1"


def strict_countersign_active() -> bool:
    """True only when the operator has explicitly chosen strict
    registration AND opted into the countersign endpoints. Checked at app
    startup to decide whether to mount ``countersign.router``."""
    return countersign_enabled() and registration_policy() == REGISTRATION_POLICY_STRICT
