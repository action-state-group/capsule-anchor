# SPDX-License-Identifier: Apache-2.0
"""Entry-retention policy — the configurable half of the asymmetric retention trade.

Roots (``signed_tree_heads`` /
``signed_tree_head_history``) are retained indefinitely no matter what this
module says — see ``store.py``'s module docstring. This module governs only
the receipt CACHE (``submitted_statements``, the "re-issue a lost proof"
convenience path). The append-only CT log itself (``log_entries``) is never
pruned by any setting here: its row count IS ``tree_size``, a structural
invariant no retention policy may violate.

Three things our retention actually governs, in order of what is lost first:
(1) re-issuing a receipt someone lost — convenience, governed here;
(2) consistency from an old entry to the present — the real property, backed
    by the indefinitely-retained root history, unaffected by this knob;
(3) equivocation/fork detection over time — backed by
    ``checkpoint_equivocations``, never deleted, unaffected by this knob.

We deliberately do NOT copy CCF's retention-relaxation conclusion. CCF can
relax retention because hardware attestation plus reproducible builds gives a
verifier a substitute for re-deriving the log's own history. This witness has
no confidential-computing attestation; taking retention relaxation without
that substitute would leave a relying party with neither property. The
default here stays unlimited precisely because we have nothing to hand a
verifier in its place.
"""

from __future__ import annotations

import os

_ENV_RETENTION = "CAPSULE_ANCHOR_ENTRY_RETENTION"

#: The only value (besides unset) that means "no pruning" — must match what
#: /health reports so a relying party reads the same word we act on.
UNLIMITED = "unlimited"


def entry_retention_seconds() -> int | None:
    """The configured entry-retention window in seconds, or ``None`` for
    unlimited (the default — today's behaviour, unchanged on upgrade).

    Unset, empty, or the literal ``"unlimited"`` (case-insensitive) all mean
    unlimited. Any other value must parse as a positive integer number of
    seconds; anything else fails closed (a malformed retention setting must
    never silently fall back to "keep everything forever" OR "delete
    everything now" — both are surprising, so we refuse to start instead).
    """
    raw = os.environ.get(_ENV_RETENTION)
    if not raw or raw.strip().lower() == UNLIMITED:
        return None
    try:
        seconds = int(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"{_ENV_RETENTION}={raw!r} is not {UNLIMITED!r} or an integer "
            "number of seconds"
        ) from exc
    if seconds <= 0:
        raise RuntimeError(
            f"{_ENV_RETENTION}={raw!r} must be a positive number of seconds"
        )
    return seconds


def declared_posture() -> str:
    """Human-readable posture string for the service descriptor / ``/health``
    — see ``AnchorerService`` docs. A policy nobody can read is not a
    promise, so this must always be a value a relying party can act on
    BEFORE depending on the service, never after."""
    seconds = entry_retention_seconds()
    return UNLIMITED if seconds is None else f"{seconds}s"
