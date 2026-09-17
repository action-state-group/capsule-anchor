"""External PUBLIC transparency-log backends (in addition to the built-in
RFC 9162 CT log in ``anchoring/``).

Newly produced Signed Tree Heads are also submitted to a third-party-operated
log (Sigstore Rekor by default) so the RFC 6962 anchor is independently
verifiable by any external CT monitor — not only parties querying this service
directly.

CRITICAL invariant: ONLY Signed Tree Heads — content-free structures containing
``tree_size``, ``root_hash``, and ``timestamp`` — are submitted to the external
log. Statement payloads, commitment values, and capsule content are NEVER sent.
See module docstrings and ``docs/architecture/18-public-log-anchor.md``.
"""

from .in_memory import InMemoryPublicLog
from .receipt_augment import augment_receipt_with_public_log
from .rekor import RekorBundle, RekorPublicLog
from .scheduler import PublicLogPublisher, start_publisher_thread
from .wrapper import attach_public_log

__all__ = [
    "InMemoryPublicLog",
    "PublicLogPublisher",
    "RekorBundle",
    "RekorPublicLog",
    "attach_public_log",
    "augment_receipt_with_public_log",
    "start_publisher_thread",
]
