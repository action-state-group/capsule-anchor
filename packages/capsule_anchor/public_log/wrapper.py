"""``attach_public_log`` -- glue an ``AnchorerService`` to a ``PublicLog``.

This is a *wrapper*, not a service edit: we monkey-patch the supplied
anchorer's ``anchor()`` method so each call additionally publishes the LATEST
Signed Tree Head to the given public log. The anchoring package itself is
untouched -- if the team later wants a first-class ``public_log`` hook on the
service, this wrapper documents the seam.

NO PLAINTEXT INVARIANT (enforced HERE, deliberately):

  * We submit the EXACT bytes returned by ``sth_payload(tree_size, root_hash,
    timestamp)`` -- those are the canonical STH bytes the authority signs.
    They contain only a tree size, a Merkle root (a hash), and a timestamp.
  * We never see, read, or forward the tenant ``root_hash`` independently of
    the STH; we never touch ledger plaintext, commitments, or encrypted blobs.

The wrapper returns the public-log receipt to callers by attaching it onto
the ``AnchorReceipt.proof`` dict under ``"public_log"`` (a dict already used
for backend-specific data), so existing call sites and tests are unaffected.
"""

from __future__ import annotations

from typing import Any, Protocol

from capsule_anchor.contracts.types import AnchorReceipt, Signature

# We import from anchoring/ ONLY for the payload helpers. Anchoring is a
# sibling package and we are not modifying it.
from capsule_anchor.anchoring.service import sth_payload


class _PublicLogLike(Protocol):
    def submit(self, payload: bytes, sig: Signature) -> dict: ...
    def name(self) -> str: ...


def attach_public_log(anchorer: Any, public_log: _PublicLogLike) -> Any:
    """Wrap ``anchorer.anchor`` so each call also publishes the latest STH.

    Returns the same ``anchorer`` (mutated in place) for fluent use. Safe to
    call once per anchorer; calling twice raises so a stack of wrappers can't
    silently double-publish.
    """
    if getattr(anchorer, "_public_log_attached", False):
        raise RuntimeError("public log already attached to this anchorer")

    original_anchor = anchorer.anchor

    def anchor_with_public_log(
        tenant_id: str, root_hash: str, seq_range: tuple[int, int]
    ) -> AnchorReceipt:
        receipt = original_anchor(tenant_id, root_hash, seq_range)
        # The freshly-signed STH covers the new log entry.
        sth = anchorer.get_sth()
        payload = sth_payload(sth.tree_size, sth.root_hash, sth.timestamp)
        public_receipt = public_log.submit(payload, sth.signature)
        # Attach the public-log receipt onto the AnchorReceipt's proof dict so
        # callers can surface it without changing the AnchorReceipt schema.
        receipt.proof = dict(receipt.proof or {})
        receipt.proof["public_log"] = {
            "backend": public_log.name(),
            "receipt": public_receipt,
            "sth_tree_size": sth.tree_size,
            "sth_root_hash": sth.root_hash,
        }
        return receipt

    anchorer.anchor = anchor_with_public_log  # type: ignore[method-assign]
    anchorer._public_log_attached = True  # type: ignore[attr-defined]
    anchorer._public_log = public_log  # type: ignore[attr-defined]
    return anchorer
