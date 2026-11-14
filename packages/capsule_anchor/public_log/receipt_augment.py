"""Attach public-log evidence to an ALREADY-SIGNED COSE Receipt's UNPROTECTED
header only.

A checkpoint's COSE Receipt is signed once,
at registration time (``AnchorerService.build_cose_receipt`` /
``witness_checkpoint``), and its bytes are cached verbatim for idempotent
resubmission (``store.put_statement`` / ``put_checkpoint_record``). A Rekor
publication for that receipt's tree_size (or a later one covering it) can
only exist SOME TIME AFTER registration -- the scheduled publisher runs on an
interval, never inline on the request path (see ``scheduler.py``). So the
public-log evidence cannot be signed in at issuance time; it is attached at
SERVE time, into the receipt's UNPROTECTED header, which the Sig_structure
never covers (RFC 9052 §4.4: only the protected bstr + payload are signed).
This keeps the signature valid and the PROTECTED content byte-for-byte
unchanged for every receipt ever issued -- see the module docstring invariant
in ``anchoring/service.py`` and [witness-receipt-signed-time-and-grade].

The cached/persisted receipt bytes are NEVER mutated -- this function returns
a NEW bytes object built from the decoded original; callers augment only the
copy handed back to a caller of a surfacing endpoint.
"""

from __future__ import annotations

import cbor2

#: COSE_Sign1 (RFC 9052 §4.2) tag; must match ``anchoring.service._COSE_SIGN1_TAG``.
_COSE_SIGN1_TAG = 18
#: Unprotected, private-use label carrying the public-log evidence map --
#: next in the private-use sequence after ``anchoring.service``'s 395/396
#: (vds/vdp) and -65537/-65538 (grade/continuity), chosen from the OTHER side
#: of the private-use range (unprotected, positive) since this is
#: unauthenticated evidence, not a witness claim.
COSE_PUBLIC_LOG_LABEL = 397


def augment_receipt_with_public_log(receipt_bytes: bytes, public_log_entry: dict) -> bytes:
    """Return a COPY of ``receipt_bytes`` whose UNPROTECTED header additionally
    carries ``{397: public_log_entry}``.

    ``public_log_entry`` is expected to be exactly
    ``{"backend": ..., "uuid": ..., "log_index": ..., "sth_tree_size": ...}``
    -- content-free coordinates into the external log, never capsule content.

    Raises ``ValueError`` if ``receipt_bytes`` isn't a well-formed COSE_Sign1
    (tag 18, 4-element array) -- a programming error if it happens, since
    this is only ever called on bytes this service itself just built.
    """
    tagged = cbor2.loads(receipt_bytes)
    if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != _COSE_SIGN1_TAG:
        raise ValueError("not a COSE_Sign1 (tag 18) message")
    arr = tagged.value
    if not isinstance(arr, (list, tuple)) or len(arr) != 4:
        raise ValueError("COSE_Sign1 array must have exactly 4 elements")
    protected_bstr, unprotected, payload, signature = arr
    new_unprotected = dict(unprotected) if isinstance(unprotected, dict) else dict(unprotected or {})
    new_unprotected[COSE_PUBLIC_LOG_LABEL] = dict(public_log_entry)
    new_tagged = cbor2.CBORTag(
        _COSE_SIGN1_TAG, [protected_bstr, new_unprotected, payload, signature]
    )
    return cbor2.dumps(new_tagged)
