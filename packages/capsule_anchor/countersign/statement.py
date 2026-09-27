# SPDX-License-Identifier: Apache-2.0
"""The statement: what a recompute establishes, what it excludes, and over
what scope -- the object the signer signs and the ``countersignatures[]``
entry carries.
"""

from __future__ import annotations

from datetime import datetime

from agent_action_capsule.canonical import jcs
from pydantic import BaseModel

from capsule_anchor.countersign.results import CheckResult


class Scope(BaseModel):
    """What a countersignature attests over. ``ledger_id`` is the
    countersign request's own ``requester.id`` -- never a bundle field: the
    v2 Evidence Bundle carries no issuer identity of its own.
    ``closure_depth`` is read from the bundle's own
    ``completeness.closure_depth``. There is no ``period`` field: the v2
    bundle declares no attestation window (the Go wire's own
    ``CountersignScope.Period`` is already optional/``omitempty`` for
    exactly this reason -- this instance simply never emits one)."""

    ledger_id: str
    closure_depth: int


class Statement(BaseModel):
    """No ``profile`` field ([countersign-whole-bundle-shape], found via the
    live request-path round trip): a prior revision carried one, but
    ``capsulectl``'s Go ``CountersignStatement`` struct does not declare it,
    and the CLI's real request path decodes with
    ``json.Decoder.DisallowUnknownFields()`` -- an extra field ANYWHERE in
    the decoded entry, including nested inside ``statement``, is a hard
    decode failure there. The prior wire-shape reconciliation (#47) never
    caught this because its own entry-interop test decoded a fixture through
    a lenient ``json.Unmarshal`` (``verifyCountersignatures``'s own entry
    decode, never the strict ``requestCountersignatures``/``decodeJSON``
    path) -- it proved the entry could be READ, never that a real request
    could be MADE. A submission's own ``profile_id`` is never lost:
    ``checks.profile_conformance``'s own ``detail`` string already names
    which ``action_type``s were/weren't covered. See :meth:`wire_dict` for
    the two further fields (``exclusions``, per-check ``detail``) the same
    round trip found missing from capsulectl's structs."""

    checks: list[CheckResult]
    #: Always present, always names capture coverage and outcome
    #: correctness explicitly -- never implied by an absent entry.
    exclusions: list[str]
    scope: Scope
    recomputed_at: datetime

    def wire_dict(self) -> dict:
        """The projection actually put on the wire (and signed/receipted --
        see ``canonical_bytes``): ``{checks, recomputed_at, scope}`` only --
        each check as ``{name, result}``, no ``detail``, and no top-level
        ``exclusions``.

        Found by the same live request-path round trip as the missing
        ``profile`` field (both this module and #47's own capsulectl
        ``CountersignStatement``/``CountersignCheck`` Go structs are
        deliberately minimal -- ``{checks:[{name,result}], recomputed_at,
        scope}`` -- and the CLI's real request path decodes with
        ``json.Decoder.DisallowUnknownFields()``: any extra key anywhere in
        the decoded entry is a hard failure there, never merely ignored).
        ``exclusions`` and every check's ``detail`` remain first-class,
        always-populated fields on the internal ``Statement``/``CheckResult``
        this module produces (every check function in ``checks.py``, every
        test, §1/§2's own contract) -- only this wire projection omits them,
        pending the entry-shape's own ratification (which may carry them once
        capsule-cli's structs grow to match)."""
        dumped = self.model_dump(mode="json")
        dumped["checks"] = [{"name": c["name"], "result": c["result"]} for c in dumped["checks"]]
        del dumped["exclusions"]
        return dumped

    def canonical_bytes(self) -> bytes:
        """The JCS (RFC 8785) bytes of the wire projection (``wire_dict``) --
        the bytes whose SHA-256 this instance registers in its own log for
        the entry's receipt. JCS, not ad-hoc sorted-key JSON, so any
        implementation holding only the entry's ``statement`` member
        reproduces the identical bytes and can check the receipt.

        This is NOT the signing input: the signature covers ``over``,
        ``signer``, ``statement`` and ``type`` together (see
        ``signer.countersign_signing_input``)."""
        return jcs(self.wire_dict())
