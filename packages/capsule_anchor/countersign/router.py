# SPDX-License-Identifier: Apache-2.0
"""FastAPI router for the countersign module (prefix ``/countersign``).

Mounted by ``app.py`` only when ``config.strict_countersign_active()`` is
true -- the witness's default (permissive) instance never gains this
router. One endpoint: submit a withheld bundle plus the requester's own
signature over its digest, get back a ``countersignatures[]`` array
synchronously in the response (``{"countersignatures": [entry]}``, matching
``capsulectl countersign request``'s ``countersignSubmissionResponse``), and
(if a webhook subscription is given) delivered in a background task so a
slow or dead subscriber endpoint never blocks the response --
``deliver_webhook``'s own retry backoff runs up to ~21s, which must never
sit in the request path.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, ValidationError

from capsule_anchor.anchoring.router import _SlidingWindowLimiter
from capsule_anchor.anchoring.service import MAX_STATEMENT_BYTES
from capsule_anchor.countersign.bundle import BundleRefused, accept_bundle
from capsule_anchor.countersign.issuers import IssuerAllowlist
from capsule_anchor.countersign.policy import NullPolicyModule, PolicyRegistry, default_registry
from capsule_anchor.countersign.recompute import recompute_statement
from capsule_anchor.countersign.signer import Attestor, Registrar, sign_countersignature
from capsule_anchor.countersign.webhooks import (
    WebhookSubscription,
    WebhookURLRefused,
    deliver_webhook,
    validate_webhook_url,
)

_attestor: Attestor | None = None
_registrar: Registrar | None = None
_registry: PolicyRegistry = default_registry()
_issuers: IssuerAllowlist = IssuerAllowlist()

# Dedicated rate limiter for /countersign/register -- the same 300/min
# convention as the anchoring surface's shared ``_POST_LIMITER``, but a
# SEPARATE instance/budget: this endpoint does a sig-verify + sign +
# log-append per call (heavier than a digest registration) and must never
# share a budget with, or be starved by, the witness surface's own traffic.
_COUNTERSIGN_POST_LIMITER = _SlidingWindowLimiter(max_calls=300, window_s=60.0)


def configure_service(attestor: Attestor, registrar: Registrar) -> None:
    """Install the shared authority attestor and log registrar this router
    signs and registers statements through -- called once from ``app.py``
    with the same instances the anchoring/attestation subsystems use, so
    there is exactly one authority signing root and one log."""
    global _attestor, _registrar
    _attestor = attestor
    _registrar = registrar


def configure_registry(registry: PolicyRegistry) -> None:
    """Swap in a different policy registry -- used by tests; production
    instances that never register a real module keep the default (which
    resolves only the ``test/v0`` double)."""
    global _registry
    _registry = registry


def configure_issuers(issuers: IssuerAllowlist) -> None:
    """Install this instance's registration-policy trust anchor -- called
    once from ``app.py``. An instance that never calls this keeps the empty
    default, which refuses every registration (fail-closed, never open)."""
    global _issuers
    _issuers = issuers


class CountersignRequester(BaseModel):
    """The wire's ``requester`` object -- who is asking, distinct from the
    bundle's own content (the v2 Evidence Bundle carries no issuer identity
    of its own). Matches ``capsulectl``'s ``CountersignSigner``."""

    id: str
    key_id: str


class CountersignRequest(BaseModel):
    """The countersign submission body ``capsulectl countersign request``
    POSTs: the withheld bundle, an advisory attestation-window label (never
    interpreted by this recompute -- the v2 bundle declares no period for
    it to bound anything against), the requester's own identity, and the
    requester's signature over the bundle digest proving who is asking.

    ``profile_id`` is optional and, as of the current ``capsulectl``
    ``countersignSubmission`` wire shape, never actually sent -- that struct
    has no ``profile_id`` field at all (verified against a real
    ``capsulectl``-built submission). A
    submission that never names one gets the five generic checks only
    (``NullPolicyModule`` -- no profile-specific coverage, never a refusal);
    a submission that DOES name one must have it registered, or the
    registration is refused (see ``register`` below)."""

    bundle: dict
    window: str | None = None
    requester: CountersignRequester
    requester_signature: str
    profile_id: str | None = None
    webhook_url: str | None = None
    webhook_secret: str | None = None


def get_router() -> APIRouter:
    router = APIRouter(prefix="/countersign", tags=["countersign"])

    @router.post("/register")
    async def register(request: Request, background_tasks: BackgroundTasks) -> dict:
        if not _COUNTERSIGN_POST_LIMITER.is_allowed():
            raise HTTPException(status_code=429, detail="rate limit exceeded — try again later")

        body = await request.body()
        if len(body) > MAX_STATEMENT_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"request body too large ({len(body)} bytes; max {MAX_STATEMENT_BYTES})",
            )
        try:
            req = CountersignRequest.model_validate_json(body)
        except ValidationError as exc:
            raise HTTPException(
                status_code=422, detail=f"request body is not a valid countersign submission: {exc}"
            ) from exc

        try:
            bundle = accept_bundle(
                req.bundle,
                _issuers,
                requester_id=req.requester.id,
                requester_key_hex=req.requester.key_id,
                requester_signature_hex=req.requester_signature,
            )
        except BundleRefused as exc:
            raise HTTPException(status_code=422, detail=f"refused: {exc}") from exc

        if req.profile_id:
            module = _registry.get(req.profile_id)
            if module is None:
                raise HTTPException(
                    status_code=422,
                    detail=f"refused: no policy module registered for profile {req.profile_id!r}",
                )
        else:
            # No profile named -- run the five generic checks only, never a
            # refusal: capsulectl's current countersignSubmission wire shape
            # has no profile_id field to send one with.
            module = NullPolicyModule()

        if _attestor is None or _registrar is None:
            raise HTTPException(status_code=503, detail="countersign module not configured")

        public_host = os.environ.get("CAPSULE_ANCHOR_PUBLIC_HOST")
        if not public_host:
            raise HTTPException(
                status_code=503,
                detail="CAPSULE_ANCHOR_PUBLIC_HOST is not configured -- this instance cannot "
                "publish a did:web signer identity without it",
            )
        signer_id = f"did:web:{public_host}"

        statement = recompute_statement(
            bundle, policy_module=module, ledger_id=req.requester.id, profile_id=req.profile_id or ""
        )
        entry = sign_countersignature(
            bundle,
            statement,
            attestor=_attestor,
            registrar=_registrar,
            signer_id=signer_id,
            requester_key_id=req.requester.key_id,
        )

        if req.webhook_url and req.webhook_secret:
            try:
                validate_webhook_url(req.webhook_url)
            except WebhookURLRefused as exc:
                raise HTTPException(status_code=422, detail=f"webhook_url refused: {exc}") from exc
            background_tasks.add_task(
                deliver_webhook,
                WebhookSubscription(url=req.webhook_url, secret=req.webhook_secret),
                entry,
                entry_hash=entry["receipt"]["entry_hash"],
            )

        return {"countersignatures": [entry]}

    return router
