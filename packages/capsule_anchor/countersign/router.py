# SPDX-License-Identifier: Apache-2.0
"""FastAPI router for the countersign module (prefix ``/countersign``).

Mounted by ``app.py`` only when ``config.strict_countersign_active()`` is
true -- the witness's default (permissive) instance never gains this
router. One endpoint: submit a withheld bundle, get back the
``countersignatures[]`` entry synchronously in the response, and (if a
webhook subscription is given) delivered in a background task so a slow or
dead subscriber endpoint never blocks the response -- ``deliver_webhook``'s
own retry backoff runs up to ~21s, which must never sit in the request path.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from capsule_anchor.countersign.bundle import BundleRefused, accept_bundle
from capsule_anchor.countersign.issuers import IssuerAllowlist
from capsule_anchor.countersign.policy import PolicyRegistry, default_registry
from capsule_anchor.countersign.recompute import recompute_statement
from capsule_anchor.countersign.signer import Attestor, Registrar, sign_countersignature
from capsule_anchor.countersign.webhooks import WebhookSubscription, deliver_webhook

_attestor: Attestor | None = None
_registrar: Registrar | None = None
_registry: PolicyRegistry = default_registry()
_issuers: IssuerAllowlist = IssuerAllowlist()


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


class CountersignRequest(BaseModel):
    bundle: dict
    profile_id: str | None = None
    webhook_url: str | None = None
    webhook_secret: str | None = None


def get_router() -> APIRouter:
    router = APIRouter(prefix="/countersign", tags=["countersign"])

    @router.post("/register")
    def register(req: CountersignRequest, background_tasks: BackgroundTasks) -> dict:
        try:
            bundle = accept_bundle(req.bundle, _issuers)
        except BundleRefused as exc:
            raise HTTPException(status_code=422, detail=f"refused: {exc}") from exc

        profile_id = req.profile_id or bundle.profile.id
        module = _registry.get(profile_id)
        if module is None:
            raise HTTPException(
                status_code=422,
                detail=f"refused: no policy module registered for profile {profile_id!r}",
            )

        if _attestor is None or _registrar is None:
            raise HTTPException(status_code=503, detail="countersign module not configured")

        public_host = os.environ.get("CAPSULE_ANCHOR_PUBLIC_HOST")
        signer_id = f"did:web:{public_host}"

        statement = recompute_statement(bundle, policy_module=module)
        entry = sign_countersignature(
            bundle,
            statement,
            attestor=_attestor,
            registrar=_registrar,
            signer_id=signer_id,
        )

        if req.webhook_url and req.webhook_secret:
            background_tasks.add_task(
                deliver_webhook,
                WebhookSubscription(url=req.webhook_url, secret=req.webhook_secret),
                entry,
                entry_hash=entry["receipt"]["entry_hash"],
            )

        return entry

    return router
