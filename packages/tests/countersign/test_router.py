"""End-to-end: the countersign router only mounts when both env switches
are set, and POST /countersign/register round-trips a withheld v2 Evidence
Bundle submission into ``{"countersignatures": [entry]}`` -- matching
``capsulectl countersign request``'s ``countersignSubmissionResponse``."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import capsule_anchor.countersign.router as router_module
from capsule_anchor.anchoring.router import _SlidingWindowLimiter
from capsule_anchor.app import create_app
from capsule_anchor.countersign.issuers import IssuerAllowlist
from capsule_anchor.countersign.router import configure_issuers

from .conftest import base_bundle_raw, sign_submission
from capsule_anchor.countersign.policy import DisclosureRefused as _BaseDisclosureRefused
from capsule_anchor.countersign.results import CheckResult


def _submission(raw, key, *, profile_id="test/v0", **extra):
    rid, rkey, rsig = sign_submission(raw, key)
    body = {
        "bundle": raw,
        "window": "30d",
        "requester": {"id": rid, "key_id": rkey},
        "requester_signature": rsig,
    }
    if profile_id is not None:
        body["profile_id"] = profile_id
    body.update(extra)
    return body


def test_countersign_router_absent_by_default():
    """The witness's default (permissive) instance never gains this router."""
    client = TestClient(create_app())
    resp = client.post("/countersign/register", json={"bundle": {}})
    assert resp.status_code == 404


def test_countersign_router_absent_with_only_one_switch(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN", "1")
    monkeypatch.delenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", raising=False)
    client = TestClient(create_app())
    resp = client.post("/countersign/register", json={"bundle": {}})
    assert resp.status_code == 404

    monkeypatch.delenv("CAPSULE_ANCHOR_COUNTERSIGN", raising=False)
    monkeypatch.setenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", "strict")
    client = TestClient(create_app())
    resp = client.post("/countersign/register", json={"bundle": {}})
    assert resp.status_code == 404


def _strict_client(monkeypatch, issuer_allowlist) -> TestClient:
    monkeypatch.setenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", "strict")
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN", "1")
    client = TestClient(create_app())
    # app.py already installs IssuerAllowlist.from_env_or_default() (empty
    # in tests, since no CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE is set) --
    # swap in the fixture's allowlist so the test's requester_key is enrolled.
    configure_issuers(issuer_allowlist)
    return client


def test_valid_bundle_round_trips_to_a_signed_entry(monkeypatch, requester_key, issuer_allowlist):
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()

    resp = client.post("/countersign/register", json=_submission(raw, requester_key))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert list(body.keys()) == ["countersignatures"]
    entry = body["countersignatures"][0]
    assert entry["receipt"]["entry_hash"]
    assert entry["statement"]["checks"]
    assert entry["independent"] is True  # the countersign instance's ephemeral key != requester's


def test_unconfigured_public_host_is_refused_not_did_web_none(monkeypatch, requester_key, issuer_allowlist):
    """A missing CAPSULE_ANCHOR_PUBLIC_HOST must fail closed -- never publish
    a broken ``did:web:None`` signer identity."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.delenv("CAPSULE_ANCHOR_PUBLIC_HOST", raising=False)
    raw = base_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key))
    assert resp.status_code == 503
    assert "CAPSULE_ANCHOR_PUBLIC_HOST" in resp.json()["detail"]


def test_unenrolled_issuer_is_refused_over_http(monkeypatch, requester_key):
    """No issuer allowlist configured (the empty default) -> every
    registration is refused, never silently accepted."""
    client = _strict_client(monkeypatch, issuer_allowlist=IssuerAllowlist())
    raw = base_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key))
    assert resp.status_code == 422
    assert "not enrolled" in resp.json()["detail"]


def test_payloads_present_is_refused_over_http(monkeypatch, requester_key, issuer_allowlist):
    """A required case: a bundle with any payload present -> refused."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()
    raw["completeness"]["payloads_mode"] = "all"
    resp = client.post("/countersign/register", json=_submission(raw, requester_key))
    assert resp.status_code == 422
    assert "refused" in resp.json()["detail"]


def test_capsulectl_withheld_bundle_round_trips_over_http(monkeypatch, requester_key, issuer_allowlist):
    """capsulectl's real ``deal report --withheld`` bundle (payloads_mode
    selected, nothing disclosed) is countersigned, not refused with a 422."""
    from .test_bundle import _capsulectl_withheld

    client = _strict_client(monkeypatch, issuer_allowlist)
    resp = client.post("/countersign/register", json=_submission(_capsulectl_withheld(), requester_key, profile_id=None))
    assert resp.status_code == 200, resp.text
    assert resp.json()["countersignatures"][0]["receipt"]["entry_hash"]


@pytest.mark.parametrize("mode", ["all", None, [], {}, 1])
def test_other_payloads_modes_are_a_422_over_http(mode, monkeypatch, requester_key, issuer_allowlist):
    from .test_bundle import _capsulectl_withheld

    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = _capsulectl_withheld()
    raw["completeness"]["payloads_mode"] = mode
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id=None))
    assert resp.status_code == 422, resp.text
    assert "refused" in resp.json()["detail"]


def test_selected_with_disclosures_is_a_422_over_http(monkeypatch, requester_key, issuer_allowlist):
    from .test_bundle import _capsulectl_withheld

    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = _capsulectl_withheld()
    raw["disclosures"] = {}
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id=None))
    assert resp.status_code == 422, resp.text


def test_selected_with_a_producer_key_extra_member_is_a_422_over_http(monkeypatch, requester_key, issuer_allowlist):
    from .test_bundle import _capsulectl_withheld

    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = _capsulectl_withheld()
    raw["extensions"]["producer-key/v1"]["disclosures"] = {"x": {"agent_input": {"secret": 1}}}
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id=None))
    assert resp.status_code == 422, resp.text


def test_webhook_delivery_runs_as_a_background_task(monkeypatch, requester_key, issuer_allowlist):
    """A webhook subscription must never block the response -- it is
    scheduled via FastAPI's BackgroundTasks, not called inline before the
    response is built. Patch deliver_webhook to record the call rather than
    hitting the network, and the DNS resolver so the SSRF guard's host
    check resolves to a public address without real network access."""
    import capsule_anchor.countersign.router as router_module
    import capsule_anchor.countersign.webhooks as webhooks_module

    calls = []

    def fake_deliver(subscription, payload, *, entry_hash):
        calls.append((subscription.url, entry_hash))

    monkeypatch.setattr(router_module, "deliver_webhook", fake_deliver)
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["93.184.216.34"])

    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()

    resp = client.post(
        "/countersign/register",
        json=_submission(raw, requester_key, webhook_url="https://producer.example/hook", webhook_secret="s3cr3t"),
    )
    assert resp.status_code == 200, resp.text
    entry = resp.json()["countersignatures"][0]
    assert calls == [("https://producer.example/hook", entry["receipt"]["entry_hash"])]


def test_webhook_url_targeting_metadata_ip_is_refused_before_scheduling(
    monkeypatch, requester_key, issuer_allowlist
):
    """SSRF guard, HARD GATE: a webhook_url whose host resolves to the cloud
    metadata address is refused with 422 BEFORE deliver_webhook is ever
    scheduled -- an enrolled issuer cannot use this endpoint to make the
    service fetch 169.254.169.254 on their behalf."""
    import capsule_anchor.countersign.router as router_module
    import capsule_anchor.countersign.webhooks as webhooks_module

    calls = []
    monkeypatch.setattr(
        router_module, "deliver_webhook", lambda *a, **kw: calls.append((a, kw))
    )
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["169.254.169.254"])

    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()

    resp = client.post(
        "/countersign/register",
        json=_submission(
            raw, requester_key, webhook_url="https://attacker.example/hook", webhook_secret="s3cr3t"
        ),
    )
    assert resp.status_code == 422, resp.text
    assert "webhook_url refused" in resp.json()["detail"]
    assert calls == []


def test_webhook_url_over_plain_http_is_refused(monkeypatch, requester_key, issuer_allowlist):
    """SSRF guard: scheme MUST be https."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()

    resp = client.post(
        "/countersign/register",
        json=_submission(
            raw, requester_key, webhook_url="http://producer.example/hook", webhook_secret="s3cr3t"
        ),
    )
    assert resp.status_code == 422, resp.text
    assert "webhook_url refused" in resp.json()["detail"]


def test_unknown_profile_is_refused(monkeypatch, requester_key, issuer_allowlist):
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="nonexistent/v9"))
    assert resp.status_code == 422
    assert "no policy module" in resp.json()["detail"]


def test_missing_profile_id_runs_generic_checks_only(monkeypatch, requester_key, issuer_allowlist):
    """capsulectl's current ``countersignSubmission`` wire shape has no
    ``profile_id`` field at all -- a submission that never names one must
    still succeed (the five generic checks only, no profile-specific
    coverage), never be refused. Refusing here would reject 100% of real
    capsulectl requests today."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id=None))
    assert resp.status_code == 200, resp.text
    entry = resp.json()["countersignatures"][0]
    assert entry["statement"]["checks"]
    assert "profile" not in entry["statement"]


def test_requester_key_mismatch_is_refused(monkeypatch, requester_key, issuer_allowlist):
    """A requester_signature that verifies under a DIFFERENT key than the
    one the issuer allowlist pins for that requester id is refused -- the
    trust anchor's own pinned key always wins, never a caller-supplied one."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()
    body = _submission(raw, requester_key)
    body["requester"]["key_id"] = "ff" * 32
    resp = client.post("/countersign/register", json=body)
    assert resp.status_code == 422
    assert "does not match the key" in resp.json()["detail"]


# --- item 2: unbounded body on /countersign/register ---


def test_oversized_body_is_refused_with_413_before_parse(monkeypatch, issuer_allowlist):
    """A body over MAX_STATEMENT_BYTES is refused with 413 BEFORE
    JSON-decode -- proven here by sending bytes that aren't even valid JSON;
    a 413 (not a 422 JSON-decode error) shows the size check ran first."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    oversized = b"x" * (router_module.MAX_STATEMENT_BYTES + 1)
    resp = client.post(
        "/countersign/register", content=oversized, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 413, resp.text
    assert "too large" in resp.json()["detail"]


def test_body_at_the_cap_is_not_refused_for_size(monkeypatch, issuer_allowlist):
    """A body exactly AT the cap must not be refused for size -- only
    STRICTLY over. It still fails JSON-decode here (not a real submission),
    proving the size gate itself is exact rather than off-by-one strict."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    at_cap = b"x" * router_module.MAX_STATEMENT_BYTES
    resp = client.post(
        "/countersign/register", content=at_cap, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code != 413, resp.text


# --- item 3: no rate limit on /countersign/register ---


def test_rate_limit_exceeded_returns_429(monkeypatch, issuer_allowlist):
    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setattr(
        router_module, "_COUNTERSIGN_POST_LIMITER", _SlidingWindowLimiter(max_calls=1, window_s=60.0)
    )
    first = client.post("/countersign/register", json={})
    assert first.status_code != 429, first.text

    second = client.post("/countersign/register", json={})
    assert second.status_code == 429, second.text
    assert "rate limit" in second.json()["detail"]


def test_rate_limit_is_a_separate_budget_per_instance(monkeypatch, issuer_allowlist):
    """A fresh limiter always starts open -- confirms the gate is a
    per-instance sliding window, not a global flag stuck from a prior test."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setattr(
        router_module, "_COUNTERSIGN_POST_LIMITER", _SlidingWindowLimiter(max_calls=300, window_s=60.0)
    )
    resp = client.post("/countersign/register", json={})
    assert resp.status_code != 429, resp.text


def test_statement_that_cannot_be_canonicalized_is_a_clean_400(monkeypatch, requester_key, issuer_allowlist):
    """A lone surrogate cannot be encoded as UTF-8, so the statement has no
    JCS form and cannot be signed. The request is refused with a 400, never
    a 500. (The JSON body parser already rejects a lone-surrogate escape;
    this covers a statement that acquires one some other way.)"""
    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_HOST", "countersign.example")
    real_recompute = router_module.recompute_statement

    def recompute_with_surrogate(*args, **kwargs):
        statement = real_recompute(*args, **kwargs)
        statement.scope.ledger_id = "ledger:\ud800"
        return statement

    monkeypatch.setattr(router_module, "recompute_statement", recompute_with_surrogate)
    safe_client = TestClient(client.app, raise_server_exceptions=False)
    resp = safe_client.post("/countersign/register", json=_submission(base_bundle_raw(), requester_key))
    assert resp.status_code == 400, resp.text
    assert "statement" in resp.json()["detail"]


class DisclosureRefused(_BaseDisclosureRefused):
    """Stands in for a module package's own refusal, a subclass of the contract's base."""


class _ReadsDisclosure:
    reads_disclosed_kinds = frozenset({"declared_count"})

    def __init__(self, refuse: bool) -> None:
        self.refuse = refuse
        self.seen: list[dict] = []

    def check(self, bundle, profile_id):
        self.seen.append(bundle.raw.get("disclosures", {}))
        if self.refuse:
            raise DisclosureRefused("the disclosed declared_count payload is not closed")
        return []


def _registry_with(module):
    from capsule_anchor.countersign.policy import PolicyRegistry

    registry = PolicyRegistry()
    registry.register("pack/v1", module)
    router_module.configure_registry(registry)


def test_declared_count_disclosure_reaches_the_module(monkeypatch, requester_key, issuer_allowlist):
    from .conftest import declared_count_bundle_raw

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    module = _ReadsDisclosure(refuse=False)
    _registry_with(module)
    raw, cid = declared_count_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))
    assert resp.status_code == 200, resp.text
    assert module.seen and all(s == {cid: {"agent_input": {"declared_count": 2}}} for s in module.seen)


def test_module_disclosure_refusal_is_a_422_not_a_500(monkeypatch, requester_key, issuer_allowlist):
    from .conftest import declared_count_bundle_raw

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    _registry_with(_ReadsDisclosure(refuse=True))
    raw, _ = declared_count_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))
    assert resp.status_code == 422
    assert "not closed" in resp.json()["detail"]


def test_forged_disclosure_is_refused_over_http_before_any_module(monkeypatch, requester_key, issuer_allowlist):
    from .conftest import declared_count_bundle_raw

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    module = _ReadsDisclosure(refuse=False)
    _registry_with(module)
    raw, cid = declared_count_bundle_raw()
    raw["disclosures"][cid]["agent_input"] = {"declared_count": 99}
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))
    assert resp.status_code == 422
    assert module.seen == []


def test_disclosure_is_refused_over_http_when_no_kind_is_configured(monkeypatch, requester_key, issuer_allowlist):
    from .conftest import declared_count_bundle_raw

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.delenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", raising=False)
    module = _ReadsDisclosure(refuse=False)
    _registry_with(module)
    raw, _ = declared_count_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))
    assert resp.status_code == 422
    assert module.seen == []


class _NoDisclosureModule:
    """A module that declares no disclosure it reads."""

    def check(self, bundle, profile_id):
        return []


def test_disclosure_with_no_profile_is_refused(monkeypatch, requester_key, issuer_allowlist):
    from .conftest import declared_count_bundle_raw

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    raw, _ = declared_count_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id=None))
    assert resp.status_code == 422
    assert "naming no profile" in resp.json()["detail"]


def test_disclosure_of_a_kind_the_module_does_not_read_is_refused(monkeypatch, requester_key, issuer_allowlist):
    from .conftest import declared_count_bundle_raw

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    _registry_with(_NoDisclosureModule())
    raw, _ = declared_count_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))
    assert resp.status_code == 422
    assert "does not read" in resp.json()["detail"]


def test_a_module_naming_another_kind_does_not_read_this_one(monkeypatch, requester_key, issuer_allowlist):
    from .conftest import declared_count_bundle_raw

    class _Other(_NoDisclosureModule):
        reads_disclosed_kinds = frozenset({"something_else"})

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    _registry_with(_Other())
    raw, _ = declared_count_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))
    assert resp.status_code == 422


def test_a_same_named_refusal_outside_the_contract_is_not_a_422(monkeypatch, requester_key, issuer_allowlist):
    """The router matches the contract's base class, not a class name."""
    from .conftest import declared_count_bundle_raw

    class DisclosureRefused(ValueError):  # not the contract's base
        pass

    class _Raises(_ReadsDisclosure):
        def check(self, bundle, profile_id):
            raise DisclosureRefused("x")

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    _registry_with(_Raises(refuse=False))
    raw, _ = declared_count_bundle_raw()
    safe = TestClient(client.app, raise_server_exceptions=False)
    resp = safe.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))
    assert resp.status_code == 500


class _Returns(_ReadsDisclosure):
    def __init__(self, results) -> None:
        super().__init__(refuse=False)
        self.results = results

    def check(self, bundle, profile_id):
        return self.results


def _post_with_module_result(monkeypatch, requester_key, issuer_allowlist, results):
    from .conftest import declared_count_bundle_raw

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    _registry_with(_Returns(results))
    raw, _ = declared_count_bundle_raw()
    return client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))


def test_a_module_result_word_outside_the_vocabulary_is_a_502_naming_it(monkeypatch, requester_key, issuer_allowlist):
    resp = _post_with_module_result(
        monkeypatch, requester_key, issuer_allowlist, [CheckResult.model_construct(name="pack.shape", result="match", detail="")]
    )
    assert resp.status_code == 502, resp.text
    detail = resp.json()["detail"]
    assert "pack/v1" in detail and "pack.shape" in detail and "'match'" in detail
    assert "established" in detail  # names the allowed words


def test_a_foreign_module_result_type_is_a_502(monkeypatch, requester_key, issuer_allowlist):
    from dataclasses import dataclass

    @dataclass
    class Foreign:
        name: str = "pack.other"
        result: str = "match"

    resp = _post_with_module_result(monkeypatch, requester_key, issuer_allowlist, [Foreign()])
    assert resp.status_code == 502, resp.text
    detail = resp.json()["detail"]
    assert "pack.other" in detail and "'match'" in detail


def test_a_valid_module_result_still_signs(monkeypatch, requester_key, issuer_allowlist):
    resp = _post_with_module_result(
        monkeypatch, requester_key, issuer_allowlist, [CheckResult(name="pack.shape", result="established")]
    )
    assert resp.status_code == 200, resp.text


class _DictResult(dict):
    """A module package's own result type, as capsule-engine's countersign
    module returns it: a ``dict`` subclass, not this package's model."""


def test_a_mapping_module_result_signs_and_is_folded_unchanged(monkeypatch, requester_key, issuer_allowlist):
    resp = _post_with_module_result(
        monkeypatch,
        requester_key,
        issuer_allowlist,
        [_DictResult(name="pack.shape", result="established", detail="d"), {"name": "pack.plain", "result": "not present"}],
    )
    assert resp.status_code == 200, resp.text
    checks = {c["name"]: c for c in resp.json()["countersignatures"][0]["statement"]["checks"]}
    assert checks["pack.shape"]["result"] == "established"
    assert checks["pack.plain"]["result"] == "not present"


def test_a_mapping_module_result_outside_the_vocabulary_is_a_502_naming_it(monkeypatch, requester_key, issuer_allowlist):
    resp = _post_with_module_result(
        monkeypatch, requester_key, issuer_allowlist, [_DictResult(name="pack.shape", result="match")]
    )
    assert resp.status_code == 502, resp.text
    detail = resp.json()["detail"]
    assert "pack/v1" in detail and "pack.shape" in detail and "'match'" in detail


def test_a_mapping_module_result_without_a_name_is_a_502(monkeypatch, requester_key, issuer_allowlist):
    resp = _post_with_module_result(monkeypatch, requester_key, issuer_allowlist, [{"result": "established"}])
    assert resp.status_code == 502, resp.text


def test_a_mapping_module_result_with_a_non_string_name_is_a_502_naming_it(monkeypatch, requester_key, issuer_allowlist):
    resp = _post_with_module_result(monkeypatch, requester_key, issuer_allowlist, [{"name": 7, "result": "established"}])
    assert resp.status_code == 502, resp.text
    assert "check 7:" in resp.json()["detail"]


def test_a_non_iterable_module_return_is_a_502(monkeypatch, requester_key, issuer_allowlist):
    resp = _post_with_module_result(monkeypatch, requester_key, issuer_allowlist, None)
    assert resp.status_code == 502, resp.text
    assert "pack/v1" in resp.json()["detail"]


def test_the_module_is_called_once_so_a_later_call_cannot_bypass_validation(monkeypatch, requester_key, issuer_allowlist):
    calls = []
    good = [CheckResult(name="pack.shape", result="established")]

    class _Flaky(_Returns):
        def check(self, bundle, profile_id):
            calls.append(1)
            return good if len(calls) == 1 else [None]

    from .conftest import declared_count_bundle_raw

    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN_DISCLOSABLE_KINDS", "declared_count")
    _registry_with(_Flaky(good))
    raw, _ = declared_count_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="pack/v1"))
    assert resp.status_code == 200, resp.text
    assert len(calls) == 1


def test_get_root_answers_while_a_countersign_registration_is_blocked(monkeypatch, requester_key, issuer_allowlist):
    """capsule-anchor#132: see tests/test_handlers_off_event_loop.py."""
    import threading

    from ..test_handlers_off_event_loop import HOLD_S, _get_root_while_held

    client = _strict_client(monkeypatch, issuer_allowlist)
    entered, release = threading.Event(), threading.Event()
    real = router_module.accept_bundle

    def held(*args, **kwargs):
        entered.set()
        release.wait(HOLD_S)
        return real(*args, **kwargs)

    monkeypatch.setattr(router_module, "accept_bundle", held)
    submission = _submission(base_bundle_raw(), requester_key)
    responses: list = []

    def post():
        resp = client.post("/countersign/register", json=submission)
        responses.append(resp)
        return resp

    with client:
        elapsed = _get_root_while_held(client, post, entered, release)
    assert elapsed < HOLD_S / 2, f"GET / waited {elapsed:.2f}s behind a blocked registration"
    assert responses[0].status_code == 200, responses[0].text
