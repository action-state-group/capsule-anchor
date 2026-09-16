"""strict_countersign_active: both switches required, either alone is
insufficient -- the witness's default behavior must never activate by
accident."""

from __future__ import annotations

from capsule_anchor.countersign.config import strict_countersign_active


def test_inactive_by_default(monkeypatch):
    monkeypatch.delenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", raising=False)
    monkeypatch.delenv("CAPSULE_ANCHOR_COUNTERSIGN", raising=False)
    assert strict_countersign_active() is False


def test_inactive_with_only_countersign_flag(monkeypatch):
    monkeypatch.delenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", raising=False)
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN", "1")
    assert strict_countersign_active() is False


def test_inactive_with_only_policy_flag(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", "strict")
    monkeypatch.delenv("CAPSULE_ANCHOR_COUNTERSIGN", raising=False)
    assert strict_countersign_active() is False


def test_inactive_with_non_strict_policy_value(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", "permissive")
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN", "1")
    assert strict_countersign_active() is False


def test_active_with_both_switches(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", "strict")
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN", "1")
    assert strict_countersign_active() is True
