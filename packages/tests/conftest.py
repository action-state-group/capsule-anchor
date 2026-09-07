"""Test environment defaults.

Sets the explicit dev escape hatches so existing tests can call create_app()
without a real Postgres URL or a configured signing key.  The fail-closed
tests in TestFailClosed use monkeypatch to temporarily remove these variables.
"""
import os

os.environ.setdefault("CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY", "1")
os.environ.setdefault("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
# The canonical public host, matching the real deployed value -- there is no
# safe default (see [anchor-did-from-host]), so tests must set one explicitly.
os.environ.setdefault("CAPSULE_ANCHOR_PUBLIC_HOST", "witness.agentactioncapsule.org")
