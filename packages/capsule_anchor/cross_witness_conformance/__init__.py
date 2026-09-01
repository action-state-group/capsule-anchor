# SPDX-License-Identifier: Apache-2.0
"""Conformance checking for external (cross-witness) CLL checkpoint submitters.

See ``checker.py`` for the check functions and ``watcher.py`` for the CLI
that runs them against a checkpoint obtained out of band. ``NOTES.md`` in
this directory records the gaps found while building this: today there is
no public endpoint that lets a third party discover or read back a
submitted checkpoint's claims from ``witness.agentactioncapsule.org`` --
this tooling must be handed checkpoint bytes, not point at a discovery URL.
"""
