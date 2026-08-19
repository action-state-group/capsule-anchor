# Adopting capsule-anchor

This is the adoption ladder for anchoring capsules: four postures, each one rung up
from the last, and **each rung is a config change, not a rewrite.** You do not need
to plan your end state before you start — begin wherever fits today and move up
later with no code change and no loss of records already sealed.

The ladder answers one question at each rung: **who else, besides you, can verify
that a record existed at a given time?**

| Rung | Posture | Who can verify it | What it costs |
|---|---|---|---|
| 1 | **Stub** — no anchor | Nobody but you, offline | Zero services |
| 2 | **Self-hosted anchor** | Anyone inside your trust domain | One deployment you run |
| 3 | **Public anchor** | Any third party | One URL (the default) |
| 4 | **Operated instance** *(roadmap)* | Any third party, with issuer identity checked | Issuer-binding enforcement — not yet shipped; see status note below |

Moving up a rung never invalidates what you already sealed at a lower one — a
record anchored locally stays valid locally even after you point new records at the
public log. There is no retroactive upgrade, and this doc will not imply one.

---

## Rung 1 — Stub: structured records, no anchor

The ten-minute first touch. Seal capsules and verify them offline, with zero
external services:

```python
from capsule_emit import emit

cap = emit(action="submit_order", operator="acme-co", ..., anchor=False)
```

`anchor=False` (or `CAPSULE_ANCHOR=false` in adapter/env config) writes a
structured, signed record to your local ledger file and nothing else. Verification
reads the ledger offline and reports the record as **self-attested / not
anchored** — that is the honest label, not a placeholder for something better; it
means exactly what it says. No `capsule-anchor` instance is involved at this rung.

Use this rung to evaluate the record shape, run air-gapped, or develop without a
network dependency. There is nothing to deploy.

---

## Rung 2 — Self-hosted anchor (production self-attested)

Deploy your own `capsule-anchor` instance inside your infrastructure — see
[Self-host](README.md#self-host) for the pip / Docker / Cloud Run paths, all
already documented in the README and unchanged by this ladder.

**What this rung actually buys you.** A self-hosted anchor is still
**self-attested to an outside party** — you operate the log, so an external
auditor still has to trust your operation of it. What it *does* buy is real inside
your own organization: **internal separation of duties.** If the team running the
transparency log is not the same team running the agents being recorded, records
become tamper-evident *across those teams* even though the whole thing is
externally self-attested. That is a genuine property, not a consolation prize —
state it as what it is.

**Naming discipline.** Describe this posture as **"self-operated"** wherever it is
surfaced (startup banner, verification output, any UI). Never let it borrow the
public tier's language — a self-hosted log is not third-party evidence, and saying
otherwise is the one honesty failure this ladder exists to prevent.

Point `capsule-emit` at it the same way you would any instance:

```bash
export AAC_ANCHOR_URL=https://your-anchor-host/v1/digest
```

---

## Rung 3 — Public anchor: third-party verifiable

One config change and every subsequent record becomes verifiable by anyone, not
just your own team — the receipt and inclusion proof come from a log you do not
operate.

```bash
# unset AAC_ANCHOR_URL, or point it at the free public instance explicitly:
export AAC_ANCHOR_URL=https://anchor.agentactioncapsule.org/v1/digest
```

This is in fact `capsule-emit`'s **out-of-the-box default** — a fresh install with
no anchor configuration already anchors here. Rung 1 (the stub) exists for
adopters who want to defer that dependency; if you skip rung 1, this is where you
already are.

Permalinks become shareable at this rung — anyone holding a `capsule_id` can pull
the record and receipt and verify them without contacting you. **Dual-write during
a transition is legitimate**: point at both your self-hosted instance and the
public one while you migrate, and say so in your own docs rather than presenting
the switch as instantaneous.

---

## Rung 4 (roadmap) — Operated instance: issuer binding enforced

The last rung is a **stricter registration policy**: the anchor only accepts
Signed Statements whose issuer identity it can verify (via `did:web`, `x5chain`,
or a SPIFFE SVID — see [Registration Policy and Issuer Binding](README.md#registration-policy-and-issuer-binding)
for the three patterns and how they differ).

**Status note, stated plainly so this doc stays honest:** the three issuer-binding
patterns above are **documented and designed**, not yet **enforced** by
`capsule-anchor`'s registration endpoint. Today, `anchor.agentactioncapsule.org`
and every self-hosted instance run an **open registration policy** — any Signed
Statement is accepted regardless of issuer identity, which is intentional for the
public neutral service and stated in the README. An "operated instance" in the
sense of this rung — registration that actually rejects an unverifiable issuer —
is future work, tracked separately. Nothing in this doc should be read as implying
issuer-binding enforcement ships today.

---

## Appendix — local rehearsal (not a rung)

For wiring the full receipt pipeline before you go anywhere external, you can run
a fully local, zero-config instance using the existing dev-only escape hatches
already documented in [Configuration](README.md#configuration):

```bash
CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY=1 \
CAPSULE_ANCHOR_INSECURE_IN_MEMORY=1 \
capsule-anchor
# Service listening on http://localhost:8000 — ephemeral key, in-memory store
```

Point `capsule-emit` at `http://localhost:8000/v1/digest` and you have the full
register → receipt → verify loop with the network off.

**The honesty note that keeps this from being confused with a rung:** a local log
signed by an ephemeral key you generated is **operational rehearsal, not added
assurance** — you hold the key either way, so nothing here is more trustworthy
than rung 1's stub from an outside party's point of view. It is useful for
exercising the pipeline, not for claiming a tier. That is why it is an appendix,
not rung 1.5.
