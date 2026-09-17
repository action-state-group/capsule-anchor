# Real end-to-end countersign round trip — 2026-09-17

[countersign-whole-bundle-shape]'s acceptance proof: a REAL Evidence Bundle, built
by `capsulectl`'s own `AssembleBundle` code path, submitted over a real HTTP request
(`buildCountersignSubmission` + `requestCountersignatures`, the exact functions
`capsulectl countersign request` uses) to a LIVE, running instance of this
repository's rewritten countersign engine, and verified with `capsulectl`'s own
`verifyCountersignatures` (`countersign verify`) — the full request path the prior
wire-shape reconciliation (#47) proved only up to the entry, never the request
itself (its own interop test decoded a committed fixture through a lenient
`json.Unmarshal`, not the strict `DisallowUnknownFields()` decode a real request
actually takes).

**Method.** A throwaway Go test file was added to a capsule-cli worktree (never
committed — capsule-cli is the read-only reference verifier for this task; the
worktree was confirmed byte-for-byte clean against `origin/main` afterward), driving
`withheldBundleFixture` (the same helper `TestCountersignRequestAgainstMockService`
already uses) against a real `uvicorn` subprocess running this repo's
`capsule_anchor.app:create_app` with `CAPSULE_ANCHOR_REGISTRATION_POLICY=strict`,
`CAPSULE_ANCHOR_COUNTERSIGN=1`, and an issuer allowlist enrolling the fixture's own
ledger key. Reproducible locally with a capsule-anchor checkout and Python
toolchain (fastapi/uvicorn/agent-action-capsule/checkpointed-local-log/scitt-cose,
all already this repo's own dependencies) via the equivalent of:

```
PYTHONPATH=<capsule-anchor>/packages \
CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY=1 CAPSULE_ANCHOR_PUBLIC_HOST=countersign.example \
CAPSULE_ANCHOR_INSECURE_IN_MEMORY=1 CAPSULE_ANCHOR_REGISTRATION_POLICY=strict \
CAPSULE_ANCHOR_COUNTERSIGN=1 CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE=<issuers.json> \
python3 -m uvicorn capsule_anchor.app:create_app --factory --host 127.0.0.1 --port <port>
```

then a real `capsulectl countersign request`-shaped POST to
`http://127.0.0.1:<port>/countersign/register`, followed by `countersign verify`
over the result.

**Three real interop bugs were found and fixed by this exercise** (all in
`countersign/statement.py`'s wire projection, `Statement.wire_dict()`) — none were
caught by the entry-only fixture test, because `capsulectl`'s real request path
decodes with `encoding/json`'s `DisallowUnknownFields()` while `countersign
verify`'s own entry decode does not:

1. `statement.profile` — not declared on Go's `CountersignStatement` struct.
2. Every check's `detail` — not declared on Go's `CountersignCheck` struct
   (`{Name, Result}` only).
3. `statement.exclusions` — not declared on Go's `CountersignStatement` struct.

All three remain first-class fields on this module's own internal
`Statement`/`CheckResult` objects (every check function, every test, COUNTERSIGN.md
§1/§2's own contract) — only the wire/signing projection (`wire_dict()`) omits them,
documented in `statement.py` and `COUNTERSIGN.md`.

## Transcript

```
=== 1. Real Evidence Bundle (capsulectl AssembleBundle, payloads=none) ===
{
  "bundle_kind": "evidence-bundle/v2",
  "bundle_version": "2",
  "checkpoint": {
    "mmr_size": 1,
    "root": "e7a33fb96c38950e32f7bf570a452772a63b193969c09a18ab6ec63f7dfe73f4",
    "statement": "0oRYYKQBJwN4H2FwcGxpY2F0aW9uL2NsbC1jaGVja3BvaW50K2Nib3IEWCAyZ0Gy1zNJatAeyODx4xWXCu39UgMC2K/0xTpKzHq1Yg+iAWh0ZXN0LWxvZwJqdGVzdC1sb2cjMaBYj6Zka2luZG5jbGwtY2hlY2twb2ludGhsb2dfc2l6ZQFpaXNzdWVkX2F0eBgyMDI2LTA5LTE3VDA3OjA0OjE3LjQ3NlppcHJldl9zaXplAGpjb21taXRtZW50WCOBWCDnoz+5bDiVDjL3v1cKRSdypjsZOWnAmhirbsY/ff5z9G9wcmV2X2NvbW1pdG1lbnRAWEBwR9Jy/X1XTAeRGmN9CjSgBFjfUD9obCcyNTr0OkwANyws7DUfoBx5JK7vfsrsd0xtwYF/IPUESteXXlEqjx0I"
  },
  "completeness": {
    "closure_depth": 2,
    "missing": [],
    "payloads_mode": "none",
    "records_mode": "complete",
    "suppressed_fields": []
  },
  "completeness_certificate": {
    "body_digests": [
      "878080046177697fe6c24624c124d74aed2d3f70171940f0d30ccc519ad82131"
    ],
    "first_seq": 1,
    "last_seq": 1,
    "log_id": "test-log",
    "memberships": {
      "878080046177697fe6c24624c124d74aed2d3f70171940f0d30ccc519ad82131": {
        "inclusion_proof": {
          "kind": "inclusion",
          "leaf_index": 0,
          "peaks_left": [],
          "peaks_right": [],
          "size": 1,
          "v": 1,
          "witness": []
        },
        "log_coordinates": {
          "leaf_index": 0,
          "log_id": "test-log",
          "seq": 1
        }
      }
    },
    "range_proof": {
      "from_index": 0,
      "from_seq": 1,
      "size": 1,
      "to_index": 0,
      "to_seq": 1,
      "witness": []
    },
    "range_root": "e7a33fb96c38950e32f7bf570a452772a63b193969c09a18ab6ec63f7dfe73f4"
  },
  "records": [
    {
      "action_id": "test-action",
      "action_type": "fyi",
      "assurance": {
        "attestation_mode": "self_attested",
        "effect_mode": "not_applicable",
        "ledger_mode": "standalone"
      },
      "canonicalization_id": "jcs",
      "capsule_id": "878080046177697fe6c24624c124d74aed2d3f70171940f0d30ccc519ad82131",
      "developer": "test-developer",
      "format_version": "4",
      "model_attestation": {
        "compute_attestation": {
          "agent_input_digest": "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862",
          "agent_output_digest": "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93"
        }
      },
      "operator": "test-operator",
      "spec_version": "draft-mih-scitt-agent-action-capsule-04",
      "timestamp": "2026-09-08T00:00:00Z"
    }
  ],
  "root": "878080046177697fe6c24624c124d74aed2d3f70171940f0d30ccc519ad82131",
  "verification": {
    "checks": [
      "graph_closure",
      "interval_coverage",
      "per_record_membership"
    ],
    "producer": "capsulectl"
  }
}
bundle digest (Go aacbundle.BundleDigest): e09b1d488c9f094e7fd84e91d635d569d15474c2d4b9cd5366e0e1c249d6298c

=== 2. Live capsule-anchor started at http://127.0.0.1:51281 (rewritten countersign engine) ===

=== 3. Live anchor's countersignatures[] entry (POST /countersign/register response) ===
{
  "type": "",
  "signer": {
    "id": "did:web:countersign.example",
    "key_id": "f27bfb20ed5272193fe638a079ec5a1095abd6f064d96afc1afd72eca9d493df"
  },
  "over": "e09b1d488c9f094e7fd84e91d635d569d15474c2d4b9cd5366e0e1c249d6298c",
  "independent": true,
  "statement": {
    "checks": [
      {
        "name": "chain consistency",
        "result": "not present"
      },
      {
        "name": "range membership",
        "result": "inconclusive"
      },
      {
        "name": "cadence",
        "result": "not present"
      },
      {
        "name": "key hygiene",
        "result": "not present"
      },
      {
        "name": "profile conformance",
        "result": "not checked"
      }
    ],
    "recomputed_at": "2026-09-17T07:04:17.892920Z",
    "scope": {
      "ledger_id": "test-log",
      "closure_depth": 2
    }
  },
  "signature": "cee08fceb3dd60a4f50dfd6b43ed6bb0e1a835a9364493170537072f7ef8195134d459c37f59f1d9991f46a076f0b07961cc33a05a1b4a7bfcbd04cbd24ec507",
  "receipt": {
    "receipt_b64": "0oRPowEnGQGLAQ+hBhpqq5DxoRkBjKEggUSDAQCA9lhAJFsZvuKcKbuWkqc22hTdlYTJ2iwV2Q1PTZTlBAUSmvf1QOVBgcDixvbJ/nE/TStX14CZdSb/2sj44wreO6qQAQ==",
    "entry_hash": "2556483eba050d972de21dca1cde490c75d1f0278126943ebd8e4a88ac4f981b",
    "leaf_index": 0,
    "tree_size": 1
  }
}

=== 4. capsulectl countersign verify result ===
state: resolved
signer: Live Round-Trip Anchor
independent: true
summary: resolved
--- PASS: TestZZLiveCountersignRoundTrip (0.42s)
PASS
ok  	github.com/action-state-group/capsule-cli/internal/cli	0.705s
```

Witness/checkpoint/anchoring/receipt/sth core is untouched by any of this (the live
anchor here IS the shared code path, run unmodified aside from the countersign
module changes; `git diff --stat origin/main -- 'packages/capsule_anchor/witness*'
'packages/capsule_anchor/anchoring*' ...` is empty).
