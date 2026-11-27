# 20 — Witness latency and scaling: what grows with the log, and the fixes

This note is for the people who run and change the hosted witness (`capsule-witness` on Cloud Run,
Postgres on Cloud SQL). It records what was measured in November 2026 at about 54,000 log entries,
which costs still grow with the log, and the ranked fixes. The measurements, with their sources,
are on [capsule-anchor#132](https://github.com/action-state-group/capsule-anchor/issues/132);
`scripts/bench_witness.py` reproduces the local profile.

No fix here changes a wire format, a receipt, a proof or a public API: every proof and root stays
byte-identical, and the tests compare them against `anchoring/ct.py`.

---

## 1. Where things stand

The slowdown reported in November was real and is mostly gone. Before #113 and the incremental
tree (`anchoring/ct_cache.py`), every registration re-read and re-hashed the whole log: a
successful `POST /checkpoints` took 2.6 s at the median and tens of seconds under CI load, and
about 2% answered 500. On the revision deployed 2026-11-26 21:24Z it takes 78 ms at the median,
185 ms at p99, with no 5xx.

A warm registration is now flat in the log size: locally 2.16 ms at the median at 54,000 entries
and 2.11 ms at 540,000. It is ten Postgres statements under the cross-instance advisory lock plus three Ed25519
signatures; in production the floor is the round trips to Cloud SQL.

What still grows with the log:

| Cost | 54,000 entries | 540,000 entries | Where |
|---|---|---|---|
| Startup: peak memory of the full log read | +160 MiB (74 to 234 MiB) | +1,617 MiB (74 to 1,691 MiB) | `_sync_log` (`anchoring/service.py:956`) materializes every row as a `TransparencyLogEntry` (`store.py:1467`) |
| Startup: time of that read | 0.31 s local | 3.46 s local | same |
| `GET /anchor/consistency-proof` | 68 ms local, about 1 s in production | 688 ms local | `consistency_proof` (`service.py:1232`) copies every leaf and rehashes both trees, under the instance lock |
| `GET /anchor/transparency-log?after_index=0` | the whole log in one response | the whole log | `transparency_log` (`service.py:914`) |
| Steady memory of the cached tree | about 4 MiB | about 40 MiB | `CachedTree._leaves`, one `bytes` object per leaf |

And one cost does not grow with the log but multiplies every other: `POST /checkpoints`
(`anchoring/router.py:976`) and `POST /countersign/register` (`countersign/router.py:146`) are
`async def` handlers that run the blocking registration on the event loop. While one waits for the
writer lock (up to 10 s) or for Postgres, the instance's event loop runs nothing else, not even
the routes that need no lock; before #113 that put `GET /` at a p99 of 24.8 s and `GET /health`
at a p99 of 5.0 s, with a maximum of 174 s.

## 2. The ceilings

- **Memory is the first hard limit, and it has a date.** The startup read peaks at about 3 KiB per
  entry (160 MiB for 54,000, 1,617 MiB for 540,000, over a local baseline of 74 MiB; every local
  figure in this note is from the rerun on #132 unless it says otherwise). In production, the
  highest memory sample on the live revision `00015-cbd` is 0.58 of 512 Mi, about 297 MiB, at
  48,000 to 54,000 entries (`container/memory/utilizations`, one-minute p99, 2026-11-26 21:27Z to
  2026-11-27 12:40Z). That sample is bucketed and may miss the startup transient, so take it as a
  lower bound: if it includes the startup read (about 155 MiB at that size), the rest is about
  140 MiB, and a new instance is killed during startup at about 125,000 entries. Every instance
  that starts after that point, autoscaled or rolled out, crash-loops: the witness goes down, not
  slow.
  - **When.** The live log held 54,011 entries at 2026-11-27 12:44Z and grew by 89 in the 46
    minutes before (about 2,800 a day). At that rate 125,000 is about 2026-12-22; at the week's
    pace while CI still posted to it (about 28,000 a week), about 2026-12-15.
  - **Order.** Fix 1 is deployed before anything else in this note.
  - **Tripwire.** The `/health` monitor (`.github/workflows/witness-monitor.yml`) fails, and so
    opens its `ci-red` issue, once `tree_size` reaches 100,000. Raise its threshold only after
    fix 1 is live.
  - **Stopgap.** If fix 1 is not live when the tripwire fires, raise the Cloud Run memory to 1 Gi;
    that is spend, Steven's call (section 3.6).
- **Write throughput is one writer at a time across all instances** (the advisory lock, #113).
  This is an estimate, not a measured ceiling: if most of the 75 ms median request is the writer
  section (a checkpoint's section also runs its continuity checks and writes its read-surface
  record, `service.py:1873`), the whole service takes about 13 registrations a second; the
  November peak was about 0.2 a second. More instances add read capacity, not write
  capacity, and each new one pays the startup read.
- **Consistency proofs** cost about 1 s each in production at 45,000 entries and grow linearly;
  each one holds its instance's lock, so registrations on that instance wait behind it.

## 3. Ranked fixes

Ranked by expected gain against cost and risk. 1 to 4 are code changes in this repository that
take effect at the next deploy; 5 and 6 need an operator.

### 1. Bound the startup read's memory

`_sync_log` reads the log in pages: `entries_after` takes an optional row limit on the three stores
(in-memory, SQLite, Postgres; keyset on `log_index`), and the sync loops until a page comes back
short. Each page is turned into leaf hashes and dropped before the next is read. The entries and
their leaf hashes are exactly what they are today, so no leaf can change; the last entry is kept
in full, as now, because the next append chains to it.

- **Gain, measured:** peak RSS after the first sync from 234 to 102 MiB at 54,000 entries and from
  1,691 to 145 MiB at 540,000 (local Postgres, pages of 5,000). What remains above the baseline is
  one page of rows plus the cached tree, which does grow with the log, at about 73 bytes a leaf
  (one 32-byte `bytes` object and its list slot) plus the subtree memo: about 4 MiB at 54,000
  and 40 MiB at 540,000. That moves the startup's 512 Mi ceiling from about 125,000 entries to
  several million. It does not bound a request that reads the whole log: `GET
  /anchor/transparency-log?after_index=0` still materializes every entry (section 4). The time of the read stays O(N) (0.25 s and 2.79 s locally); it is spent at startup,
  not on a request.
- **Cost:** an optional `limit` on one store method, and tests that the paged sync builds the same
  tree as one read of the whole log, across page boundaries, with both leaf forms, on all three
  stores.
- **Risk:** low. Read-only, the same rows in the same order; a gap or reordering is caught by the
  existing index check in `_sync_log`.

### 2. Consistency proofs from the cached tree

`CachedTree` gains the RFC 6962 §2.1.2 `SUBPROOF` over its own subtree hashes, the same way
`audit_path` already reuses them, and `consistency_proof` uses it and `CachedTree.root` instead of
copying every leaf.

- **Gain, measured:** with the subtree memo filled, O(log N) memoized hashes plus at most a few
  hundred fresh ones per proof instead of O(N): `old=1000` to the tip from 68 ms to 0.49 ms at
  54,000 entries and from 688 ms to 0.53 ms at 540,000 locally, and about 1 s in production
  before; the instance lock is held for that long instead. The memo starts
  empty in a new process, and the first root after startup hashes every leaf once (54,000 hashes
  at 54,000 entries); the app factory computes that root at startup, next to the log read it
  already does (`app.py:234`), so no request pays it.
  On a fresh tree the first proof costs that one pass (22.5 ms at 54,000 entries, 201 ms at
  540,000).
- **Cost:** about 30 lines and a differential test against `ct.consistency_proof` for every pair of
  sizes up to 130 and sampled pairs up to 600 (next to the root and path tests in
  `packages/tests/test_log_contention.py`).
- **Risk:** low. The output is a list of hashes the tests compare byte for byte.

### 3. Run the blocking handlers off the event loop

`POST /checkpoints` and `POST /countersign/register` keep reading the body with `await` and then
run the registration in the thread pool (`fastapi.concurrency.run_in_threadpool`), as every
plain `def` route already does.

- **Gain:** a write waiting on the writer lock or on Postgres no longer stalls the event loop, so
  routes that take no service lock (`GET /`, the DID document, the registration policy) answer at
  once. Routes that take the instance lock, `GET /health` among them (it calls `log_size()`,
  `app.py:368`), still wait for the writer section in progress, as they do from a thread today.
  That wait has no bound of its own: the 10 s timeout covers only taking the writer lock
  (`store.py:1415`), not the statements that follow once it is held. Changing what `/health` locks
  is a separate decision and is not part of this fix.
- **Cost:** a few lines per handler, and a test per handler that `GET /` answers on the same event
  loop while a registration is held inside the service (without the change it waits the whole
  5 s hold).
- **Risk:** low. The service is already called from many threads (every `def` route); the lock
  discipline is unchanged. The thread pool is anyio's shared limiter, 40 threads by default, the
  same one every `def` route uses, and a registration can hold a thread for as long as it waits
  on the writer lock (up to 10 s). A burst of more than about 40 waiting writes on one instance
  would therefore queue the `def` reads behind them. At the November peak (0.2 writes a second)
  that is far off; raising the limiter or giving writes their own is the answer if it is not.

### 4. Fewer round trips per registration (measure before building)

Ten statements per writer section, each a round trip to Cloud SQL. psycopg's pipeline mode or
folding the receipt, subject-index and tree-head writes into fewer statements could take the
production floor from about 75 ms toward 30 ms. Not built now: the current floor is far below any
reported pain, and the November peak write rate is about 70 times below the write ceiling; the change touches the atomicity #113
established and needs its own plan review. Revisit when write traffic grows.

### 5. Operator: the uptime check that posts to `/checkpoints`

A Cloud Monitoring uptime check posts an empty body to `/checkpoints` every 10 seconds, over both
http (answered 302) and https (answered 400): 79% of all `POST /checkpoints` in the measured week.
It costs little, but it hides real traffic in the logs and metrics. Point it at `GET /health`, or
keep one https check with a content match on the 400 body. Owner: whoever runs the Cloud Monitoring
configuration of project `fluxxom`.

### 6. Operator: settings that need no change now

Everything in this section that costs money (minimum instances, more memory, a larger Cloud SQL
tier) is Steven's decision, as is every deploy.

- **Cloud Run memory (512 Mi):** after fix 1 is deployed the remaining growth is the cached tree,
  about 40 MiB at 540,000 entries. Until it is deployed, the 125,000-entry ceiling and the stopgap
  in section 2 apply.
- **Cloud SQL `db-f1-micro`:** CPU peaked at 54% in an hour, memory in use 13%, at most 10
  backends. No change needed.
- **Minimum instances (0 today):** a new instance takes 5.6 to 9.1 s to start (p50 per day), 176
  starts in the week. `deploy/DEPLOY.md` already recommends `--min-instances=1` (and
  `--max-instances=10`); the live service runs 0 and 20 (`gcloud run services describe`,
  2026-11-27). The live values are what runs; the guide's are a recommendation nobody applied.
  One minimum instance would spare the first request after an idle period that wait, for the
  cost of one idle instance. Steven decides whether to apply it; the guide is then updated to
  whatever he chooses, so the two stop drifting.
- **maxScale 20:** never approached (hourly peak 8). With one writer at a time, more instances do
  not raise write capacity.

## 4. Not changed, and why

- **`GET /anchor/transparency-log` returns the whole log from `after_index`.** At 54,000 entries
  that is one large response (p50 856 ms on the old revision, 31 calls in the week). A page limit
  would change what a monitor receives, a public API change; it is its own item,
  [capsule-anchor#133](https://github.com/action-state-group/capsule-anchor/issues/133), rather
  than done here.
- **Persisting the tree's subtree hashes** in Postgres would make startup independent of the log
  size. After fix 1 the startup read costs about 0.5 s per 100,000 entries locally, a few
  seconds in production, and is not on any request path, so a new table is not justified yet; revisit at a few million entries.
- **A second connection for reads**, so reads do not wait behind a writer section on the store's
  one connection: in the profile a read waited behind at most one writer section (an 11.1 ms
  maximum locally at 540,000 entries, with four writers), not behind the log. That is a measurement, not a bound (a
  slow statement inside a section makes the read wait as long), and it does not justify a second
  connection's failure modes.
