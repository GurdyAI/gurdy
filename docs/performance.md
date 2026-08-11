# Performance: what we measured, what we fixed, and what we cannot certify here

**Date:** 2026-07-26 · **Hardware:** Apple M3 Pro, 12 cores, macOS · **Baseline commit:** `91c1c2e`

This records the §8.2 performance work. It is organised around one question —
**of the latency an agent sees, how much did we add?** — because that is the
question NFR-1 gates and it is easy to answer wrongly in both directions.

The spec's own instruction shaped everything here:

> Composed p99 is measured under concurrency in the reverse-proxy topology
> (§8.2), **never inferred by summing standalone microbenchmarks**. — §3.2 NFR-1

It was right. Both defects found were invisible to every microbenchmark of the
decision path, because both live in the hop.

---

## 1. The budget, and who owns each part

NFR-1: **≤3ms p50 / ≤5ms p99 added per call**, gated for sidecar/tap, measured
but not gated for in-cluster reverse proxy. The hot path is defined as
`hop + derive + extract + eval`, with mint explicitly per-task and amortised.

| Term | p99 | Share of the 5ms budget | Status |
|---|---|---|---|
| derive — three ES256 operations | ~240µs | ~5% | **measured** |
| extract — the extractor registry | 158ns | ~0% | **measured** |
| eval — Cedar | 922ns | ~0% | **measured** |
| attest — handing the record to the queue | ~5µs | ~0% | **measured** |
| **the request path, all of it** | **~300µs** | **6%** | **measured, reproducible** |
| response hashing | ~0.45µs/KiB | ~2µs typical, ~3ms at 8 MB | **measured** (D13) |
| **hop** | — | the remaining ~94% | **needs a deployment** |

**Our contribution is 6% of the p99 budget.** The other ~94% is a network hop
whose cost is a property of where you deploy, which is exactly why the spec gates
NFR-1 on a sidecar and declares the reverse-proxy figure best-effort.

### The composition matters more than the total

Within our ~300µs, **identity is 77–87%** — three ES256 operations per call
(verify the incoming txn, sign the call assertion, verify that assertion).
Extract and Cedar together are under half a percent.

Two consequences:

- Any future latency work belongs in the crypto, not the policy engine. This
  retroactively validates ADR-1: the embedded Cedar evaluator is nowhere near
  being the constraint.
- The gated quantity is dominated by a component that is *inherent to the
  evidence claim*. We sign per-call assertions because that is what makes a
  record attributable; the cost is the feature.

---

## 2. Throughput (NFR-2: 1,000 decisions/sec)

**6,000 decisions/sec with zero dropped records** — 6× the requirement. A 60s
run at 3,000/s moved 180,000 requests per arm with zero drops, zero write errors
and zero identity failures.

The scaling ceiling is lower than the core count suggests, and the reason is
recorded as **D12**: on the *no-SDK* path — the common one — `autoMint` takes a
process-wide mutex and performs an ES256 verify of the cached token while holding
it. Measured against the SDK-present path, which does the same number of crypto
operations without that lock:

| Path | ns/op (12-way parallel) | Implied ceiling |
|---|---|---|
| no `Gurdy-Txn` (autoMint, locked) | 70,970 | ~14,100/sec |
| with `Gurdy-Txn` (no lock) | 33,020 | ~30,300/sec |

Identical crypto, so **2.15× is pure contention**. Both are far above NFR-2, so
it is recorded rather than fixed. The fix is small: compare a cached expiry
instead of re-verifying, under a read lock.

### Sustained: 30 minutes at 1,000/s

A minute cannot show drift. Thirty can, and the answer is that nothing in the
decision path drifts — `gurdy-bench -soak 30m -soak-window 1m`, 1.8M requests:

| | window 1 | window 30 | change |
|---|---|---|---|
| p50 | 753µs | 761µs | +1.1% |
| p99 | 995µs | 998µs | +0.3% |
| achieved rate | 1,000/s | 1,000/s | held |

**Zero dropped records, zero write errors, zero identity failures** across all
1.8M calls. The schedule held in every one of the 30 windows — an open-loop
generator that falls behind records the lag, and it never did.

Memory rose 16.5 MB → 46.9 MB and **decelerated toward a plateau** (+32 KB/min at
minutes 15–20, +6 KB/min at 25–30): steady state rather than a leak. Note what
this run could *not* see — D6's unbounded `autoTxn` map is keyed by client IP and
all load came from one, so a soak is exactly the wrong shape to find that one.
File descriptors held between 44 and 82 with no trend.

**The finding is capacity, not speed.** The export grew **1.9 GB in 30 minutes —
~65 MB/min, ~92 GB/day at rated load** — into a single append-only file per
partition, with no rotation, retention or compaction. 3.66M records for 1.8M
calls (2.03 per call: decision + response, as designed), ~560 bytes each.

Append latency did not degrade as the file grew, which is why this is D14 and not
a latency defect. It is also why it is not "add logrotate": the file *is* the
chain. `prev_hash` links every line to the one before it and the header names one
pubkey for the whole file, so a rotation scheme has to state how a verifier walks
across the seam, and any compaction has to explain what a hash chain with a hole
in it proves.

Soak mode reports and does not gate. The thresholds worth gating on are what this
run establishes; a gate invented before the first measurement is a guess wearing
a number's clothes.

---

## 3. Two defects, and why only a composed test could find them

### `MaxIdleConnsPerHost: 2`

`httputil.NewSingleHostReverseProxy` inherits `http.DefaultTransport`, which
keeps **two** idle connections per host. A sidecar talks to exactly one upstream,
so that was the entire pool: past two concurrent calls, every request dialled a
fresh TCP connection and left the previous one in TIME_WAIT.

Nothing in an in-process benchmark can see this — it is entirely in the hop.
Fixed with a tuned transport (`maxUpstreamConns = 256`).

### A synchronous log write per decision

The decision log went straight to stdout through slog's mutexed handler: one
`write(2)` per decision, with every request goroutine queued behind it.

Measured in isolation under parallel load: **5,311ns → 392ns** per record, a
13.6× improvement, and — more to the point — no blocking I/O inside a lock every
request needs.

The fix went through three versions, and the middle one is the instructive one:

| Version | Result |
|---|---|
| Unbuffered `slog` → `os.Stdout` | one syscall per decision, serialised |
| `bufio.Writer` on a ticker | **no better**: flushing held the lock across the disk write, so every caller queued behind one big stall every 200ms instead of many small ones |
| Swap the buffer under the lock, write the copy with it released | request path is a memcpy; disk latency cannot reach it |

**A rarer stall is not a shorter tail** — it is the same work moved to the
percentile that gets reported. `TestFlushWriterDoesNotBlockCallersOnSlowIO`
fails against the `bufio` version, so that specific mistake cannot return.

---

## 4. D5, finally measured

The roadmap listed request-body buffering as "most likely thing to blow the NFR-1
budget, and currently unmeasured." It is not the likely culprit:

| Body size | Added cost |
|---|---|
| 1 KiB | baseline |
| 64 KiB | +9µs |
| 1 MiB | +400µs |
| 4 MiB (the cap) | **+1.65ms** |

Realistic MCP frames are kilobytes, where the cost is noise against 172µs of
identity work. It only bites at the cap, where it consumes a third of the p50
budget. **Debt with a known ceiling, not a defect.**

### D13: the response side has no cap, deliberately

Every response byte is hashed on the way back, at ~2.1 GB/s — **~0.45µs per
KiB**. Unlike the request body, this is *uncapped*: inspection can stop early
because a truncated body is still forwarded, but a partial `resp_hash` is
evidence of nothing.

| Response size | Hashing cost |
|---|---|
| 4 KiB | ~1.6µs |
| 1 MiB | ~295µs |
| 8 MiB | **~3.0ms** |

Time-to-first-byte is unaffected — `hashingWriter` writes to the client before it
hashes — so what grows is total transfer time, because the hash serialises
between chunks. The alternatives are worse (no response evidence, or a hash that
covers "some of the response"), so this is a documented property rather than a
bug.

---

## 5. What we cannot certify on this hardware, and why saying so matters

**The p99 gate is not resolvable on a shared laptop.** The *ungoverned* baseline
— a direct loopback call to a trivial Go server, with the proxy nowhere in the
path — showed:

- p99 swinging between **1.6ms and 14ms** across arms of the same run
- p999 reaching **93ms**
- max up to **130ms**

Against a **5ms** budget for the *added* cost. The effect is smaller than the
ruler's markings.

`cmd/gurdy-bench` therefore reports **INCONCLUSIVE** rather than a verdict when
the baseline's own p99 exceeds the gate. This is deliberate: a FAIL produced by
measurement noise reads exactly like a FAIL produced by the proxy, and only one
of those is worth chasing.

### Three things that made the numbers lie, all now guarded

**Coordinated omission.** A closed-loop generator — send, await, send the next —
cannot enqueue work faster than the system drains it, so it never observes
queueing delay. `gurdy-bench` is open-loop: requests are emitted on a fixed
schedule and each is measured from when it was *due*, not when it was sent. It
also reports when it fell behind its own schedule, because then the offered load
was below target and **the tail is understated, not flattered**.

**Arm ordering.** The first version ran baseline-then-proxy and produced a
failing p99. Pointing both arms at the *same* upstream still produced a 7× gap:
the second arm inherits the first's cooling connections, garbage and scheduler
state. A fixed order does not compare two systems, it compares two moments. Now
A/B/A, with the baseline on both sides and their disagreement itself reported.

**Percentile subtraction.** `p99(proxied) − p99(direct)` is not the p99 of the
added latency: percentiles do not subtract, and the two tails need not come from
comparable requests. Both distributions are printed in full and the delta is
labelled an estimate.

### Timer resolution, below ~2000 req/s

At 1,000 req/s the inter-arrival gap is 1ms, at the edge of the platform's timer
resolution, so each sample carries sleep-wakeup jitter unrelated to the proxy. It
shows up unmistakably: the tail is **worse at 1,000/s (10.5ms) than at 3,000/s
(896µs)**. That is not a load response, it is the clock. Throughput and p50 are
trustworthy at any rate; the tail needs a quiet dedicated host or a rate high
enough that the generator never sleeps.

### The outliers are the OS, not GC

Max ranges 1.8–17.3ms run to run. With 32KB and 398 allocations per decision,
garbage collection was the natural suspect. **`GOGC=off` produced the worst max
of the lot (17.3ms)**, so it is scheduler preemption on a shared machine, not
collection. Recorded because the plausible-but-wrong answer would have sent
someone optimising allocations for no gain.

---

## 6. The tools

### `internal/clock` — live, per-stage, in production

```bash
curl -s localhost:8091/latency | jq        # per-stage percentiles
curl -sX DELETE localhost:8091/latency     # start a fresh window
```

One monotonic clock read and atomic adds into fixed buckets: **~100ns per
observation with every core contending**, zero allocations, 0.03% of the stage it
measures. There is no flag to disable it — a knob for a cost that size is a knob
nobody should have to think about, and one that defaults off is a tool nobody has
when they need it.

Percentiles, never averages: an average is precisely what hides a tail, and a
mean service time would have shown nothing wrong in any defect found here.
Reported percentiles are within **6.25%** and are the low edge of their bucket,
so the tool understates rather than overstates.

**The payload states what it cannot see.** The hop is the larger term of NFR-1's
budget and none of it appears there, so the exclusion travels with the data
rather than living only in this document.

### `cmd/gurdy-bench` — the composed gate

```bash
go run ./cmd/gurdy-bench -proxy http://127.0.0.1:9400/ -direct http://127.0.0.1:9401/ \
  -admin http://127.0.0.1:9402 -rate 1000 -duration 30s -gate
```

Open loop, A/B/A, refuses to subtract percentiles, and **fails a run that dropped
ledger records before it reports latency at all** — a proxy that sheds evidence
under pressure gets *faster*, so that check has to dominate any celebration of a
p99.

### Microbenchmarks — which component, not whether it passed

```bash
go test -run='^$' -bench=. ./cmd/gurdy-proxy ./internal/tis ./internal/policy
go test -run TestDecisionServiceTimeDistribution -v ./cmd/gurdy-proxy
```

`go test -bench` reports ns/op averaged over the run, which is why
`TestDecisionServiceTimeDistribution` exists separately: it reports the
*distribution* of in-process decision time, and that is the half of NFR-1 that
does not need a deployment.

---

## 7. What remains

| Item | Why it is still open |
|---|---|
| **Composed p99 on a quiet dedicated host** | The gate NFR-1 actually specifies. Not resolvable on shared hardware; needs a sidecar deployment |
| **30-minute sustained run** | Only 60s done. The long window is for *drift* — memory, file descriptors, latency creep, ledger rotation — none of which is observable in a minute |
| **Fan-out burst: 20 sub-agents × 50 concurrent calls** | A correctness-under-concurrency test, not a latency one, and the likeliest place a lineage race would appear |
| **D10: a TIS that hangs rather than refusing** | Both SDKs degrade correctly when the socket is *absent*; a wedged mint stalls for the 5s timeout |
| **D12: the autoMint mutex** | ~14,100 vs ~30,300 decisions/sec. Above NFR-2, so a ceiling rather than a blocker |

Nothing measured here suggests the budget is at risk. What it says is which parts
we own: **6% of the p99 budget on the request path, a predictable per-byte cost
on the response, and a hop whose cost belongs to the deployment.**
