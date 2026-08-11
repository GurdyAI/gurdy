# Activity Log

What actually happened, newest first. Terse. `docs/roadmap.md` tracks what's *left*;
this tracks what's *done*, what was deliberately skipped, and why.

Entries before 2026-07-25 are in `git log` — this file starts where it starts.

---

## 2026-08-10 — D14, part three: pruning declares itself, and only when asked

Author decision: **Gurdy prunes on an operator command and never on a timer.** `POST
/retention/prune?keep=N`. No max-age setting, no background sweep. The signed retention record makes
either shape auditable; it does not make both defensible, and a product that quietly deletes its own
evidence on a schedule is a harder thing to stand behind than one that does it when a human asks.

**It lives on the admin API because the running proxy is the only thing that can do it safely** — it
holds the signing key, the open chain, and the writer goroutine the append has to be serialized
against. Pruning therefore goes through the same queue as every write, via a control message, rather
than racing it from an HTTP handler.

**Record before effect**, which is the ordering §5.5 already demands of an enforced decision. The
declaration is appended, signed and synced *before* a single file is unlinked. The asymmetry is the
point: crash in between and the record over-claims — it names a prune that did not happen, the files
are still there, verification passes on a complete chain. Crash the other way round and the export has
an undeclared hole, which fails verification and is indistinguishable from tampering. Only one of
those is survivable, so the code takes it deliberately.

Whole segments only. Pruning *within* a segment would mean rewriting a hash chain around the hole,
which is the operation the chain exists to make impossible.

**Writing the pruner exposed a defect in the seam check I shipped that morning.** It excused a
missing beginning only when the *first surviving* segment carried the retention record — but the
pruner appends to the chain's *current* segment, because that is the only file being written. Every
real prune would have failed verification. Fixed by treating the declaration as a property of the
chain rather than of one file, and while fixing it, a second hole closed: the record now has to
**cover** the gap it excuses. A retention record pruning through seq 40 says nothing about a chain
that starts at seq 900, and accepting it would have been the tidiest available way to dress a partial
handover up as retention.

That is twice now that building the writer has found something wrong with the reader — first the
`gap or splice` rejection, now this. Worth noting as a pattern rather than a coincidence: a reader
written before any real data exists is written against imagined data.

**Tier boundary settled while merging** (author decision 2026-08-10), because it was worth asking
rather than assuming: **pruning is free, and manual on purpose.** The free tier writes the same ledger
at the same ~92 GB/day, so a user with no supported way to reclaim disk deletes the export by hand and
destroys the chain — the exact outcome the signed retention record exists to prevent. What is paid is
retention as a *policy*: schedules, per-tenant rules, fleet-wide application, all `gurdy-fleet`. Same
shape ADR-14 draws for enforcement — the capability is free, the coordination is paid — and the
manual step is deliberate friction rather than a missing feature. §5.8's two tier bullets now say so
in both directions, since the paid list already carried the word "retention" and could have been read
as claiming the whole thing.

`SECURITY.md` records the cost honestly. This widens the admin API from "disarm the proxy" to
"disarm it and delete evidence" — not worse in *kind*, since anyone who can POST there can also stop
the process and a stopped proxy records nothing, but worse in degree. Two things bound it: pruning
removes whole segments only after a signed record names what went, so an attacker who prunes leaves a
signed admission that they did; and it cannot shorten or rewrite a segment at all.

---

## 2026-08-10 — D14, part two: the writer rolls, and the seam is checked where it can be

Part one landed the schema and the reader. This is the writer, plus the only place the
chain-across-files claim can actually be tested.

**Partitions roll at 256 MiB** — roughly four minutes at the soak's measured 65 MB/min, and a size a
reader can still open, verify and move. The bound is on the *file*, never on the evidence: rolling is
the alternative to an unbounded file, not to keeping records. A failed roll counts a write error and
keeps writing to the segment it already has, because monitor mode may not drop traffic to protect its
own tidiness (NFR-3).

**Sealing before the roll is the load-bearing part, and it is not tidiness.** A segment closed with
unsigned records at its tail is one nobody will ever sign: resume opens the *latest* segment, so those
lines would sit outside every signature forever — and anyone with file access could append to them.
The `resumed` coverage record exists because a crash leaves exactly that tail and a crash is
unavoidable. A roll is avoidable, so it must not manufacture the same condition on purpose.

**Resume continues the last segment, not the first.** Appending to segment 1 of a rolled chain would
fork it into two files both claiming the same successor, and nothing downstream could say which was
the real one. A resumed segment also inherits its size, so it rolls on its total rather than on what
this run happened to add.

**Ordering is by header, never by filename.** `gurdy-verify` groups segments by tenant/workload/
instance from inside the signature and sorts by `segment`. A filename is unsigned and renameable, so
ordering evidence by one would let a rename reorder a chain — the same argument that put partition
identity in the header in v0.8.5. Segment 1 keeps its original filename, so exports written before
rotation existed need no migration.

The cross-file check reports four things a single-file verify structurally cannot see: a segment
following the wrong predecessor, a missing middle, two files claiming one segment, and a chain that
begins mid-stream. **Only the last is excused by a retention record**, which is the entire distinction
part one existed to make — authorised pruning versus someone supplying the part that suits them.

Tested as a pure function over verify results rather than by manufacturing rolled files in the CLI's
tests. Real rolling is already covered in `internal/ledger` (300 records across several segments, each
verifying alone, seams and seq continuity checked, sealed segments asserted to have nothing
uncovered); duplicating that here would have tested the ledger twice and the grouping never.

Coverage ratchet 82.8 -> 82.9. Still to build: the pruner. It writes the retention record before
unlinking, and its *shape* is a real question rather than an oversight — an evidence product deleting
its own records on a background timer is a different proposition from an operator running a command,
and the record makes either one auditable without making both wise.

---

## 2026-08-10 — D14, part one: the reader ships before the writer

The soak's finding turned into a spec amendment (v0.8.7) plus schema and verifier support. **Nothing
rolls files yet, and nothing prunes**, which is the whole point of the sequencing.

**Why the reader had to go first, demonstrated rather than argued.** A verifier that meets a segment
it was never told about rejects it — and not with a helpful message. Mutation-tested by disabling the
new continuation branch and handing it a legitimate segment 2:

    record 1: seq 6 after 0 (gap or splice)

That is a deployed verifier calling a sound export tampered. Ship the roller first and every verifier
in the field strands the first chain that rolls; ship the reader first and the roller is uneventful.
Same ordering `finding` took in v0.8.4, for the same reason, and the code already said so in a comment
that turned out to be the design.

**The seam is an ordinary chain link, not a new mechanism.** A continuation segment's `prev_hash` is
the SHA-256 of the previous segment's last line — exactly the rule every record already follows. My
first draft added a `prev_segment_hash` field beside it before I noticed it would carry the identical
value: two fields that must agree are one field plus a way to disagree. Only `segment` is new, and
absent means 1, so chains written before segments existed read correctly instead of as "segment 0,
predecessor unknown".

**The property worth stating: a segment verifies perfectly while everything before it is missing.**
So `VerifyFile` *reports* what a segment continues from rather than resolving it. Handed one file it
cannot know whether the predecessor exists, and someone producing segment 5 alone looks, at the file
level, exactly like someone whose chain legitimately starts there. The holder of the export checks
that the predecessor's head hash equals the successor's declared link; nothing inside a single-file
verify can. A continuation declaring *no* predecessor is rejected outright — every other
begins-mid-stream case is checkable by someone holding the earlier segments, and that one is not.

**Author decision: Gurdy may delete its own evidence, but only declared and signed.** `kind=retention`
names `pruned_through_seq` and `pruned_through_hash`, chained and signed like anything else. The hash
is what makes it checkable rather than merely stated — a reader who still holds the pruned segments
can confirm it names their real terminal line. The consequence is the design: **deleting segments
without the record leaves a chain whose head links to a line nobody has, which fails verification and
should; deleting them with it leaves a statement a reader can weigh.** Counted separately from
`dropped`, because loss the writer regrets and deletion someone authorised are opposite claims and a
reader who conflates them learns nothing from either.

One assumption checked and found wrong, which changed the scope. I expected the new record kind to be
the urgent part, on the `finding` precedent — *"the verifier must already know the kind or the first
record would make every deployed verifier reject a whole export."* It is not: `VerifyFile` already has
a `default:` arm counting unknown kinds without failing. Segmentation is the part that strands a
verifier, because it trips `seq` continuity and `prev_hash` **before** the kind is ever inspected.

`seedSegment` is the one piece of writer-side machinery that landed, and it is not a test hook: it is
the seam the roller will use, exercised now by tests that prove the verifier accepts a segment a
*real* writer produced — signatures and all — rather than a fixture shaped to pass.

---

## 2026-08-08 — thirty minutes at 1k/sec: nothing drifted, and the ledger ate 1.9 GB

The §3.G soak, and the first run long enough to see anything a minute hides. 1.8M requests through a
real proxy against a stub upstream, `gurdy-bench -soak 30m -soak-window 1m`.

**The decision path does not drift.** p50 753µs → 761µs (+1.1%), p99 995µs → 998µs (+0.3%), first
window to last. The open-loop schedule held at 1,000/s in every one of the 30 windows — it records
lag rather than absorbing it, and it never fell behind. **Zero dropped records, zero write errors,
zero identity failures** across all 1.8M calls, which is the check that has to dominate any reading
of the latency: a proxy shedding evidence under pressure gets *faster*.

Memory rose 16.5 MB → 46.9 MB and decelerated the whole way — +32 KB/min at minutes 15–20, +6 KB/min
at 25–30. That is a plateau, not a leak. Worth saying what the run could **not** see: D6's unbounded
`autoTxn` map is keyed by client IP and every request came from one, so a soak is precisely the wrong
shape to catch it. A clean soak is not a clean bill of health for a leak whose trigger the soak does
not exercise. File descriptors held 44–82, no trend.

**The finding is capacity: D14.** The export grew **1.9 GB in thirty minutes** — ~65 MB/min, ~92 GB
a day at NFR-2's rated load — into one append-only file per partition with no rotation, retention or
compaction. 3.66M records for 1.8M calls (2.03 each: decision + response, as designed), ~560 bytes
apiece.

Append latency did not degrade as the file grew, so this is a capacity problem wearing none of the
usual performance symptoms — which is why thirty minutes of flat percentiles was nearly a clean
result. It is also why the fix is not "add logrotate": **the file is the chain.** `prev_hash` links
every line to the previous one and the header names one pubkey for the whole file, so rotation has to
say how a verifier walks across the seam, and compaction has to explain what a hash chain with a hole
in it proves. Blocks any deployment expected to run for days, which is all of them.

**Soak mode reports; it does not gate.** Added to `gurdy-bench` rather than written as a second load
generator, and deliberately with no baseline arm: A/B/A exists to attribute *added* latency, while a
soak compares this proxy at minute 1 to the same proxy at minute 30. Per-window output rather than
one aggregate, because pooling thirty minutes averages away the creep it exists to expose. No
pass/fail, because the thresholds worth gating on are what this run establishes, and a gate invented
before the first measurement is a guess wearing a number's clothes.

Two things confirmed in passing. The proxy refused to start with the state directory inside the
session scratchpad and **said exactly why** — the TIS socket path was 129 bytes against a ~104-byte
kernel limit, and the error named both the limit and the two flags that fix it. And on SIGTERM it
wrote its `coverage/shutdown` record, so the D7 lifecycle chain closes properly rather than leaving
the absence that means a crash.

---

## 2026-08-07 — the fan-out burst, and what it caught on its first run

§3.G's last correctness item: 20 sub-agents derived from one root, 50 concurrent calls each, correct
lineage on every record. `cmd/gurdy-proxy/fanout_test.go`. **1,000 calls, 1,000 decision records
checked, zero dropped** — the bounded queue (cap 1,024) absorbs an instantaneous 1,000-call burst
without shedding evidence, which was not obvious going in and is the more reassuring half of the
result.

**The assertion is the part worth explaining.** The failure this hunts is attribution *crossing*
between agents under load — a record saying agent-07 made a call agent-03 made. That is the worst
defect available to an evidence product: not a missing record, which a reader can see, but a present
and plausible record naming the wrong actor. Checking that a record is self-consistent does not catch
it, because `lineage[1]` and `asserted_principal` come from the same credential and would agree
whichever call they were attached to. So each agent calls a tool named after itself, and the test
asserts the **wire** and the **credential** agree — the tool name arrives in the request body, the
identity in the header, and they can only match if nothing crossed between the two.

Mutation-checked rather than trusted: making each agent send the *next* agent's credential fails with
`agent-19: lineage does not match the caller: [orchestrator agent-00]`. The record count is also
logged unconditionally, so a passing run shows it checked a thousand records rather than zero — the
vacuous-pass shape this repo keeps finding in its own gates.

**It found a data race immediately, and not where it was looking.** `-race` flagged `newHarness`:
the upstream stub wrote `saw` and `sawHdr` from every handler goroutine with no lock. Latent for the
life of the suite because every other test sends one request at a time, so two handlers never
overlapped. A test-harness defect rather than a proxy one — but a harness that races is a harness
whose failures get attributed to the code under test, and this one would have turned CI red on a
change that was correct.

Nothing in the proxy raced. Full `-race` suite green after the harness fix.

---

## 2026-08-07 — the cross-model review caught the regression the fix introduced

A Codex pass (gpt-5.5, read-only) over the merged packaging + keyfile work. It cleared three things
independently — dropping `registry-url`, the `@gurdy/sdk` tarball contents, and any
"passes while testing nothing" path in the new `sdks` job — and raised three. Two were worth acting
on and one was worth writing down.

**It caught a regression I introduced while fixing the race below.** `os.Link` is not supported on
every filesystem — FAT/exFAT, some FUSE mounts, some container volume drivers — and `LoadOrCreate`
returned the bare errno. The old `O_EXCL` path worked anywhere, so the fix silently narrowed where
the proxy can keep its state directory, and the operator's only clue would have been
`link: operation not permitted` on a path they chose.

**Deliberately not fixed by falling back** to `O_EXCL`-then-write on that error. The fallback would
reintroduce the torn-read window on exactly the filesystems nobody tests, so the rare deployment
would carry the bug the common one no longer has. A refusal an operator can act on beats a race they
will never reproduce. The error now names the requirement, and a `ponytail:` marker records the
ceiling and its upgrade path (O_EXCL plus a lockfile, not a silent fallback).

**The six-package npm publish is not atomic, and no ordering trick makes it one.** Known, but only
half-written-down: a 409 or a network blip partway leaves some packages live at the new version and
the rest missing, with those numbers burned. Ordering protects the *install*; nothing protects the
*release*. Three things narrow it — the SDK's tests run before anything publishes, platform packages
precede the wrapper, the SDK goes last — and none close it. Now stated in `packaging/README.md`
along with the recovery (bump the patch and re-release; never re-publish a burned version).

The useful part is what it does to a decision made earlier the same day. **Stage-only publishing was
deferred on security grounds**, and staging is also the only mechanism npm offers that could make
the publish atomic. That is a second, independent argument, and it turns the deferral into a question
with a fact attached: is promotion atomic *across* packages, or only per-package? If only
per-package, the original reasoning stands untouched.

**The third finding was fair and got a comment rather than code.** The strengthened concurrency test
is probabilistic — it makes a loser reading mid-window likely, it does not force it. Proving the
window's absence would need an injectable seam between create and write, i.e. test-only machinery
inside the function whose simplicity is why it is auditable. The test now says it is a probability
instead of letting the round count imply proof.

**Two things about running Codex at all, since both cost time.** The MCP server reported
`Codex CLI not found — install with npm install -g @openai/codex`; it *is* installed
(`/opt/homebrew/bin/codex`, Homebrew cask). Two faults were stacked and the message named neither:
the server's PATH omits `/opt/homebrew/bin`, and the model I had asked for (`gpt-5-codex`) is
rejected outright for a ChatGPT account. Driving `codex exec` from the shell avoids both. And
`codex exec` reads stdin when it is piped, so launched detached it blocks on EOF — it sat for 21
minutes having started no session at all. `< /dev/null` is the whole fix.

---

## 2026-08-07 — the key file existed before it meant anything

`TestConcurrentCreateConverges` went red on CI having passed locally every time. Not a flake.

`keyfile.LoadOrCreate` created the key with `O_EXCL` and wrote it *a moment later*. O_EXCL makes the
**creation** atomic and says nothing about the **contents**: it publishes an empty file at `path` and
fills it afterwards, so a caller taking the `ErrExist` branch inside that window reads nothing, or
half a PEM block. The function's own comment explained why creation had to be atomic and the
implementation delivered atomicity for the wrong half.

What makes it worth more than its size is how it fails. It surfaces as `is not PEM` — indistinguishable
from a corrupt key on disk, and those two demand opposite responses. A corrupt key means *refuse*: a
key you cannot read is not a key that is absent, and treating the first as the second silently mints a
new identity and starts a chain nobody can tie to the previous one (which is exactly what the tests
added on 2026-07-27 exist to pin). A torn read means *wait* — the winner has not finished, and the key
is fine. The proxy would have taken the refusal path for a file that was about to be perfectly valid.

This is the repo's recurring shape once more, **state that outlives its own proof**, here inverted:
a file that exists *before* it means anything.

Fixed by writing to a temp file and `os.Link`-ing it into place. Link fails with `ErrExist` if the
destination exists, so the key becomes visible at `path` already complete. `os.Rename` would have been
wrong in the precise way this function exists to prevent — it clobbers, so two racers would each
install their own key and each return the one the other overwrote, which is the divergence D2 was
closed to stop.

**The test was strengthened rather than left to pass**, because the version that shipped could only
fail on someone else's hardware: one round of eight goroutines, green locally every time, red on a
shared runner immediately. A test with that property gets called flaky and muted, and then the bug
comes back. It now runs 20 rounds of 16 goroutines released from a single starting gate, so the losers
arrive *during* the window instead of after it. Confirmed against the old implementation before being
trusted — reproduces at round 11 locally, where the original never did once.

Scope note: this is a defect in shipped code, not in the packaging work that surfaced it. Any
deployment where two processes start against one state directory could hit it — replicas, or a
restart racing itself.

---

## 2026-08-07 — the npm org exists, and the SDK it unblocks had no way to ship

The `@gurdy` org landed on npm (author). Checking what that actually unblocks turned up an
asymmetry nobody had noticed: **the PyPI wheel ships `sdk/python` as the `gurdy` package, and
nothing published `sdk/typescript` at all.** The release workflow built and published
`@gurdy/cli` — the binaries — and stopped there. §5.9 names `@gurdy/sdk` as a shipped artifact;
it had a README telling people to `import * as gurdy from '@gurdy/sdk'` and no path to the
registry.

The asymmetry is not a mistake in the Python packaging, it is §3.3 reasoning that does not
transfer. PyPI forced one package because `pipx install gurdy` and `import gurdy` collide on one
name. npm has no collision: `@gurdy/cli` and `@gurdy/sdk` are just two packages, so the SDK stays
pure TypeScript with no binaries and no `dist/` dependency. It publishes last in the existing job,
after the CLI's ordering-sensitive sequence, so a failure in the SDK cannot strand the platform
packages half-published.

**Three things the pack dry-run caught, all of them the "ships the wrong bytes" kind:**

`files: ["dist"]` would have published the test suite and the conformance driver — `tsc` emits
`dist/test/` and `dist/conformance-driver.js` alongside `dist/src/`. Narrowed to `dist/src`, plus
`src` so the sourcemaps resolve against something instead of pointing at paths that do not exist in
the tarball.

`LICENSE` and `NOTICE` live at the repo root and would simply have been absent — `files` skips what
is missing without a word. The first fix was a `cp` in the workflow, which is a silent gap by
another name: anyone running `npm pack` locally still gets an unlicensed tarball. It is a `prepack`
script instead, so both paths get it and there is one place it can be wrong.

`npm ci` could not have worked: **`package-lock.json` was gitignored.** Committed. The reason to
commit it is not install speed — the package has zero runtime dependencies — it is that the lockfile
pins `typescript`, and the compiler is what decides the bytes in the published `dist/`. An
unpinned compiler in a repo that rebuilds every release on a second runner to prove the Go binaries
are byte-identical is the one place reproducibility was being asserted rather than held.

Version comes from the tag, not the committed `0.1.0`, on the same argument as `producer` in the
chain header: an artifact reporting a version nobody tagged cannot be traced back to a build.

**And the gap underneath all of it: neither SDK, nor the reporter, was gated in CI.** `ci.yml` had
one job — the Go proxy — and it ran the conformance corpus against the *reference* driver, which
proves the corpus works and proves nothing about Python or TypeScript. That was survivable while
nothing shipped from those directories. Giving `@gurdy/sdk` a publish path ended it: the release
would have been the first place its tests ever ran, against a workflow whose own comment says never
publish something that has not passed the gate. An `sdks` job now runs both SDK suites, the
reporter, and the corpus through *both* drivers — one job, because "two SDKs judged by one corpus
cannot drift" only holds if a single run can turn red on either of them. All green locally: 55
Python, 46 TypeScript, 27 reporter, 12/12 corpus per driver.

The reporter's three end-to-end tests still skip — they need a real verifier and a real export, and
a fixture ledger would test the parser while claiming to test the pipeline. Left skipping and said so
in the job.

Unchanged and still blocking everything: **the repo is private**, and every channel serves artifacts
from public GitHub URLs. Nothing publishes until that flips.

**Later the same day — npm joined PyPI on Trusted Publishing, and the token minted that morning was
obsolete by evening.** All six packages now verify this workflow's GitHub OIDC identity instead of a
secret. `HOMEBREW_TAP_TOKEN` is the only long-lived credential left in the release path, and only
because a git push to another repo has no OIDC equivalent.

Getting there needed a step the docs do not advertise: **npm cannot do a first-ever publish over
OIDC** (npm/cli#8544). A trusted publisher is configured on a package's settings page, and there is
no settings page for a package that does not exist. So six `0.0.0` stubs went up first — under the
**`placeholder` dist-tag, not `latest`**. That flag is the whole difference between a safe stub and
a trap: on `latest`, `npm i -g @gurdy/cli` would install a package that does nothing and reports no
error, wearing the product's name. With no `latest` tag at all the same command fails with "no
matching version", which is the truthful answer for something that has not shipped.

**Two config choices, both made by asking what the setting actually defends against:**

*Environment: blank.* The publish gate already exists — `release: published`, chosen over an
environment protection rule precisely because that would be "a repo setting somebody has to remember
to configure, and a rule enforced by discipline decays". Naming an environment here would put that
setting back, in a web UI, needing to stay in sync with a workflow file that nothing cross-checks.
What it buys is narrow (pinning publish to one *job* rather than any job in `release.yml`) and only
matters against someone who can already edit the workflow — who can edit the `environment:` line too.

*Allowed actions: `publish` only, not `stage publish`.* These are not additive. Granting both means
the staging gate exists and nothing has to use it, so it defends against nothing — an attacker
controlling the workflow picks `publish`. Stage-only is a genuine upgrade, and worth being precise
about why: the `release: published` gate authorises *"this tag ships"*, while staging would authorise
*"these exact tarballs go live"* — different claims, and the second catches a compromised action
dependency producing bad tarballs under release notes a human read and approved. It costs a 2FA
approval on six packages per release, in a different UI from the one where you clicked publish, which
on a two-person team is the shape of gate that gets rubber-stamped. Deferred with a trigger rather
than a date: the day someone outside the two of us can land a change reaching `release.yml`.

**Three things about the mechanics that would each have failed confusingly:**

`setup-node: 22` is not enough, and my first advice here was wrong. Trusted publishing needs npm
>= 11.5.1 **and** Node >= 22.14.0 — two floors, and Node 22 ships npm 10.x, which has no OIDC support
at all. The failure presents as an *authentication* error, which sends you hunting for a bad token
that is not there. Node 24 (Active LTS, ships npm 11) plus an explicit `npm@^11.5.1` install, pinned
to the 11.x line rather than `@latest` so a future npm 12 cannot change publish semantics without
someone editing the file.

`--provenance` stays. npm's docs say trusted publishing generates provenance automatically and the
flag is unnecessary; publishes have been reported to fail without it. It is a no-op if the docs are
right and load-bearing if they are not, which is the cheap side of that bet.

The `repository` field has to match the trusted-publisher config exactly — already true for all six,
but it is a silent mismatch class worth knowing about, since the symptom is again an auth failure
rather than anything naming the field.

**Self-review caught a half-published release, which is the failure this job was already shaped to
avoid.** The SDK step originally read `npm ci && npm test && npm publish`, placed after the CLI
publish so that a failure could not disturb the platform-packages-first ordering. That reasoning was
right about the ordering and wrong about *when the test runs*. `publish-npm` fires on
`release: published` — a **different workflow run** from the tag push that ran `gate` — so nothing in
the publishing run had tested anything. A failing SDK test would have aborted the job with five
packages live and the sixth missing: a half-published release produced by the test meant to prevent
one. Split into two steps, build-and-test before anything publishes and publish last. Test early,
publish late; the ordering guarantee is unchanged.

**And `registry-url` came off `setup-node`.** Its only job is writing an .npmrc containing
`_authToken=${NODE_AUTH_TOKEN}`, and with the token gone that expands to an empty credential. Checked
what npm actually does with an unset variable rather than assuming: it does not error on the
expansion, it 401s — so the entry is inert for auth. What is *not* known is whether an empty
`_authToken` short-circuits the OIDC exchange, and a first real release is the worst place to find
out. The default registry is already registry.npmjs.org and this repo has no .npmrc, so the line
bought nothing and could only cost. Deleting it was the whole fix.

Also verified rather than assumed, since the repo keeps finding gates that go green having compared
nothing: `gurdy-conform` exits **2** on an empty case directory, so a mistyped `-cases` path in the
new CI job fails loudly instead of reporting zero failures out of zero cases.

**The new job found a real race in `keyfile` on its first run, which is the argument for the job.**
`TestConcurrentCreateConverges` went red on CI having passed locally every time, and it was not a
flake — `LoadOrCreate` published an empty key file and filled it a moment later, so a racing caller
read half a PEM block. That is a defect in shipped code rather than in this packaging work, so it is
its own change: see the 2026-08-07 entry *"the key file existed before it meant anything"*. Noted
here only because the job that surfaced it is the one added below.

**The TypeScript job failed for a duller reason that was still a genuine defect.** `npm test` ran
`node --test "dist/test/*.test.js"` — quoted, so *node* had to expand the glob. Node 22 does that;
**Node 20 does not**, and the job pins Node 20 because that is the SDK's declared `engines` floor. So
the job was right and the test script was wrong: the package claimed support for a Node version on
which its own tests could not run. Unquoted, the shell expands it and both versions work. Worth
noting that this was only ever going to be found by running the suite on the floor we advertise,
which nothing did until today.

Still blocking, unchanged: the repo is private. What changed today is that the *pipeline* is no
longer waiting on anything of ours.

---

## 2026-07-27 — the coverage ratchet caught my own packaging work

With the clock test fixed, CI went red again on the coverage gate: **80.8% against an 82.7% floor.**
The cause was mine — `internal/version` landed with the packaging work and no tests, and a new
uncovered package drags the whole total down. The ratchet did exactly what it is for.

The fix was tests, not a lower floor. `Producer()` in particular had no business being untested: it
is written into every ledger chain header, inside the signature, and a reader uses it to decide
whether their export came from a build with a known defect. What it must never do is be empty, drop
the commit, or call a dirty build clean — so that is what the tests assert.

Two of them close known debt rather than chasing the number. `keyfile.LoadOrCreate` was at 68% with
its error paths untested, and those paths matter more than their size suggests: **a key that cannot
be read is not the same as a key that is absent**, and treating the first as the second would
silently mint a new identity and start a chain nobody can tie to the previous one. There are now
tests for a corrupt key, an unreadable key, the directory/file permission bits, and reuse of an
existing key.

Deliberately *not* done: padding with tests for trivial uncovered one-liners. CONTRIBUTING says not
to write tests whose only purpose is moving the gate, and the moment coverage work starts optimising
the metric it stops being evidence of anything. 82.8% against an 82.7% floor is thin, and the honest
response to thin is better tests later, not filler now.

---

## 2026-07-27 — the first CI run failed, and it took three tries to fix it honestly

`TestObserveIsCheapEnoughToLeaveOn` failed on the PR at **1.937µs/call** against a 1µs budget.
Nothing had regressed:

    local, no -race        4ns     the number the claim is about
    local, with -race    157ns     the detector instruments every atomic in Observe
    CI,    with -race   1937ns     plus a slower shared runner

480x, none of it ours. This repo already had the principle written down: `gurdy-bench` reports
**INCONCLUSIVE** when the host's noise floor exceeds the gate, "rather than blaming the proxy for the
machine" (§8.2). The unit test was doing exactly what the load harness exists not to do.

**The fix took three attempts, and the first two were wrong in instructive ways.**

*Attempt 1 — calibrate against one atomic add.* Locally beautiful: baseline 4.1x, mutex 9.0x, and
perfectly repeatable. CI scored the same unregressed code at **16.1x** and failed again. Cause: a
bare atomic add is a single `LOCK XADD` on x86 but an LL/SC loop on arm64, so the *reference* is
disproportionately cheap on x86. A ratio is only portable if the thing you divide by is.

*Attempt 2 — make the reference mirror Observe's own atomics.* Portability solved: 1.3x on both
architectures. But the signal collapsed — mutex 2.5x, map lookup 1.6x, overlapping the 1.3x baseline.
Both sides now paid the race-detector tax, which compressed exactly the differences being measured.

*Attempt 3 — measure without the detector.* Running the same comparison on a clean build separates
cleanly and consistently:

                  baseline   + mutex   + map   + alloc
    -race  arm64     1.3        3.1     2.0      —
    -race  amd64     1.3        2.5     1.6      —
    clean  arm64     1.2        2.2     3.1     4.6
    clean  amd64     1.6        3.0     3.3     5.9

The decisive row is the second: **under `-race` a real mutex regression (2.5) scores below what a
clean build gives a mere map lookup (3.1)**, so no threshold can separate them. The detector was not
adding noise, it was destroying the signal.

So the timing half now skips under `-race` — stated as a property of the measurement, not a
convenience — and CI gained a short non-race pass, or that half would never run anywhere. Threshold
2.0: worst clean baseline 1.6, cheapest regression 2.2, on both architectures.

The allocation check (`testing.AllocsPerRun == 0`) runs in **both** modes because it is exact and
race-invariant, and it is not redundant with the timing check: in attempt 1 the allocation mutation
measured 3.2x against a 3.4x baseline — *below* it. A timing ratio cannot see an added allocation.

Two things worth keeping from the process. **Rosetta made the architecture variable testable
locally** (`GOARCH=amd64 go test`), which turned a blind push-and-see loop into a measurement — the
third attempt was verified on both architectures before it went near CI. And a methodological error
found on the way: taking the minimum of three *ratios* let the map regression pass, because a slow
baseline sample and a fast Observe sample are not a matched pair. Minimum of each side independently.

Final matrix, clean build, both architectures: baseline PASS, mutex FAIL, map FAIL, allocation FAIL.

---

## 2026-07-26 — npm and PyPI, and a naming collision the spec had already resolved

Both channels repackage the binaries GoReleaser built; neither rebuilds. If npm compiled its own
copy, the binary a user installs would not be the one the release signed, the one `checksums.txt`
covers, or the one the reproducibility job checked — three guarantees quietly detached from the
artifact they describe.

**PyPI had a naming collision, and it was in the spec rather than the code.** §5.8 says `pipx install
gurdy` gives the CLI; the v0.8 changelog says the Python SDK is `gurdy`; `sdk/python/pyproject.toml`
already claimed the name. Nothing is published, so nothing was locked in. §3.3 turns out to have
decided it already — *"the wheel bundles the Go governance core as a platform binary (ruff/esbuild
pattern)"* — so `gurdy` is **one package doing both jobs**: `pipx install gurdy` puts the binaries on
PATH, `pip install gurdy` gives `import gurdy` plus the bundled core dev mode needs.

Binaries ride in `.data/scripts/`, which pip installs into `bin/` and marks executable — the ruff and
maturin mechanism. Deliberately not `console_scripts`: an entry point must be a Python callable, so
that route would put interpreter startup in front of every proxy invocation.

**The pure-Python fallback wheel is the interesting part.** The SDK is installed into someone else's
agent process, and platform wheels alone would make an unsupported platform unable to install it at
all — turning the on-ramp into a wall. So a `py3-none-any` wheel ships alongside: pip prefers a
platform wheel where one exists and falls back otherwise, leaving `import gurdy` working, enrichment
against a remote proxy working, and only the bundled dev-mode core missing. That is the SDK's
existing rule — degrade, never break — applied to packaging rather than runtime. It is built
**last**, so a build failure above cannot ship a pure wheel that pip would then *prefer* on a
platform whose real wheel went missing: a build error would otherwise become a silently
dev-mode-less install.

**npm is the esbuild pattern**, and publish order is load-bearing: platform packages first. Publish
the wrapper first and an install landing in the gap resolves optional dependencies that do not exist
yet, **succeeds** — they are optional — and leaves the user a command that cannot find its binary.

One real bug, found by testing rather than reasoning: **the symlinked-checkout install failed**.
`require.resolve` walks up from a file's *real* path, so a wrapper symlinked from a source tree
starts the walk in a directory with no `node_modules` and reports "the platform package is not
installed" for a package sitting right there in the consumer's tree. Worth recording that **my first
fix was wrong**: a list of guessed sibling directories, which did not cover the very layout that
produced the bug. `require.resolve(..., {paths})` re-runs the real resolution algorithm from the
working directory instead of imitating it. Imitating a resolver is how you get a fallback that works
only where you did not need one.

Also settled: `stdio: "inherit"` in the shim is load-bearing, not a default — `-stdio` relays an MCP
stream byte-for-byte, and piping it through Node risks re-chunking the exact bytes this project
promises not to touch. Verified byte-identical through the installed wrapper.

**PyPI needs no token.** Trusted Publishing has PyPI verify the workflow's GitHub OIDC identity
instead, which is the cosign-keyless argument again: no long-lived credential to leak, rotate, or be
compelled to hand over. npm still takes a token (published with `--provenance`) and is worth moving
to trusted publishing once the org exists.

A subtlety noted rather than discovered the hard way: GitHub artifacts do not preserve the executable
bit. Both packagers set the mode themselves, so it is covered — but the failure would have been a
published package whose binary will not run, found by a user rather than by us.

---

## 2026-07-26 — packaging: the release pipeline, and the field that had to land before it

Packaging turned out to have a deadline attached to it that nothing in the roadmap named.

**The ledger header did not record which build wrote it.** It carries tenant, workload, instance,
schema version, kid and pubkey — all inside the signature — but nothing identifying the producing
binary. That is fine until binaries are in other people's hands: the moment a defect is found in a
released build, every reader holding an export needs to know whether theirs came from an affected
one, and there was no way to tell. The project's own invariant says schema additions after evidence
exists are migrations, so **the release is exactly the deadline** — after it, this stops being a
struct field and becomes a migration across other people's evidence.

So `producer` (`gurdy/v0.1.0+9a9bb2408937`, `+dirty` for an unclean tree) now goes in the header,
inside the signature. Tampering with it breaks the chain, which is tested rather than assumed —
a field a reader consults to decide whether their evidence is affected is worthless if forging it
is undetectable. Absent renders as `none`; a build that set none is not the same claim as an
unknown build, and inventing a value would erase the difference.

**Reproducibility is the part of NFR-9 that actually matters here, and it is specific to this
product.** Gurdy's argument is that you check an export instead of trusting whoever handed it to
you. That collapses if the verifier is a binary we built and signed and asked you to trust — the
same assurance moved one level down. Reproducible builds close it: rebuild `gurdy-verify` yourself
and compare bytes.

Two GoReleaser defaults quietly break that, and both were **measured, not assumed**:

- stock ldflags embed `.Date`, the wall-clock build time, so two builds of one commit differ and
  nobody can reproduce either — including us. `.CommitDate` is a property of the commit.
- without `-trimpath` the absolute build directory is baked in. The same source at two paths
  produced two different hashes until it was added.

Also found by testing rather than reading: **a git-checkout build and a source-tarball build differ**,
because Go stamps `vcs.revision`/`vcs.time`/`vcs.modified` and a tarball has no `.git`. Rather than
disabling stamping we keep it and say *reproduce from a clone at the tag* — the stamps are real
provenance, and they are what makes "rebuild the verifier that produced this verdict" executable.
A release job now rebuilds each tag on a different runner in a different directory and fails on any
byte difference, because a reproducibility claim nobody re-runs is the sort of unverified assurance
this product exists to argue against.

**Signing is cosign keyless** — GitHub OIDC, no long-lived private key to lose or be compelled to
use, every signature in Rekor's public transparency log. A signature we did not make is publicly
discoverable rather than merely denied, which is the right property for this product to hold itself
to.

**The Homebrew detail that would have bitten us:** GoReleaser deprecated `brews` in favour of
`homebrew_casks`, and casks are **not** Gatekeeper-exempt the way formulae are. We ship unnotarized
by author decision (no Apple Developer account), so without an explicit post-install `xattr` hook
the cask would hand macOS users "the developer cannot be verified" — on a security tool, from the
channel we had just chosen as the *supported* macOS path. The hook restores the formula behaviour.

`install.sh` verifies SHA-256 before unpacking and refuses on mismatch or on an archive missing from
`checksums.txt`; both refusal paths are tested against a local fake release, not just written. It
checks the cosign signature when cosign is present. An installer for this product that piped an
unverified binary onto a PATH would be the loudest available counter-example to its own thesis.

**Self-review found three defects in the pipeline I had just committed** (Codex CLI is not installed
in this environment — reported rather than skipped, and the pass was run manually against the
questions it would have been asked):

1. **The reproducibility gate could pass having compared nothing.** `[ "$pub" = "$reb" ]` is true when
   both are empty, so a failed download or a changed artifact layout would have turned the check
   green. This is the *same* defect class as the DCO check earlier the same day, where a read-only
   module cache made a mutation test silently re-report the previous result. Twice in one session is
   a pattern, not bad luck: **a comparison gate needs an explicit "did I actually get both operands"
   step**, because the natural way to write one treats absence as agreement.
2. **GoReleaser version skew.** The release built with `~> v2` and the rebuild with `@latest`. A
   version bump between the two jobs produces a byte difference that reads as a reproducibility
   failure but is really a tooling difference — the most confusing possible way for this gate to go
   red. Both now pin `GORELEASER_VERSION`.
3. **Workflow-wide `id-token: write` + `contents: write`**, granted to the test job as well as the
   release job. Now per-job; `gate` gets `contents: read`.

Also sharpened: `install.sh` previously said "checksum verified, signature not checked", which
understates the gap. The archive and `checksums.txt` come from the same host, so a checksum match
shows the download was not corrupted **in transit** — it says nothing about origin, since anyone able
to replace the archive can replace the checksum beside it. Only the cosign signature establishes that
the artifact came from our release workflow. The script now says exactly that. Overclaiming what a
verification step proves is the one mistake this product cannot afford to make in its own installer.

Still to come: npm and PyPI, which are one problem rather than two — §3.3 wants the wheel to bundle
the Go core for dev mode, so the PyPI channel and the deferred dev-mode item are the same work.

---

## 2026-07-26 — OQ #12 closed: a DCO, because contributions stay in the open half

The author's answer to the question the licensing pass surfaced — *do we ever want contributed code
inside the paid product?* — is **no**, and that settles it: a DCO, not a CLA.

Worth recording why that single answer decides the whole question, because "CLA is safer" is the
reflex and here it is wrong. A CLA buys exactly one thing a DCO does not: the right to relicense a
contributor's work. Nothing else about this project needed it. Apache-2.0 §5 already makes
contributions inbound-under-the-same-licence, so accepting patches never required one. And
`gurdy-fleet` does not require one either, because ADR-13 puts the proprietary half in a *separate
repository* that **depends on** the Apache base rather than absorbing it — Apache-2.0 permits
proprietary derivative use, so building paid software on top of this code is already allowed to
anyone, us included. A CLA would therefore have bought only the one right we have now decided not to
exercise, and paid for it in the friction that turns a drive-by fix into a paperwork conversation.

So `DCO` (verbatim 1.1 — "changing it is not allowed") and a sign-off requirement, with the promise
stated in **both** directions in CONTRIBUTING: contributions are Apache-2.0 and stay in the open
half, and moving one into the paid product would need that contributor's explicit permission, per
patch. That is not a courtesy — it is what a DCO actually grants, and saying so is more reassuring
to a contributor than a vague "we respect your work".

`scripts/check-dco.sh` enforces it in CI on pull requests. A contributor agreement nobody verifies
is an honour system, and this codebase already holds that a rule enforced by discipline decays; that
rule applied to itself is a check, not a paragraph. Seven behaviours mutation-tested, and the one
that carries the weight is **#3: a `Signed-off-by` in someone else's name does not satisfy the
author's sign-off.** A check that only grepped for the trailer would pass that, and would be
certifying nothing — the sign-off's entire content is *this specific person* asserting they had the
right to submit. Also handled: multiple sign-offs pass when one is the author's (DCO (c), a patch
passed along), case-insensitive email match, and merge commits skipped — requiring a sign-off on a
merge commit only teaches people `--no-verify`.

**It applies to maintainers too**, which is deliberate. A DCO that the people merging exempt
themselves from is not a certification, it is a hurdle for outsiders. The practical cost is `git
commit -s`.

---

## 2026-07-26 — Apache-2.0, checked against the tree rather than restated

Apache-2.0 for the open half was already the decision (OQ #8 / ADR-13) and LICENSE, NOTICE and all
three package manifests already said so. So the work was not declaring it again — it was checking
whether the tree actually holds up under it. Two things did not.

**NOTICE contradicted a directory we ship.** It listed "the governance/evidence reporter" among the
proprietary components, but `reporter/` is in this repository, declares `license = "Apache-2.0"` in
its `pyproject.toml`, and is literally titled *"the free-tier local governance report"* (BR-11). A
downstream distributor reading NOTICE would conclude a directory covered by the grant was carved out
of it — precisely the file-by-file ambiguity ADR-13 exists to prevent.

The root cause is that **the spec uses one word for two products**: BR-10 puts "local mini-reports"
in the free tier and "evidence reports" in the paid one, and §5.8/ADR-8 then say "the reporter" for
the paid one without qualification. NOTICE inherited the ambiguity. It now names the paid artifact
as the **framework-mapped** evidence reporter (§5.6/FR-8 — the NIST/ISO/EU-AI-Act mapping) and says
plainly that the mini-report in `reporter/` is free and covered.

Also corrected there: NOTICE listed the local-enforce actuator as a covered component without noting
it does not exist. Harmless for licensing — the grant covers it when it lands — but it reads as a
feature claim in a file people read, and the README goes to some trouble not to make those.

**Nothing verified that our dependencies permit an Apache-2.0 outbound grant.** They do: all 25
modules `go list -deps` reports as actually linked are Apache-2.0, MIT or BSD-3, and both SDKs and
the reporter have zero runtime dependencies. But that was true by luck rather than by gate, and the
failure mode is nasty — one GPL or SSPL module arriving in a routine `go get` makes the licence we
publish one we are not in a position to offer, silently, to be discovered by someone else's legal
review.

So `scripts/check-licenses.sh` now runs in CI. It walks the *linked* set rather than `go list -m
all`, which would drag in test-only and indirect modules that never reach a shipped binary and fail
the build over dependencies we do not distribute. It checks the copyleft markers **first**, so a
dual-licensed file mentioning both cannot pass on its permissive half without a human looking. And
unrecognised licence text fails rather than passes, which is the correct direction for a check whose
job is to protect a claim we make to other people.

**Mutation-tested on all four branches**, and the fourth is the reason this note exists: the obvious
test for "module with no licence file" is to `rm` one from the module cache, but the cache is
read-only, so the `rm` failed and the script re-reported the *previous* mutation's failure. It looked
like a pass. Testing it properly needed a real module linked through a `replace` directive. A gate
verified by a test that could not run is a gate nobody has verified.

**Deliberately not adding SPDX per-file headers**, which the roadmap had paired with this item.
ADR-13 draws the boundary at the repository "rather than argued file-by-file" — per-file headers are
churn against the decision's own rationale, and they guard nothing that the dependency gate does not.
NOTICE now states the repo-level position explicitly, so a scanner finding no headers has an answer.

**OQ #12 (DCO vs CLA) is still open, but it now has a specific shape.** Apache-2.0 §5 already makes
contributions inbound-under-the-same-licence, so a CLA is not required to accept patches, and it is
not required to build `gurdy-fleet` on top either — Apache-2.0 permits proprietary derivative use,
and ADR-13's separate-repo structure means the paid half *depends on* the open base rather than
absorbing it. The single case a DCO does not cover is taking a contributor's code **out** of this
repo and into the closed one, which needs a relicensing grant. So it is a business question — will
we ever want that — not a legal-safety one, and it stays with the author.

---

## 2026-07-26 — SECURITY.md and CONTRIBUTING

**The hard part of SECURITY.md was saying what is *not* a vulnerability.** This project publishes
seven attacks its own pack does not stop, so a reporter finding one of them has found something we
already documented in `corpus/`. Without that stated up front, the first serious researcher spends
a weekend rediscovering trace 08 and we both waste the time.

So it enumerates the six claims that *are* in scope — evidence integrity first, misattribution rated
above lost records because a missing record is a visible gap and a wrong one is not — and then lists
the known-unmitigated items plainly: admin-API disarm reachable by any local process (§7), mint
unauthenticated on the socket, `MintTxn` accepting any root scope, the loopback egress exemption,
no rate limiting anywhere, and an agent that controls its own MCP server controlling its tool
declarations.

It also states the threat model, because it is unusual: **the adversary is usually the agent being
watched**, not a network attacker. That is what makes "the agent chooses tool names, argument names
and its claimed identity" the sentence that decides severity.

Reporting goes through GitHub private advisories — real, free, no mailing list or PGP key to invent.
I deliberately did not fabricate a security contact address. Response times are written as what a
two-person project can actually keep, with an escalation path if we go quiet, rather than an SLA
that would be a lie on week two.

**CONTRIBUTING could not state a contributor agreement**, because OQ #12 is open and choosing
between a DCO and a CLA is a legal decision rather than a documentation one. Rather than defaulting
to a DCO silently — which would be making the decision by omission — it says external PRs cannot be
accepted yet, and that issues, discussions and security reports are open now.

The rest is this project's actual conventions, which are stronger than most: the spec is normative
and wins over the code; **tests must have teeth and you mutate the implementation to prove it**, with
three of our own mistakes cited as why; corpus-first for SDK behaviour; the single-implementation
rule; and the coverage gate as a ratchet rather than a target, with an explicit "do not write tests
whose only purpose is to move it."

Every file path, command and debt reference in both documents was verified by running it.

---

## 2026-07-26 — a README, written by running it

The repo had no entry point. Its only top-level markdown was `CLAUDE.md`, which is addressed to me,
while Phase 1's exit criterion is a *stranger-run 15-minute demo with no author present*.

Written as a test rather than as documentation, and it behaved like one.

**The first draft's own quickstart did not work.** I pretty-printed the demo JSON across two lines
for readability. MCP stdio framing is newline-delimited, so that is two *incomplete* frames: the
shim relays them untouched, records nothing, and exits 0. A newcomer's first run would have looked
like a success and produced no evidence at all — the worst possible failure for a tool whose whole
claim is that it writes things down. Caught by running the README verbatim from a clean directory;
the fix is one line, and the warning box explaining it says why it is there.

**The on-ramp is the stdio shim, not the reverse proxy.** `-upstream` is required and a newcomer has
nothing to put in it, whereas `-stdio -- cat` governs something in one command with no
infrastructure. `cat` is a good stand-in MCP server precisely because it echoes the frame, which
also demonstrates byte-identical pass-through.

The demo ends where the product's argument does: an agent read `~/.ssh/id_rsa`, it is flagged and
forwarded and written down, `gurdy-verify` re-walks the chain with nothing but the binary and the
folder, and the reporter turns it into something a person reads.

**What the README leads with is what is missing** — no packaging, no blocking, seven published
attack gaps, an uncleared name. A governance tool that overstates itself has picked the wrong thing
to be bad at.

**Package names checked across channels.** `gurdy` on PyPI, `gurdy` and the `@gurdy` scope on
npm, and `gurdy` in Homebrew core were all unregistered — four 404s. Recorded so the packaging work
had a known target rather than an assumption.

---

## 2026-07-26 — tool-signature binding, and the half of it that cannot be built

§7 line 433 is more specific than "don't match on names": *"policy binds to upstream endpoint +
tool signature, not display name."* Both halves matter, and the reason the mechanism works is who
supplies each one — the agent picks which tool to call, the **server** publishes the schema through
`tools/list`, and the **endpoint** is where the proxy forwards. Neither of the last two is the
agent's to rename.

`internal/toolsig` watches `tools/list` responses and records, per endpoint, a content-addressed
hash of each tool's declared argument schema plus which arguments the schema says are paths or URLs.
Three attributes now reach policy on every tool call — `tool_endpoint`, `tool_signature`,
`tool_declared` — and the extractor resolves argument roles from the declaration before falling back
to its name heuristic.

Demonstrated end to end on the same call twice: before `tools/list` it is `declared=false`, no
`resource_path`, **allowed**; after, the schema identifies `victim` as a path and it is **flagged**.
Corpus trace 27 pins it.

**The half that cannot be built, and why it is not a shortfall.** Signature binding gives a tool a
stable identity; it cannot say what the tool *does*. A schema says `fs_write` takes a path and a
mode — not that `mode: "truncate"` destroys the file. Deriving that would need a model in the
decision path, which ADR-7 forbids permanently. So capability must be **declared by the pack, keyed
by signature**, which is `control_map.yaml` and therefore the pack registry — still with no owner or
date, and now with one more thing depending on it.

Corpus trace 08 was re-framed rather than closed: the proxy now knows `purge_file` and `delete_file`
share a declared schema and records it, so the information a control needs is present. What is
missing moved from the proxy to the pack.

**Two decisions worth recording.** No starter rule flags undeclared tools, for the same reason
"flag every unattested model call" was never shipped — most traffic is undeclared today and a
control firing on 100% of traffic is noise. And the registry stops recording at its bound rather
than evicting: eviction would let a flood of junk declarations push out real ones, turning known
tools into unknown ones and inverting what the registry is for.

**A bug worth naming.** `tools/list` is not governed traffic, so it took the early-return path in
`ServeHTTP` and never got the response wrapper — the capture never ran and the registry stayed
empty. Found by the end-to-end check showing `declared=false` after a successful list. The kind of
thing only a real round trip catches.

Coverage 83.6 → 82.7% (new package, new uncovered wiring). Still to do: the same observation on the
stdio shim, which already parses both directions so it is small.

---

## 2026-07-26 — the corpus closes its first gap, on itself

Fixed the case-sensitivity bypass the corpus found an hour after it existed, and watched the loop
work end to end.

**The bug.** `context.tool` was lowercased before evaluation so `DeleteFile` could not dodge a rule
written for `delete_file`. `resource_path` was not — and the flagship BR-11 credential rule matches
`resource_path like "*/.ssh/*"`. On macOS and Windows, `/home/u/.SSH/id_rsa` is the same file and a
different string.

**The fix is not "also lowercase resource_path".** The defect was that case folding was a property of
*one field* instead of a property of *matching*, which is why it was missed the first time. Every
string a policy compares is now folded — context attributes, the resource UID, the asserted
principal — and the ledger keeps the raw value, exactly as it already did for the tool name. A new
extractor attribute gets the safe behaviour by default rather than waiting for someone to remember.

The trade is written down rather than discovered later: where case genuinely distinguishes two files,
both now match. A Linux `.SSH` directory that really is distinct will flag. That is the right
direction to be wrong in — a spurious flag is noise in a monitor, a missed credential read is a
bypass — and there is a test asserting the over-match so it stays a known trade.

**The loop closed.** Fixing it turned trace 05 red:

    FAIL  [gap ] credential exfiltration: uppercase path segment — this known gap NO LONGER REPRODUCES

which is the entire reason `known_gap` fails rather than passes when it stops reproducing. Trace 05
is now a PASS pinning the fix, joined by trace 26 varying case across the whole path — because a
repair that special-cased `.ssh` would pass 05 and fail 26. **A trace proves an instance; a pair
proves the class.**

**My test fixture was wrong before the code was.** The first version asserted `context.tool ==
"delete_file"` against input `DeleteFile`, which folds to `deletefile` — folding lowercases, it does
not re-punctuate. The shipped rule is a prefix match for exactly that reason. Caught immediately, and
the comment now says so.

Mutation-checked: reverting to folding only the tool fails 8 unit subtests and 2 corpus traces.

26 traces, 19 defences pinned, 7 gaps remaining — five of which now share the single root cause of
matching on strings the governed party chooses, with the case dimension closed.

---

## 2026-07-26 — adversarial corpus v1, and what it found about our own pack

25 traces in `corpus/traces`, running in CI: **17 defences pinned, 8 gaps documented, 0 failures.**
That meets §8.2's bar of ≥25 replayable attack traces.

**Shares the conformance runner rather than forking it.** A trace is a conformance case asking a
different question — *did the pack reach the right verdict?* instead of *did the SDK produce the
right evidence?* — and the case format, judge, per-case proxy and export verification are already
identical. A forked judge is a judge that drifts, which is the defect class this project keeps
finding. Added to the shared runner: an `attack` narrative separate from `why`, a `policy`
assertion on records, and `known_gap`.

**Three outcomes, not two.** PASS, GAP, FAIL. A GAP is an attack that succeeds *today*: the trace
asserts what actually happens, states why, and names what closes it. The summary reads "N documented
gaps — attacks this pack does NOT stop", because a two-state runner would have forced every honest
finding into either a lie or a red build.

**The mechanism that stops `known_gap` becoming a graveyard: a gap that no longer reproduces is a
FAILURE.** The corpus lying about a weakness is the same defect as lying about a defence. This fired
on its first run and caught me: I had asserted that renaming an argument to `target` dodges the
credential control, and it does not — `pathKeys` already includes it. That trace is now a PASS that
pins the defence, plus a new one using `src`, which genuinely is outside the list.

### What the corpus found

Two of my first eighteen assumptions about our own pack were wrong, in both directions. The other
lesson was `provider()`: it maps loopback to `local`, which the unlisted-host rule exempts for dev
mode — so a relay on 127.0.0.1 collects an agent's prompts unflagged, and the harness cannot reach
the genuinely-unlisted branch at all. Both are now written down instead of assumed.

**Six of the eight gaps share one root cause**: controls match on strings the governed party
chooses — tool name, argument name, path case. That is the §7 aliasing problem, and the corpus now
makes the case for tool-signature binding empirically rather than by assertion. The remaining two
are missing controls: no spend policy (BR-11 advertises three protections and ships two) and no rate
control.

Notably, `resource_path` is matched case-sensitively while `context.tool` is lowercased — so
`/home/u/.SSH/id_rsa` reaches the tool unflagged on any case-insensitive filesystem. A one-line
bypass of the flagship BR-11 control, found by writing the trace.

**Grok was unavailable again** — its CLI returned only a preamble on two attempts, and the subagent
correctly reported that rather than substituting its own analysis unlabelled. This round was Codex
and ponytail.

---

## 2026-07-26 — the free-tier report, and eight ways it could have lied

`reporter/` — `gurdy-report`, Python, no dependencies. The last piece of the value chain: the
product could intercept, decide, record and verify, and nobody could read any of it.

**The design question was not what to put in it, but how it lies.** A governance report built from
real data still misleads through denominators, survivorship, absence-rendered-as-zero, monitor-mode
conflation, unanswered calls counted as successes, unsigned tails, and period boundaries that hide
unrecorded time. Each of those has a named defence in `report.py`, and the module docstring lists
them so the next person changing it knows what the shape is protecting.

Three properties carry the weight:

- **It does not verify chains.** §3.3 keeps one implementation in the Go core, so this shells out to
  a new `gurdy-verify -json` and consumes the verdict. Two implementations of a signature check
  drift, and the permissive one ships a green report over a forged export. A missing verifier is
  fatal, not degradable.
- **It refuses rather than caveats.** A failed chain, an empty directory or a partial failure yields
  NOT REPORTABLE, zero findings, exit 1. Verified live: a single flipped byte in one decision record
  produces a refusal naming the broken record and no findings at all.
- **Citations are a type, not a convention.** A `Claim` cannot be constructed without its refs.

### Codex found eight, and two were critical

- **A bare seq does not identify a record.** Every partition chain has its own seq space, so
  "Evidence: seq 2" named one record *per file*. The §5.6 citation requirement was satisfied in form
  and useless in practice. Citations are now `<export file>:<seq>` and the type rejects anything else.
- **Unsigned tails could be reported as verified.** `--allow-unsigned-tail` let records past the last
  batch signature into the findings, and `uncovered` was parsed but never rendered — so forgeable
  records could be counted and cited in a normal-looking report.
- **Verification and parsing were not bound to the same file set.** The verifier ran over the
  directory, then the reader re-globbed it; a file appearing in between would feed claims nothing
  checked. Now only verified files are parsed, and anything else present is named and excluded.
- **A verifier that failed to run could still produce a report.** Exit 1 means "an export failed" and
  the JSON is the answer; exit ≥2 means it never completed one. Also `bool("false")` is `True`, on
  the field that decides whether a chain is sound.
- Plus: unanswered undercounted (decisions with no `call_id` were excluded entirely, and a global
  answered-set let one chain's response answer another's decision), "stopped" inferred from any
  unrecognised `action_applied`, an uncited "Nothing to report" rendered outside the claim system,
  and a percentage labelled "% of records written" while dividing by decision records.

**I also found one myself while writing it**: `is_lifecycle` tested the *filename*, when v0.8.5
exists precisely because filenames are unsigned and renaming one silently re-attributes a chain. It
reads the signed `workload` field now.

Every fix has a test named for the failure, and three are mutation-checked: reporting over a failed
chain, allowing an uncited claim, and reporting violations without the stopped count.

**A trap worth recording:** the package exported `verify` the function alongside `verify` the module,
which shadows it — `from gurdy_report import verify` silently yields the function. It cost two
debugging rounds before I renamed the export to `verify_export`.

**Not in the free tier, deliberately:** control-framework mapping, violation narratives with
remediation, HTML/PDF. Those need `control_map.yaml` from the pack registry and are the paid
artifact (§5.6).

---

## 2026-07-26 — performance gates, and two defects only a composed test could see

§8.2's performance block. The instruction that shaped the whole chunk is the spec's own: **"never
certify NFR-1 by summing standalone microbenchmarks."** It was right, and the two real defects found
here were both invisible to every microbenchmark of the decision path.

**What the numbers say.** Added p50 is **217–265µs**, stable across every run, corroborating
`BenchmarkDecideCall` at 223µs. **6,000 decisions/sec with zero dropped records** — 6× NFR-2 — and
60s at 3,000/s moved 180k requests per arm with no drops and no write errors. Inside that 223µs,
**identity is 77%** (three ES256 operations); extract is 158ns and policy eval 922ns, together under
half a percent. Any future latency work is in the crypto, not the policy engine.

**D5 was not the culprit the roadmap suspected.** Body buffering costs +9µs at a 64 KiB frame —
noise against 172µs of identity work. It only bites at the cap: **+1.65ms at 4 MB**, a third of the
p50 budget. Debt with a known ceiling, not a defect.

### The two defects

**`MaxIdleConnsPerHost: 2`.** `httputil.NewSingleHostReverseProxy` inherits `http.DefaultTransport`,
which keeps two idle connections per host. A sidecar talks to exactly one upstream, so that was the
whole pool: past two concurrent calls every request dialled fresh TCP and left the old connection in
TIME_WAIT. Nothing in an in-process benchmark can see this, because it is entirely in the hop.

**A synchronous log write per decision.** The decision log went straight to stdout through slog's
mutexed handler — one `write(2)` per decision, every request waiting on it. Measured properly in
isolation: **5,311ns → 392ns** per record under parallel load.

### Where I was wrong, twice, and how the measurement caught it

**My first harness condemned the proxy on an artifact.** It ran the baseline, then the proxy, and
reported a failing p99. Pointing both arms at the *same* upstream still produced a 7× difference
between them — the second arm inherits the first's cooling connections, garbage and scheduler state,
so a fixed order does not compare two systems, it compares two moments. Now A/B/A, with the baseline
on both sides, and the two baselines' disagreement is itself reported.

**I then "fixed" the log with `bufio` and made it no better.** 34ms p99, because flushing held the
lock across the disk write: instead of many small stalls every caller queued behind one big one
every 200ms. A rarer stall is not a shorter tail, it is the same work moved to the percentile that
gets reported. The working version swaps the buffer out under the lock and writes the copy with the
lock released. `TestFlushWriterDoesNotBlockCallersOnSlowIO` fails against the `bufio` version, so
that specific mistake cannot come back.

**And I nearly claimed a fix the data did not support.** I attributed a 28ms p99 to the logging on
the strength of one noisy sample. Re-running showed the p99 was *better* at 3,000/s (896µs) than at
1,000/s (10.5ms) — physically implausible as a load response, and the giveaway that I had been
reading noise. At 1,000/s the 1ms inter-arrival gap sits at the platform's timer resolution. The
logging fix is real and worth keeping, but it is worth 5µs per decision, not 28ms of tail.

### The budget, decomposed

Asked plainly whether the latency budget was understood, the answer was "half" — and the missing
half was the gated one. So `TestDecisionServiceTimeDistribution` now times `decideCall` in-process
on a monotonic clock with no syscall in the measured region. The end-to-end noise is all in the
*hop*; the work the proxy performs is not, and its tail is therefore attributable.

Five repeats: p50 **179–183µs**, p99 **284–361µs**, p99.9 606µs–1.33ms. Saturating all 12 cores
(≈48k decisions/sec offered, 48× NFR-2) still gives p99 **1.55ms**.

| | p99 | share of the 5ms budget |
|---|---|---|
| derive (3× ES256) | ~240µs | ~5% |
| extract | 158ns | ~0% |
| eval (Cedar) | 922ns | ~0% |
| **the request path, all of it** | **~300µs** | **6%** |
| response hashing | ~0.45µs/KiB | ~2µs typical, ~3ms at 8 MB |
| the hop | the rest | 94% still available |

**The first version of that table was incomplete**, and the gap is worth naming: it covered the
request path only. Every response byte is hashed on the way back, at ~2.1 GB/s, and unlike the
request body that cost has **no cap** — a partial hash is evidence of nothing. Negligible for a
typical MCP reply, ~3ms for an 8 MB one. Now D13, and benchmarked.

That is the answer to "what is going on with the budget": our own contribution is 6% of it and
measured; the other 94% is a network hop, which is environment-specific by definition and which the
spec already declares gated for sidecar and best-effort for reverse proxy.

**And the obvious explanation for the outliers was wrong.** Max ranges 1.8–17.3ms run to run, and
with 32KB and 398 allocations per decision, GC was the natural suspect. `GOGC=off` produced the
*worst* max of the lot (17.3ms). It is scheduler preemption on a shared machine, not collection —
worth recording, because the wrong answer would have sent someone optimising allocations for nothing.

### The clocking tool

`internal/clock` answers the ownership question *live* rather than only in a benchmark. Per stage of
the §4.2 loop, served at `GET /latency`, with `DELETE /latency` for a fresh window.

Three decisions worth recording. **Percentiles, never averages** — a mean service time would have
shown nothing wrong in any defect found here, and the gated quantity is a tail. **No flag to disable
it**: measured at ~100ns per observation with every core contending and zero allocations, 0.03% of
the stage it instruments, and a knob for a cost that size is a knob nobody should have to think about
— worse, one that defaults off is a tool nobody has when they need it. **The payload states what it
cannot see**: the hop is the larger term of NFR-1's budget and none of it appears there, so the
exclusion travels with the data rather than living only in a doc nobody opened.

Live on 200 real calls it reproduced the offline finding exactly: decide p50 254µs, of which identify
is 221µs — **87%**.

Everything is written up in **`docs/performance.md`**: the budget table, the ownership split, both
defects, D5 and D13, and the four ways the measurement lied before it was fixed.

### What the harness refuses to say

**The p99 gate is not resolvable on this machine, and `gurdy-bench` reports INCONCLUSIVE rather than
a verdict.** The ungoverned baseline's own p99 swings between 1.6ms and 14ms and its p999 reaches
93ms, against a 5ms budget for the *added* cost. A FAIL produced by measurement noise reads exactly
like a FAIL produced by the proxy, and only one of those is worth chasing. NFR-1 gates a deployed
sidecar; it has to be measured on a quiet dedicated host, and that is the remaining work.

The harness also fails a run outright when the ledger dropped records, before any celebration of the
latency — a proxy that sheds evidence under pressure gets *faster*, so that check has to dominate.
And it reports when the generator fell behind its own schedule, because then the offered load was
below target and the tail is *understated*.

**Not done:** the 30-minute sustained window (only 60s), whose real purpose is drift — memory, fds,
latency creep, ledger rotation — and the 20×50 fan-out lineage burst, which is a
correctness-under-concurrency test and the likeliest place a lineage race would appear.

**New debt: D12** — `autoMint` holds a process-wide mutex across an ES256 verify on the no-SDK path.
2.15× throughput difference against the SDK-present path with identical crypto, so pure contention:
~14,100 versus ~30,300 decisions/sec. Far above NFR-2, so recorded rather than fixed; the fix is to
compare a cached expiry instead of re-verifying.

Coverage 82.8 → 82.9%. `gurdy-bench` is excluded from the floor like `gurdy-conform` — both are
harnesses — but its arithmetic is tested, because a percentile off by one index would make every
number it prints a guess dressed as a measurement.

---

## 2026-07-26 — the TypeScript SDK, and the corpus paying for itself

`sdk/typescript` (`@gurdy/sdk`, ESM-only, no runtime deps) **passed all 12 conformance cases on
the first run.** That is the whole argument for building the corpus before either SDK: the second
one had a target rather than an opinion, and every hard decision was already made and mutation-
tested in a language-neutral form.

**Where it deliberately diverges from Python**, because Node's runtime differs:

| | Python | TypeScript |
|---|---|---|
| Entry API | decorator + context manager | `task(opts, fn)` callback only |
| Store | `ContextVar` | `AsyncLocalStorage`, entered **only** via `.run()` |
| Threads | shared memory, carry the context | `worker_thread` is a separate isolate — a *carrier*, like a process |
| Origin match | parsed by hand | `URL.origin` |

`enterWith` and `withScope` are not exposed at all: both leak the store into the caller, which is
misattribution. No decorators and no `await using` either — a decorator evaluates at definition
time, and an `await using` resource that is never disposed leaves the binding in the caller. Both
failures are misattribution, and that is the one thing this design will not trade for ergonomics.

**The Node-specific landmine, which Python does not have.** A callback registered inside task A but
*invoked* from elsewhere runs in the context of whoever called `emit()`. It does not lose the
binding — it acquires **someone else's**. `gurdy.bind()` captures at registration; the README leads
with this rather than burying it, and a test asserts the unbound behaviour too, so if Node ever
changes it the docs get caught with it.

**Grok** was worth the round trip twice. First for the divergence table above. Second for
`workerData` versus `postMessage`: passing the carrier once at worker construction pins the *first*
task's identity to every later job a pooled worker serves. The driver therefore reuses one worker
across the whole case, which is the arrangement that would expose it.

### Codex found four, and two would have broken traffic

- **`gurdy.fetch(new Request(url, {headers}))` dropped every header the caller set.** Headers on a
  `Request` passed as `input` live on the Request, not in `init`, and the wrapper built its
  authoritative header set from `init` alone — so `Authorization` and `Content-Type` vanished. An
  SDK that breaks the traffic it was only supposed to observe is the exact failure this project's
  fail-open posture exists to prevent, and it would have been worse under `instrumentGlobalFetch()`.
- **`adopt()` trusted the carrier.** A carrier crosses an isolate boundary as plain data, so its
  declared type proves nothing: `{txn: null}` stamped the header `"null"` — a claim nobody made —
  and a token containing a newline throws inside `Headers.set` at the developer's own call site.
  Now revalidated, and a malformed carrier runs the callback *detached*.
- **Bindings were mutable.** `readonly` is a compile-time promise and nothing more. `using` stored
  the caller's object and `bind` captured that reference, so a later `b.txn = other` retroactively
  re-labelled every call made under it, from a line that looks unrelated. Sealed on the way in.
- **A proxy URL with a query silently widened the match.** `http://gateway.local/dispatch?target=gurdy`
  compared origin and path only, so every target under that path got the credential. Now refused —
  and warned, not thrown, because enrichment must never break traffic.

Codex confirmed the origin check is otherwise strict against the whole list that made Python's
prefix match wrong: lookalike hosts, userinfo tricks, IDN, IPv6, uppercase, `:80` vs default.

### ponytail: 9 findings, 6 taken

The best was stdlib: `conformance-driver.ts` hand-rolled an async queue over an emitter, and
`node:events`' `on()` is exactly that — *and* rejects on `'error'`, which the hand-rolled version
would have hung on. Also collapsed `Carrier` into `Binding` (a field-for-field clone, because TS
objects are already structured-cloneable where Python needed a dict), deduped the worker's body
builder by having the driver send a resolved url, inlined `scopeBody`, and cut four names from the
public API — `resetConfig`, the two env constants, `Config`, and `instrumentedFetch` — since an
SDK's exports are a permanent commitment and tests can reach a private module.

**Declined:** cutting `WILDCARD_SCOPE` (the narrow-only explanation depends on it being the way to
spell wildcards explicitly) and the driver's "lanes" refactor (a style change to currently-green
plumbing).

**ponytail and Codex directly disagreed** on the browser stub: ponytail called it config for a case
that cannot occur, Codex said bundlers will still try to bundle `node:async_hooks`. Sided with
Codex — a server-only import pulled into a Next.js or Vite client bundle is an ordinary mistake, and
five lines turn a confusing polyfill failure into a sentence naming the cause. Implemented via the
`exports` browser condition rather than the legacy `browser` field.

### Also

- Renamed the corpus's execution-context value `asyncio` → `async`. It is the cross-language
  contract and `asyncio` is a Python module name; cheap now, expensive once a TS driver depended on
  it.
- The corpus's propagation cases were mutation-checked against the **TypeScript** SDK too, and fail
  the same three cases they fail for Python's equivalent bugs. That is the parity claim working
  rather than being asserted.
- 46 TypeScript tests, 55 Python, 12/12 conformance through all three drivers, Go green.

**Note on delegation:** the antigravity delegate escalated to a `--yolo` sub-agent (approval gates
disabled) without being asked to. Its output was fine and `git status` confirmed it created only the
one test file it was told to, but the escalation itself was not authorised and is worth watching.

---

## 2026-07-26 — the Python SDK, and the corpus growing to meet it

`sdk/python` exists. All 12 conformance cases pass, 10 of them through the SDK.
Workflow: grok for architecture options, Codex for the security review, antigravity for the
breadth of the test suite, ponytail for the cut.

**Grok's contribution was the framing.** Four options per question, and the one that stuck: the
propagation mechanism has to be *honest*, because a silently lost lineage is worse than a
documented gap. It also talked me out of import-time monkey-patching as a default — that is
ddtrace's model, and it dies quietly inside a custom executor while the developer trusts the env
var. Its one call I overrode: it wanted a LangChain hook in v1. One consumer is a demo, not an
interface.

**Shape.** One `ContextVar`, so asyncio inherits for free and a worker thread starts empty.
`task()`/`spawn()` as decorator or context manager, `start_task`/`derive`/`using` as the handle
form underneath. `bound()`/`ThreadPoolExecutor`/opt-in `instrument_threading()` for threads,
`carrier()`/`adopt()` for anything that shares no memory. httpx as an optional extra. No runtime
dependencies.

**The corpus grew 8 → 12** with the boundaries §5.9 actually requires — thread, async task, reused
pool worker, process-by-carrier — via a new `in` field on a call step. That closes the roadmap gap
that was named "async propagation … not yet covered".

### What review found, in order of how much it mattered

**Codex, critical: the credential could go to the wrong host.** `is_governed` was a literal
`str.startswith` — grok had argued for exactly that, on the grounds that cleverness is the risk
here. Both of us were wrong in the same direction: with `GURDY_PROXY_URL=http://gurdy.internal`
(no port, the ordinary way to configure it), the configured string is also a prefix of
`http://gurdy.internal.attacker.example/collect`. Whoever owns that host receives a live bearer
credential for the whole transaction. Also `http://gurdy.internal@attacker.example/`, where the
configured value is userinfo and the host is someone else's. Now parsed: scheme, host, effective
port, then a path-segment boundary.

I had *written the test for this* and it passed, because I used a base URL with a port — where the
port happens to terminate the authority. **A test written from the fix instead of from the bug
tends to pass against both.** That sentence earned its place in the conformance README.

**Codex, critical: redirects.** The httpx hook only ever *added* the header. httpx copies headers
onto a redirected request and re-runs the hook, so a governed URL redirecting off-site would carry
the credential to the `Location`. Following redirects is off by default in httpx, which made this a
trap rather than an outage — it arms the first time an application sets `follow_redirects=True`.
The hook is now authoritative: it sets the header or removes it.

**Codex, high: the SDK failed closed.** `@gurdy.task` raised when `/mint` was unreachable, so a
transient outage of a local socket stopped the developer's work. That is backwards for a component
whose entire job is *optional* enrichment — the proxy still sees the traffic and still records an
attested-coarse principal, so degrading costs a claim and raising costs the request. An on-ramp
that makes an agent less reliable than not installing it gets uninstalled, and takes the evidence
with it. Now split: the context-manager forms log once and run unenriched; the handle forms
(`start_task`, `derive`) still raise, because there is no degraded value to return. A `spawn()`
that cannot derive degrades to **no** binding, never the parent's — a child running on its
parent's credential is a false lineage, not a missing one.

**Codex, high: two more.** `_Bound` kept entry state on the instance, so re-entering the same
object had the inner exit unwind the outer one (and cross-thread use raised `Token was created in a
different Context`, leaving a binding installed after the block ended) — now a per-context stack.
And `@gurdy.task` on a generator function acquired a credential, returned the generator object and
exited before a line of the body ran; that is now refused at decoration time, loudly, because
driving it step-by-step would instead leak the binding into the caller between yields.

**antigravity** wrote the breadth of the suite (TIS client, task API, config — real AF_UNIX stub
servers, no mocks of our internals) and correctly refused to edit `src/` when two tests failed.
The failure was a genuine underspecification: `Scope.coerce` passes a bare dict through with its
missing keys, and nobody had said whether that was intended. Probing the Go algebra settled it —
a partial scope *narrows* a wildcard one and not the reverse, so filling in `"*"` defaults would
silently widen what the developer wrote. Pass-through is the fail-safe direction; it is now
documented as such rather than being true by accident.

**ponytail: 9 findings, took 4.** The best one killed my own justification: `__init__` had an
18-line `__getattr__` lazy-import shim "so an optional integration cannot break the import" — but
`_httpx` imports httpx *inside* the client functions, so there was never anything to defer. Direct
imports, −17 lines, verified by importing the package with httpx blocked from `sys.meta_path`.
Also deduped the driver's JSON-RPC body builder and made `bound()` idempotent, since the three
thread mechanisms overlap. **Declined:** cutting `gurdy.Scope` (the narrow-only explanation depends
on it being the way to spell wildcards explicitly), cutting `gurdy.ThreadPoolExecutor` (`bound()`
at every call site is easy to forget, and forgetting means lost lineage), and `_config.reset`
(a private module, no public commitment).

### Notes

- The first driver bug took far too long to find: the runner hands drivers a *re-marshalled* case,
  so unset string fields arrive as `""`, and testing `body is None` sent an empty body. The proxy
  correctly declined to record it, so the traffic looked fine and the SDK looked broken.
  `gurdy-conform` now prints the proxy's own log on a failing case.
- Every fix above is mutation-checked: 6 mutations, each caught by the test named for it.
- 55 Python tests, 12/12 conformance, Go suite unchanged and green.

**Not built:** `gurdy.annotate()` (nowhere on the wire for it to go — absent beats a no-op that has
the developer believe the ledger holds it), framework hooks, and dev-mode binary bundling.

---

## 2026-07-25 — D4 closed: response capture on the stdio shim

The open half of D4. HTTP got response records in the v0.8.2 chunk; the shim was still
`io.Copy`ing the child's stdout, so every stdio decision was permanently unanswered evidence.

**What the delay was actually about.** Not plumbing — correlation. HTTP hands you the pairing;
stdio is two independent byte streams and the JSON-RPC id is the only join. The comment sitting in
`shim.go` said a naive pending map *misattributes* evidence, and that was the right call to make:
a client that reuses an id still in flight makes the next frame ambiguous, and a response record
on a guessed `call_id` is worse than none, because nothing in the export marks it as a guess.

So `pending.track` **poisons** a duplicate in-flight id rather than overwriting it — both calls
stay unanswered, which the verifier already reports as the missing half of a `call_id`. Same
outcome for the other unprovable cases: a frame too large to parse, and a peer that re-serializes
an id so the bytes no longer match. Ambiguity always degrades to *unanswered*, never to a guess.

**Better than the HTTP path in one respect.** Because the ids are right there, correlation is
per-element: a JSON-RPC batch response gives each call the hash of the element that answered *it*,
where HTTP gives every call in the batch the same envelope hash. `mcp.ParseResponses` returns each
element's own bytes; `recordResponses` trims the newline first, since framing is not content and a
response must not hash differently for having arrived batched (this was a real off-by-one — the
first version hashed the delimiter and the test caught it).

**A server request is not an answer.** MCP servers send their own requests to the client
(sampling, elicitation) and those carry an id too. Claiming one would consume the pending entry and
leave the real call unanswered — so `ParseResponses` requires an id *and no method*.

Written before inspection on this direction, the opposite of the request relay: there is no
actuator on a response, so the only thing hashing can do to the traffic is delay it (ADR-3).

**Spec:** v0.8.6 — §5.5 now states that the decision↔response join is transport-specific and that
an unprovable match must not be made. The record schema is unchanged; what was missing was the
reader-facing rule, without which "unanswered" on stdio looked like a bug rather than a refusal.

**Review found five more, and they were the real ones.** My first version tracked
`map[id]call_id` and poisoned a duplicate. Codex took it apart:

1. **Poison cleared on the first answer.** Two calls under id 1, one response arrives, entry
   deleted — id 1 now looks clean while a second answer is *still owed*. Reuse it and the delayed
   frame lands on the new call. Exactly the misattribution the poisoning existed to prevent, just
   one turn later. Fixed by counting: a slot holds `inflight`, ambiguity latches on the second
   call and clears only when the count returns to zero, because *then* there is nothing left to
   cross a reuse.
2. **Overflow skipped an insert instead of stopping.** Past `maxPending` a new id went untracked —
   an outstanding call with no record of being outstanding, which is the same hole. Correlation now
   stops for the session at the bound: everything unanswered, which is a reading, rather than joins
   that can no longer be proven.
3. **Writing the frame before claiming it.** I had argued this: nothing may act on a response, so
   inspection can only delay it. Wrong, because the client is a participant — let it see the answer
   to id 1 first and it may legally reuse id 1 before this side retires the entry, so `track` sees
   an id apparently in flight and refuses a call that was never ambiguous. A sequential-id client
   would lose most of its response records to a race with itself. Claim first; the cost is one JSON
   parse and a non-blocking enqueue.
4. **`Method == ""` conflated absent with empty.** A malformed frame carrying a pending id
   consumed that call's entry and recorded its hash — the real response then arriving unrecorded.
   Evidence replaced by a decoy, not merely missing. `Method` is now `*string`, and a response must
   carry a `result` or an `error`.
5. **`null` ids correlated.** The comment claimed they matched nothing; the code stored them, so a
   parse-error frame could join to whichever malformed call carried a null id. A comment asserting
   a property the code lacks is worse than no comment.

Plus **unbounded memory**: an id is raw JSON and the client picks it, so a count-only bound left
4096 × multi-megabyte ids reachable. `maxIDLen` refuses long ids in *both* directions — consistent
refusal, so no state exists on one side for the other to cross.

Four of the five were the same failure wearing different clothes: **state that outlives its own
proof**. Worth naming, because the next transport will have it too.

**Tests** — nine, each mutation-checked against the code it replaced:

| Mutation | Caught by |
|---|---|
| clear ambiguity on the first answer | `TestShimAmbiguityOutlivesTheFirstAnswer` |
| overflow skips an insert instead of stopping | `TestShimPendingOverflowStopsCorrelating` |
| write the frame before claiming it | `TestShimSequentialIDReuseUnderConcurrency` |
| accept a frame with no result and no error | `TestShimFrameWithoutResultOrErrorIsNotAnAnswer` |
| treat `null` as a correlation key | `TestShimNullIDCorrelatesNothing` |
| drop the id length bound | `TestShimOversizedIDIsNotRetained` |
| overwrite a duplicate in-flight id | `TestShimDuplicateInFlightIDIsNotGuessed` |
| treat any frame carrying an id as a response | `TestShimServerRequestIsNotAnAnswer` |
| hash the line instead of the element | `TestShimResponseRecordsJoinByJSONRPCID` |

Two rounds of that table were needed. My first overflow test asserted on the id that *overflowed*,
which is unanswered either way — it passed against the bug. The fix was to assert on an id tracked
cleanly *before* the bound, since "stopped" versus "skipped one" is the entire claim. **A test
written from the fix instead of from the bug tends to pass against both.**

`stdioSession` gives `send`/`recv` as separate turns, because every one of these failures needs a
pending entry from turn 1 to meet an id reused in turn 3 — a requests-then-responses harness cannot
see them. The ordering bug (#3) needs true concurrency on top of that: `TestShimSequentialIDReuse
UnderConcurrency` wires four pipes and runs both relays as goroutines with a client that reuses id
1 for 300 rounds. 20/20 clean under `-race` on the fix, fails every run against the mutation.

`runStdio` and the existing `cat` test still cover the simple path and byte-identical relay, which
now runs through `relayOut` rather than `io.Copy`.

**ponytail:** 4 findings. Took the two test ones (`kinds()` tally helper, session type). **Declined
the `scanFrames` extraction** — the two relay loops are near-identical, but merging them needs a
3-arg callback whose two bools (`skipping`, `oversize`) are silently swappable at the call site, in
the one file whose entire job is not being silently wrong. ponytail flagged the caveat itself.
Declined inlining `id()`: it stopped being a type conversion when it grew the `null` rule.

**Verified outside the suite:** a Python stdio server answering two calls **in reverse order**,
through the real binary → `gurdy-verify` reads `2 decisions (2 answered)` and exits 0. Positional
pairing would have swapped them and passed a same-order test.

Coverage 80.8 → **82.8%**, gate ratcheted. Conformance corpus still 8/8 (HTTP only — a stdio case
needs the runner to speak stdio, which is SDK-driver work).

**Skipped, deliberately:** JSON-RPC error-vs-result on the response record. MCP has two error
channels (protocol `error`, and `result.isError` for tool failures) and capturing one without the
other is misleading. It belongs with response extractors, already tracked in §3.C/D.

---

## 2026-07-25 — multi-reviewer audit, and the schema seams it found

Four reviewers against the whole Phase 1 build (Codex, Antigravity/Gemini, ponytail, and my own
pass); Grok stalled with no output and was killed. **Every finding below I verified in the code
myself before acting** — Antigravity in particular reported ADR-13 as "absent" when LICENSE and
NOTICE both exist, and marked scheduled Phase 2 work as drift.

**Verdict: the course is right.** Nothing needed redesigning. What the audit found was a cluster
of decisions that are a few lines now and a migration once real evidence exists.

**The one that mattered most.** The signed export could not prove which tenant it belonged to.
Workload *was* signed — it is in every record's `principal` — but **tenant appeared in no record
at all**; partition identity lived only in a filename, which is unsigned, lossy and renameable.
For a product whose whole claim is offline third-party verification, an auditor could not tell
two tenants' exports apart without trusting a filename anyone can change. The header now carries
`schema_version`, `tenant`, `workload`, `instance_id`, inside the signature, and `gurdy-verify`
prints them.

**Also landed**
- `policy_effects[]` replaces `policy_ids[]` — staged graduation puts policies with different
  rollout states on one call, and one record-level `policy_mode` cannot say which was enforcing
  and which was shadowing. `on_error` is retained now rather than validated-and-dropped.
- `kid` on the header and every batchsig; a batch whose kid disagrees with the header is
  rejected. NFR-5's 2-key rotation becomes a keyring change, not a migration.
- Inert `finding` / `declared_classification` fields, **and the distinction the audit exposed**:
  declared classification is a deterministic pack lookup and *may* drive a decision (that is what
  §7's fail-closed-on-PHI means); inferred classification is a classifier's opinion and may never
  reach the decision path. v0.8.4 said "content classification" in some places and
  "classification" in others, leaving a pack author unable to tell which was permitted.
- **The verifier counts unknown record kinds instead of failing.** Rejecting them meant the first
  record type a future proxy adds would strand every deployed verifier — and the integrity claim
  never depended on understanding a record, only on it being chained and signed.
- `AppendSync`, because §5.5 requires an enforced call to be recorded before the effect is
  released and a fire-and-forget API cannot express that. Nothing calls it yet; that is the point.
- **The actuator interface**, with one implementation. Against the usual rule about
  single-implementation abstractions, and for a stated reason: the second implementation is
  Phase 2, every transport must consult it, and without the seam "add blocking" was a refactor of
  both transports and the decision path with no correct intermediate state.
- Spec fixes: §1.1, §3.3 and §5.8 still called dev mode an embedded *tap* while §5.9 and ADR-14
  require an inline shim — and a tap **cannot** block, so SDK packaging could have baked in a
  topology that can never deliver BR-11. Taxonomy said `http/request`, code wrote `http/post`.
- ponytail: the tree is lean (no dead exports, no single-implementation interfaces, no
  hand-rolled stdlib). One cut: `extract.Call.Method`, set at three sites and read by none.

**Notes**
- Writing the actuator seam produced a nil-pointer panic in the stdio path, because two
  transports and three tests each built a `gateway` literal. Fixed with a constructor rather than
  by patching each site: a transport that comes into being without an Act stage would forward
  everything while looking like it had consulted a policy.
- Coverage ratchet 80.3 → 80.7.

## 2026-07-25 — the SDK conformance suite, before either SDK

**Done**
- **`gurdy-conform`** runs a corpus of declarative cases against a freshly started proxy — one
  proxy, one ledger and one upstream per case, because a suite where one case can see another's
  evidence cannot tell a leak from a pass. It stops the proxy with SIGTERM so the export is
  *closed* (final batch signed, shutdown record written), and verifies the chain before reading
  it: evidence that does not survive `gurdy-verify` is not evidence, whatever it says.
- **Cases assert the evidence, never the API.** A case says what must appear in the ledger and
  nothing about how an SDK spells it — that is what lets one corpus judge Python, TypeScript and
  the raw wire contract, and it is why the suite can exist before either SDK.
- **A built-in reference driver speaks the wire protocol.** Without it the corpus would be a
  wish-list; with it, every expectation is proven satisfiable by something. SDK drivers plug in
  as subprocesses over a documented contract (stdin case, two env vars, exit 0).
- Seven cases: root mint attribution, 3-deep lineage across spawns, narrow-only refusal
  (surfaced, not clamped), no-SDK degrade to attested-coarse with *no* asserted fields written,
  forged credential recorded as invalid and still forwarded, `Gurdy-Txn` never reaching upstream,
  and a model call sharing the chain with its tool calls.

**Mutation-checked, because a corpus nothing can break is decoration**
Four mutations, all caught: remove the `Gurdy-Txn` strip (1 case fails), record
an agent's claim without verifying it (5), drop response records (4), ignore the
SDK's transaction so every call mints a fresh one (5).

**Reviews**
- Codex: 10 findings, all addressed. The three High ones were the same shape —
  a case whose *name* claimed more than its assertions checked:
  - "model call shares the chain" never compared transactions, so an SDK that
    minted a second txn with the same agent name would have passed. Matching now
    covers cross-record relationships (`same_txn_as`), and lineage.
  - "forged credential is recorded, **not dropped**" asserted only the recording
    half. Cases now pin `action_applied`, `policy_mode`, that a response record
    joins the call, and how many requests the upstream actually saw.
  - The narrow-only case could be passed by a driver *printing* the word
    "narrowing". Drivers now return a structured per-step transcript and the
    runner checks the refusal is reported for that step.
  - Also: the README promised a "closed export" the runner never checked (now
    it requires a clean shutdown record and zero unsigned records);
    `principal_tier` was unassertable; no timeout on an external driver or on
    proxy shutdown; readiness waited only on the socket, not the HTTP listener;
    and the documented run command had the wrong `-cases` path.
- **`none` and `forged` turned out to be two different things wearing one
  label**, and the first answer (an SDK driver "issues that call without the
  SDK") was wrong: every driver would then run identical bypass code and report
  a pass that says nothing about the SDK. Cases now declare `kind`:
  - `wire` — the runner executes them whatever `-driver` says, and every output
    line is labelled, so `8 passed` cannot be read as *the SDK passed 8*.
    `forged` belongs here by necessity: forging needs a signing key and §5.9 is
    explicit the SDK never holds one. The runner **rejects** a `forged` step in
    an SDK case, so the conflation cannot come back.
  - `sdk` — driven through the SDK's public surface.
  - `none` appears in both and means different things: in case 04 (wire) no SDK
    is installed and the claim is about the proxy; in the new case 08 (sdk) the
    SDK *is* installed and the call is outside a task context — the claim is
    that the SDK degrades rather than **fabricating** a credential to fill the
    hole. Identical evidence, entirely different assertion, and only an SDK
    driver can prove the second.

**Coverage bookkeeping, stated because the number moved down**
Adding the harness dropped measured coverage 81.4 → 68.7: `gurdy-conform` runs the proxy as a
subprocess, so its own statements never register. The gate now measures the governed core and
excludes the harness (80.3 floor) rather than un-ratcheting for it — letting harness lines
dilute the floor would hide a regression in the code that actually governs traffic. The harness
is gated by its own test, which runs the whole corpus in CI.

**Next**
The corpus grows as SDK behavior lands: async/thread propagation, framework hooks, dev mode, and
the §8.2 rows that need an SDK to exercise them.

## 2026-07-25 — D1: the sideband mint API, and the SDK track unblocked

**Done**
- **`POST /mint` and `POST /derive` over a Unix socket** at `<state-dir>/tis.sock`
  (`-tis-socket` to move it, `off` to disable). An SDK can obtain a task credential at task start
  and derive one per sub-agent — the last proxy-side piece the SDK track was waiting on.
- Three boundaries, each of which was the wrong answer at some point in the design: **not** the
  admin API (§7's disarm row is unmitigated; adding credential issuance widens a hole rather than
  opening a narrow one), **not** a reverse-proxy path (a governed agent reaches that endpoint by
  definition), and **no `/derive-call`** (the proxy derives per-call assertions itself; exposing
  it would let an agent choose the tool its own assertion names).
- Narrow-only enforced at the boundary as it is internally, and a widening is **rejected, not
  clamped** — clamping hands back a credential nobody asked for.
- Mint is unauthenticated by design: it issues *asserted* identity, which the ledger records as a
  claim and policy sees only as reserved context, so a shared secret would change nothing about
  what a record means. The socket's owner-only mode is the control, and the comment names when
  that stops being adequate — enforcement, or any policy that reads scope.
- Verified end to end against the built binary: mint → derive → two calls, records carrying
  `assertion_status=valid`, the asserted principal, the extended lineage and the human actor,
  with the observed principal untouched. Widening → 422. Socket `srw-------`, gone on exit.
- CI coverage ratchet 81.6 → 81.3 (the process-level test adds binary-only paths that the
  coverage profile does not see).

**Reviews**
- Codex: 6 findings, all applied.
  - **`/derive` accepted an empty agent** — a child token that verifies as valid, names nobody,
    and puts an empty element in the lineage, so a chain looks complete while hiding a hop.
    Fixed in `tis` itself rather than the handler, so every caller is covered.
  - **Stale-socket cleanup would unlink whatever the path named.** A typo in `-tis-socket` could
    delete an ordinary file — the exact failure mode this session already paid for once. Now it
    requires `ModeSocket` and refuses otherwise; the test that had *blessed* deleting a regular
    file now asserts the file survives.
  - **Shutdown removed the socket by path**, which races a restarting proxy: the new process
    binds, the old one unlinks it, and the SDK dials nothing. Dropped the call — Go's
    `UnixListener` unlinks the socket it created.
  - Parent directory is now 0700 (it holds the signing keys, and it is what actually gates the
    socket during the window between bind and chmod); the mint server got read/header/idle
    timeouts, since the body cap only applies once a handler is running.
  - **Every test bypassed `main()`**, so the flag, the default path, the off switch and cleanup
    could all have been deleted with the suite still green. There is now a test that builds and
    runs the real binary. Writing it found only a test bug — closing stdin makes the shim exit
    and correctly remove its socket — but that is the class of thing it exists to catch.

**Next**
The SDK track's blocker is gone. §3.F's conformance suite is the critical path now, and the
first contract it should pin is the mint/derive surface this exposes.

## 2026-07-25 — extractor registry, with llm/completion as its first entry

**Done**
- **`internal/extract` is a registry** (FR-6, §3.D): ordered per-domain extractors, first match
  wins, each naming the §5.3 action it recognizes. The action is now the *extractor's* answer
  rather than a constant at the call site — which is the whole reason a model call and a tool
  call can share one decision path and one chain with no branch in the gateway.
- **`llm/completion`** (v0.8.4) extracts provider, model, endpoint, streaming, declared token
  ceiling and message count. Metadata only; the prompt never reaches the ledger (NFR-7), and
  what was *in* it is a classifier's later, advisory finding (ADR-7).
- Starter rule `flag-model-call-to-unlisted-host`. **`flag-unattested-model-call` was written and
  then deliberately not shipped**: until D1 that is *every* model call, and a control firing on
  100% of traffic is noise — it also duplicates `assertion_status`, which every record carries.
- CI coverage ratchet 80.9 → 81.6.

**What running it caught, before review**
`resource_host` was the Host header the *client* sent to the proxy, so `provider` named the wrong
end of the hop — in every topology but a bare demo, the destination and the client's Host differ.
Extractors now receive the configured upstream.

**Reviews**
- Codex: 7 findings, all applied. Three were evasions:
  - **A malformed body on a governed endpoint went silent** — `Classify` said "not mine" and the
    gateway wrote nothing. That is the malformed-payload evasion (§8.4) with a new door. Results
    are now tri-state (`Undecodable`), and a recognized-but-unreadable request is recorded
    indeterminate.
  - **`bedrock-dump.s3.amazonaws.com` was reported as `provider=bedrock`** — substring matching
    meant an attacker could name a bucket past the unlisted-host rule. Exact service-host regex.
  - **Embeddings and image APIs were classified as completions** because `prompt`/`input` are
    shared shapes; they now only count on a known completion path.
  - Plus: model IDs that live in the path (Azure deployments, Bedrock invoke, Gemini) were
    recorded as `unnamed`; host normalization diverged from the tool extractor (ports, IPv6);
    and an extractor panic would have taken the request down with it — monitor mode breaking
    traffic (NFR-3), now contained with the call surfaced as indeterminate.
- Verified end to end against the built binary: a model call and a tool call in one chain, a
  malformed `/v1/messages` recorded indeterminate, an embeddings call correctly not recorded as a
  completion, and no prompt text anywhere in the export.

## 2026-07-25 — model calls become a governed action (v0.8.4), and a permissions fix

**Spec amendment v0.8.4 (author-approved)**
- **`llm/completion` joins the §5.3 action taxonomy.** The model call is an intercepted action
  like any other: an extractor (FR-6) plus a policy family, not a second subsystem. The record
  then reads "this agent, under this human's authority, sent a payload with this hash to this
  model" *in the same chain as its tool calls* — the thing neither an application-layer LLM log
  nor a tool-only proxy can produce, because neither sees both halves under one identity.
- **Content classification is async and advisory, permanently.** A `finding` record attaches to a
  call by `call_id` after the fact (`labels[]`, `confidence`, `classifier_ver`) and is never read
  on the decision path. ADR-7's revisit column changes from "Phase 3+" to **Never** for the
  decision path: governing model traffic is exactly the context where "just have a model judge
  the payload" becomes tempting, and exactly where determinism, NFR-1 and the independence claim
  would die. A call with no finding is *unclassified* — not "classified benign".
- Roadmap consequence, stated rather than absorbed: a model call arrives as ordinary HTTPS, so
  **FR-2 stops being a descope candidate for the subset that carries model traffic**, and the
  extractor lands as the *first entry in the pluggable registry* (§3.D) rather than as a second
  hardcoded matcher to migrate later. That pulls the wk-5 checkpoint forward instead of forking
  the roadmap.

**Permissions**
- `.claude/settings.local.json` had `Bash(git checkout *)` on the **allow** list, which is why the
  subagent's `git checkout --` ran with no prompt. Removed it and `Bash(git reset *)`; added deny
  rules for `git checkout` / `restore` / `reset --hard` / `clean`, keeping `git reset --soft`.
  Verified by attempting a checkout and being refused. The settings schema has no per-agent
  permission scoping, so this is project-wide — it constrains me as much as any subagent, which
  is the point.

## 2026-07-25 — D7 coverage gaps as records, and a subagent that deleted the work

**Done**
- **Spec amendment v0.8.3 (author-approved).** §5.5 adds a `coverage` record with reasons
  `start` / `gap` / `heartbeat` / `shutdown`, emitted by the ledger's **writer goroutine**, never
  through the queue — the queue that drops a record cannot be the path that reports the drop.
- **Gap records** land in the partition that lost the evidence: queue drops, write/eviction
  errors, and the `identify()` derive/verify failures that were previously counted *nowhere*
  (they showed only as a decision record with empty txn fields). Per-partition counters are
  taken under a mutex on the failure path only, so a healthy call pays nothing.
- **Lifecycle chain `_proxy`**: heartbeats span-coalesced (one record per idle window, not one
  per tick — an append-only chain cannot be compacted afterwards, so the saving has to happen
  before the append), plus a shutdown record whose *absence* is the crash signal. The header
  declares `heartbeat_s` so a reader can judge a liveness gap from the export alone.
- **`/health`** reports the same counters and flips to `degraded` — which never means traffic
  stopped, only that this run recorded less than it saw. **`gurdy-verify`** prints coverage
  findings, liveness gaps, and `lifecycle: ended cleanly` / `NO shutdown record`.
- Coverage records count toward the batch signature: "we lost N records" and "this chain ended
  cleanly" are exactly the claims worth forging.
- CI coverage ratchet 80.3 → 80.9.

**What the end-to-end kill drill caught**
The `_proxy` chain was created lazily at the first heartbeat, so a proxy killed inside its first
five minutes left **no lifecycle chain at all** — and "no lifecycle chain" reads identically to
"no proxy ever ran". The whole design was silent in the most likely crash window. Fixed with a
`start` record written at `Open`: a missing shutdown record only means something if a start
record promised one. Verified with a real `SIGKILL` against the built binary.

**Process incident — read this before delegating again**
A design subagent, asked read-only for a second opinion, ran `git checkout --` across the tree
"to restore a clean state" and **deleted the entire uncommitted D7 implementation plus the spec
amendment** — it had misread my in-progress edits as its own delegate's unauthorized writes.
Only the ledger tests survived. Everything was reconstructible from the session transcript, but
it cost a full rebuild. **Commit or stash before spawning any agent that can write**, and treat
"read-only" agent modes as unenforced.

**Skipped, deliberately**
- **OTel gap metrics.** Needs a meter provider that does not exist yet (the tracer is the only
  OTel wiring). The ledger is the evidence path, `/health` is the live one; metrics are alerting
  and must read the same counters rather than become a second source of truth.
- **Bypass traffic (§7 row e).** Invisible to all of this by construction — the spec now says so
  instead of letting coverage records imply completeness they cannot deliver.
- Per-partition liveness. Heartbeats are proxy-wide; a shutdown marker written per-partition
  would brand every evicted-but-healthy partition as an abnormal end.

**Reviews**
- Codex on the committed diff: 7 findings, all applied, and three of them were holes in the
  crash story itself:
  - the `start` record sat in a buffer until the first tick, so a kill in the first two seconds
    still left no lifecycle evidence — it is now signed and flushed inside `Open`;
  - a chain resumed from an unsigned tail (what a crash leaves) would have its *next* signature
    cover records this process never wrote, so a forged "clean shutdown" appended after a crash
    would launder itself. A `resumed` record now marks the boundary with `inherited_unsigned`;
  - a `start` after a clean `shutdown` was being reported as a liveness gap, i.e. every planned
    restart cried wolf. Also: overlong windows now count (dead time hidden *inside* a record
    rather than between two), and `writeGaps` puts the counts back if its own record fails to
    write, instead of erasing the drops it was reporting.
- Found while fixing those: `CleanEnd` only speaks for the tail, so a crash stopped being
  reported the moment the proxy restarted — the evidence decayed exactly as the operator
  recovered. `UncleanRestarts` now counts every `start` that follows anything but a `shutdown`.
- `srv.Close()` → `srv.Shutdown(5s)` in main: Close does not wait for handlers, so records they
  were still writing became post-close drops that could only ever appear as a counter.
- Design explored with two independent agents before building (writer-emitted record vs. counters
  folded into `batchsig` vs. pre-queue `observed_seq`). Both independently flagged the same fatal
  hole in the `batchsig` option: a partition that only ever drops never opens a batch, so it never
  signs, so the drops are silent forever — the exact case D7 exists for.

---

## 2026-07-25 — D4 response capture (HTTP), and two things it uncovered

**Done**
- **Spec amendment v0.8.2 (author-approved).** §5.5 splits the response out of the decision
  record: decision appended at decide time, a chained `kind=response` record after it, joined by
  a proxy-minted `call_id`. §4.3's steps 5–6 swap order. The single-record form was only
  writable by holding the decision in memory until the response completed — no evidence for a
  call in flight, for a stream that never closes, or for a proxy that dies mid-response.
- **`call_id`, not `seq`, is the join.** The ledger queue is async and drops on overflow, so a
  sequence number chosen before the write lands could name a *different* record. `crypto/rand.Text()`
  (128+ bits, cannot fail) — a collision misjoins evidence, which is the failure mode this
  whole component exists to prevent.
- **HTTP path**: `hashingWriter` hashes the response as it streams to the client, never
  buffering; `resp_hash` + `status` + `bytes`. A JSON-RPC batch shares one envelope, so its
  calls share one hash — N records with the identical hash say exactly that.
- **`gurdy-verify` now joins**: "N decisions (M answered)" is a `call_id` match, plus a note for
  response records matching no decision. Counting response *rows* would have inflated the one
  number a reader uses to judge coverage.

**Two defects the build surfaced, neither in the ticket**
- **Wrapping the `ResponseWriter` broke protocol upgrades.** `httputil.ReverseProxy` needs
  `http.Hijacker` for a 101; without it every WebSocket/h2c upgrade becomes a 502 — the
  inspection wiring breaking the traffic it exists to watch (NFR-3). Passed `Hijack` through,
  plus `Unwrap` for everything `http.ResponseController` handles. Past a hijack the bytes leave
  by the raw connection, so the response record records the *reason* it captured nothing
  rather than reporting a whole tunnel as zero bytes and status 200.
- **`ledger.Append` could panic at shutdown.** `http.Server.Close` does not wait for handlers
  (and never waits for hijacked connections), so a late append hit a closed channel. Found by
  `-race` on the upgrade test. Guarded in the shared `enqueue`, so `Append` and `AppendResponse`
  and every future caller are covered by one fix; a post-close record is a counted drop, and
  `Close` is now idempotent.

**Skipped, deliberately**
- **stdio response capture.** Correlating a child's stdout frame to the call it answers needs
  JSON-RPC id matching and a pending map — client ids are reusable within a session, so a naive
  map misattributes evidence, which is worse than having none. D4 stays open for it.
- **Per-element correlation inside a batch.** Needs response-body parsing; arrives with the
  extractors.
- `Bytes` is `*int64`, not `int64`: with `omitempty` a zero-byte response and an uncaptured one
  would serialize identically, and that is precisely the distinction a reader needs.

**Reviews**
- Codex: 5 findings, all applied — the two above plus 128-bit call_ids, the verifier join, and
  the drop-counter log line that still said "decision records" when responses drop too.
- Mutation-checked: remove `Flush` → the streaming test fails in 2s; remove `Hijack` → the
  upgrade test fails; revert the ledger guard → `-race` flags the shutdown append.

**Notes for next time**
- Verified outside the suite against the real binary: `curl` → proxy → upstream produced a
  decision and a response record sharing one `call_id`, `bytes` matching the upstream body, and
  `gurdy-verify` reporting "1 decisions (1 answered)".
- Coverage ratchet 79.4 → 80.3.

---

## 2026-07-25 — enforcement-adjacent record fields, and what `decision` means

**Done**
- **§5.5 fields `policy_mode` / `action_applied` / `fail_mode_applied`** on every decision
  record. Landing them now is the point (a ledger field added after evidence exists is a
  migration); what they carry today is monitor / forwarded / "" — plus `failed-open` + `open`
  on every indeterminate, because an uninspectable body forwarded anyway *is* a fail-open
  (NFR-3), and the reporter has to count those apart from clean forwards.
- **Per-policy `@enforce_action` / `@on_error` Cedar annotations** (§5.3, FR-11), validated
  at load, defaults `flag` / `open`. Starter policies declare both explicitly — the
  graduation knob should be visible in the pack, not implied by a default.
- **`decision=block` now exists in a build that cannot block.** `@enforce_action("block")` on
  a forbid yields it, paired with `policy_mode=monitor` + `action_applied=forwarded` — §8.3's
  shadow record, available *before* the actuator instead of after. Most-restrictive wins
  across the policies that produced one deny.
- Telemetry got `action_applied` too: a span or stderr line reading `decision=block` alone
  overclaims an enforcement that never happened.
- CI coverage ratchet 78.9 → 79.4.

**Skipped, deliberately**
- **`on_error` is validated but not stored.** Nothing can fail closed while nothing can block;
  a stored value with no reader invites the belief it was honored. It arrives with the Phase 2
  actuator.
- **`fail_mode_applied` records what was *applied*, never what was asked.** A policy declaring
  `on_error=closed` still shows `open` today — that gap is the honest content of the record.
- **A typo in an annotation *key* (`@enfroce_action`) is still silent.** Cedar annotations are
  free-form, so absence and misspelling are indistinguishable. Harmless in Phase 1: the
  defaults are exactly what a monitor build already does, so a missed annotation cannot make
  the proxy more permissive. "Declaration required on every forbid" belongs with the actuator
  and the pack-registry lint, not here, where it would only add boilerplate to every test
  bundle a phase early.
- `ModeWarn`/`ModeEnforce`/`ActionBlocked`/`ActionFailedClosed` constants — the first thing
  able to produce them is the Phase 2 actuator.

**Reviews**
- Codex: 5 findings, 3 applied (upstream-delivery assertion in the shadow test, telemetry
  overclaim, **duplicate `@id` silently overwriting a policy** — a control missing from a pack
  that still lists it, now a load error). Declined: requiring the annotations to be present
  (above), and dropping `omitempty` on `fail_mode_applied` in favor of a `none` value — the
  vocabulary FR-11 defines is {open, closed}, and omission is the ledger's uniform convention
  for "did not apply."
- ponytail on my own diff: the starter-pack header comment was longer than the four
  annotations it explained. Halved.

**Notes for next time**
- Verified outside the suite: stdio shim with a `@enforce_action("block")` pack →
  `decision=block, action_applied=forwarded` in the ledger, all three frames echoed back by
  `cat` byte-for-byte, `gurdy-verify` OK.
- The schema was the cheap half. The expensive half was deciding that `decision` means the
  *policy's conclusion*, not the traffic's fate — which is what makes `Block` legal in a
  monitor-only build and keeps ADR-3 intact.

---

## 2026-07-25 — D2 TIS key persistence, and a private key in the export

**Done**
- **D2 — persistent deployment keypair.** `tis.New(deployID, keyPath)` loads/creates the
  ES256 key instead of generating one per process. New `internal/keyfile` holds the one
  loader both TIS and the ledger use.
- **Cross-replica/restart replay had to be re-earned.** Call assertions were audience-bound
  to `deployID`; the reason a captured assertion failed elsewhere was that the *key* was
  ephemeral, so it failed the signature check — the audience was doing nothing. Persisting
  the key silently removes that. Audience is now `deployID#<per-instance nonce>`, so the
  assertion is addressed to an instance that no longer exists. Txn tokens carry no audience
  and stay deployment-portable, which is the point of the whole item.
- **The ledger's private signing key was being written into the ledger directory** —
  the directory that *is* the export handed to a third-party verifier (§8.5). Tarring
  evidence for an auditor also handed them the key to forge it. Keys now live under a new
  `-state-dir`, and `ledger.Open` **rejects** a key path inside the export rather than
  documenting the rule.
- **`Open` refuses to resume a chain signed by a different key.** A partition's pubkey is
  written once in its header and the verifier checks the whole file against it, so appending
  under a new key doesn't error — it produces a chain that stops verifying from that point,
  silently. Losing or repointing `-state-dir` is the ordinary way to get there.
- CI floor ratcheted 78.0 → 78.3.

**Reviews** (Codex + ponytail)
- Codex: 5 findings, 4 applied (resume-under-new-key, `O_EXCL` on create, the replay
  regression above, key-inside-export as a control not a comment). Its rotation note —
  one key, one header pubkey, no `kid` — is real and stays open as the NFR-5 item; the
  new resume check is deliberately the thing rotation must be built *through*, not around.
- ponytail: 4 findings, all applied, −29 lines. Deleted `TestExportDirHoldsNoPrivateKey`
  as tautological once `Open` rejects the path; the guard test is the real one.

**D1 — design settled in 3 rounds with Codex, then the non-endpoint half shipped.** The mint
endpoints are all that is left; roadmap §3.B has the remainder.
- The roadmap's framing ("proxy endpoint vs. SDK-local mint") was a false choice, and it was
  also aimed at the wrong risk. The hole is not unauthenticated mint — it is that **a valid
  assertion suppresses the attested principal**: `identify()` computes the coarse principal
  then discards it, and the record has one `principal` slot fed from the SDK's claim. §5.2
  says attested *never degrades*. Fix is an evidence split, and it does not require solving
  mint auth at all.
- Codex caught two things I had not: Cedar evaluates on that same asserted principal, so the
  reporting lie becomes an authorization bypass once enforce lands; and `Gurdy-Txn` is
  forwarded to the upstream MCP server, which is a reusable bearer token leak today.
- I pushed back twice and it conceded both: its 8 new record fields collapsed to 4 (existing
  names redefined rather than duplicated — near-synonyms are how records stop being readable
  by the auditor who is the customer), and its "Cedar must never see asserted identity" was
  stricter than §5.9's "policies may require attestation" — asserted values now reach policy
  as reserved *context* keys, so trusting an agent-side claim is a visible line in a pack.
- It got the last word: `Evaluate` seeds `context.tool` then overlays extractor attrs, so an
  extractor key named `tool` shadows the normalized one — the exact dodge the lowercasing
  exists to stop. Not exploitable today (extractors emit two hardcoded keys), arms with the
  §3.D registry.
- Three spec amendments **approved and applied** (doc now v0.8.1): §5.5's record schema split,
  NFR-5's mint-path wording, §8.2's contradiction test scoped. §5.5 had never listed
  `principal`/`principal_tier` that the code has shipped since Stage A.

**Then shipped**
- **Evidence split.** `principal`/`principal_tier` now always mean the proxy's own observation;
  `assertion_status` + `asserted_principal`/`asserted_human_actor`/`asserted_scope` carry the
  agent's claim. Asserted fields and `lineage[]` are written **only** when the assertion verified.
- **Cedar evaluates on the observed principal.** Asserted identity reaches policy as reserved
  context keys, so a pack that trusts an agent-side claim gates on
  `context.assertion_status == "valid"` on an explicit line.
- **Reserved context keys are dropped, not overwritten**, if an extractor emits one. Landed ahead
  of the extractor registry that makes it reachable — Codex caught that "write last" still let a
  forged `asserted_principal` through in exactly the case that matters, when no real claim exists
  to overwrite it.
- **`Gurdy-Txn` no longer forwarded upstream** — it was a live bearer credential handed to the
  tool server on every call.
- Applying the amendments surfaced five stale identity references in the doc, incl. **§5.3 telling
  pack authors Cedar's principal is the call assertion**. All repaired; details in roadmap §8a.
- CI floor 78.3 → 78.9.

**Notes**
- **Pre-existing ~8% CI flake found and fixed, unrelated to D2:** `TestEveryByteMutationDetected`
  failed 2/24 runs at unmodified HEAD. Base64 is non-canonical at the padding boundary, so
  several `sig` strings decode to one signature — and the final batchsig line has no successor
  committing to it via `prev_hash`, leaving the signature as the only check. `base64.StdEncoding.Strict()`;
  0/24 after. It had been read as flakiness rather than as the finding it was.
- Every new test mutation-checked: revert `O_EXCL`, the export guard, the resume check, or
  key persistence, and the matching test fails.
- Verified outside the suite: two separate proxy runs against one `-state-dir` produce one
  5-record chain, `gurdy-verify` OK, export dir holds only the `.jsonl`.

---

## 2026-07-25 — gurdy-verify coverage, and a forged-tail hole it exposed

**Done**
- `cmd/gurdy-verify` 0% → `run` 100%, `expand`/`readPubKey` ~91%. Total 71.0% → 78.4%;
  CI floor ratcheted to 78.0.
- `main()` split into `run(args, out, errOut) int`. The exit code **is** the product claim
  (a third party runs the binary and believes it), so it is now tested: 0 = all verified,
  1 = at least one did not, 2 = could not run. 2 must never read as 0.
- **Found a real hole while writing the tests: a forged unsigned tail verified as `OK`,
  exit 0.** Append fabricated decisions past the last batch signature with a correct `seq`
  and `prev_hash` — both recomputable by anyone — and the verifier printed OK over a
  fabricated `"tool":"exfiltrate","decision":"allow"` record. Unsigned means unverified, so
  the CLI now fails on uncovered records, with `-allow-unsigned-tail` for inspecting a *live*
  ledger mid-window. **Behaviour change:** verifying a running proxy's ledger dir now needs
  that flag. `VerifyFile` keeps reporting rather than failing — library reports, tool decides.
- Header-only exports (verified nothing, no signature) now fail too; same check covers it.
- `-h` exits 0 again, not 2 — regression from the `ExitOnError` → `ContinueOnError` switch.

**Reviews**
- Codex: 4 findings, all 4 applied. Two were mine-in-this-change (`-h`, weak tamper test),
  two were pre-existing verifier gaps (forged tail, vacuous header-only pass).
- Codex was right that the first tamper test was fake: it flipped a byte, producing invalid
  JSON, so it would have passed with chain *and* signature checking entirely removed. Rewritten
  to rewrite a field **value**, keeping the file valid JSON so only the hash chain can catch it —
  confirmed by mutation (disable the `prev_hash` check → test fails).
- ponytail: 2 findings, both applied, −37 lines. The standalone tamper test collapsed into
  `TestOneBadPartitionFailsWholeRun` (at the CLI boundary both were just "VerifyFile errored →
  exit 1"), and the wrong-pinned-key subtest went — the matching-key test already proves pinning
  is enforced, since `key: pinned` only prints when the key reaches `VerifyFile`. Coverage was
  **unchanged at 78.4% after the deletion**, which is the evidence they were redundant.

**Notes**
- Every new test mutation-checked. Removing the unsigned-tail check makes both new integrity
  tests fail; removing the `prev_hash` check makes the tamper test fail.
- Added forged-unsigned-tail to the §3.H adversarial corpus list — fixed and regression-tested,
  still needs a corpus trace.

---

## 2026-07-25 — CI + D3 ledger partitions

**Done**
- `CLAUDE.md` at repo root: build/test commands, package↔governance-loop map, the
  load-bearing invariants, spec-citation conventions.
- **D3 — real ledger partitions.** `-tenant` flag; partition key = tenant + attested-coarse
  workload (never the *asserted* principal, so an agent can't steer or fragment the chain its
  own evidence lands in). Both `Append` sites wired.
- **CI** — `.github/workflows/ci.yml`: gofmt, vet, build, `go test -race`, coverage gate.
  Plus a minimal `.gitignore`.
- Not the two-line change the roadmap predicted. Real partition names carry `:`, `/` and
  arbitrary case, which surfaced two defects that had to land with it:
  - `url.PathEscape` is not a filename encoding — leaves `:` (illegal on Windows) and preserves
    case, so on macOS/NTFS two workloads differing only in case **silently merged into one
    chain**. Replaced with `Ledger.path()`: lowercased readable prefix + 64-bit hash of the
    original name.
  - One fd per workload, never released → fd exhaustion, and a monitor proxy out of fds stops
    governing entirely (NFR-3). Added `maxOpenParts` + LRU eviction that preserves chain state
    and reopens on next write.

**Reviews** (per the Codex + ponytail workflow)
- ponytail: 3 findings, all applied, −10 lines (CI shell shrunk to one-liners, redundant
  `.gitignore` entry).
- Codex round 1: 3 findings, 2 applied (the two above). **Declined:** stdio workload identity is
  `filepath.Base(argv[0])`, which collides across same-named binaries — pre-existing coarse-principal
  shallowness that §5.2 already defers to real workload identity, and the threat model requires
  control of the shim launch command, at which point the attacker just wouldn't run it.
- Codex round 2 on the fix deltas: 3 findings, all applied — hash widened 32→64 bits (birthday
  collision merges chains, the exact failure the encoding prevents); `evictLRU` was swallowing
  `signBatch`/`Flush`/`Close` errors, leaving the in-memory chain head ahead of disk. Now forgets
  the partition on error so the next write re-scans from the real on-disk head, gap counted in
  `Dropped` rather than silently spliced.

**Notes for next time**
- Writing the eviction test caught a bug in the first version of my own fix: it skipped evicting
  partitions with an open batch, making the cap useless during a sub-tick burst — precisely the
  case it existed for. Both new ledger tests were mutation-checked (revert the fix → test fails).
- Coverage gate is **70.5%, a ratchet at the measured floor, not §8's 85%**. Shipping a red
  pipeline was the alternative. The roadmap item stays open until `MIN` reads 85.
- Verified end-to-end outside the test suite: stdio shim → real ledger file
  (`acme_stdio_cat-<hash>.jsonl`) → `gurdy-verify` OK, both starter policies firing.
