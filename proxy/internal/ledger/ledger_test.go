package ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeN(t *testing.T, dir string, n int) string {
	t.Helper()
	l, err := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"}) // sibling of the export, stable across restarts
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		l.Append("local", Record{
			TS: "2026-07-24T00:00:00Z", TxnID: "T1", Tool: "read_file",
			Action: "mcp/tools_call", Decision: "allow",
			Lineage: []string{"agent"}, BundleVer: "v0",
			ResourceAttrs: map[string]string{"resource_path": "/tmp/x"},
		})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := l.Dropped.Load(); got != 0 {
		t.Fatalf("dropped %d records", got)
	}
	return l.path("local")
}

// Partition names are (tenant, workload) keys carrying ":" and "/" and
// arbitrary case. Two distinct workloads must never map to one file: a merged
// chain silently misattributes evidence.
func TestPartitionFilenamesDistinctAndPortable(t *testing.T) {
	l, err := Open(t.TempDir(), filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	names := []string{
		"local/cat", "local/Cat", // differ only by case — collide on macOS/NTFS
		"local/stdio:cat", "local/stdio:Cat",
		"local/::1", "local/127.0.0.1",
		"other/cat",              // same workload, different tenant
		"local/" + longName(200), // over the readable-prefix cap
		"local/" + longName(201),
	}
	seen := map[string]string{}
	for _, n := range names {
		p := l.path(n)
		if prev, dup := seen[p]; dup {
			t.Fatalf("partitions %q and %q share file %s", prev, n, p)
		}
		seen[p] = n
		if base := filepath.Base(p); strings.ContainsAny(base, `:/\<>"|?*`) {
			t.Fatalf("partition %q -> filename %q is not portable", n, base)
		}
	}
}

func longName(n int) string { return strings.Repeat("w", n) }

// Workload churn must not exhaust file descriptors (NFR-3: a proxy that runs
// out of fds stops governing), and a partition whose handle was reclaimed must
// resume its own chain rather than start a new one.
func TestPartitionEvictionResumesChain(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"}) // sibling of the export, stable across restarts
	if err != nil {
		t.Fatal(err)
	}
	rec := func() Record {
		return Record{TS: "2026-07-25T00:00:00Z", Tool: "read_file",
			Action: "mcp/tools_call", Decision: "allow", BundleVer: "v0"}
	}
	// One record each to well over the fd budget, so the first partitions are
	// certainly evicted, then write to the very first one again.
	total := maxOpenParts * 3
	for i := 0; i < total; i++ {
		l.Append(fmt.Sprintf("local/w%d", i), rec())
	}
	l.Append("local/w0", rec())
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := l.Dropped.Load(); got != 0 {
		t.Fatalf("dropped %d records under churn", got)
	}
	if l.open > maxOpenParts {
		t.Fatalf("%d open handles exceeds budget %d", l.open, maxOpenParts)
	}

	// w0 took two writes across an eviction: one unbroken, verifiable chain.
	res, err := VerifyFile(l.path("local/w0"), nil)
	if err != nil {
		t.Fatalf("chain broken across eviction: %v", err)
	}
	if res.Decisions != 2 {
		t.Fatalf("want 2 decisions in the resumed chain, got %+v", res)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	files = slices.DeleteFunc(files, func(f string) bool { // the lifecycle chain is not a workload
		return strings.HasPrefix(filepath.Base(f), ProxyPartition)
	})
	if len(files) != total {
		t.Fatalf("want %d partition files, got %d", total, len(files))
	}
	for _, f := range files {
		if _, err := VerifyFile(f, nil); err != nil {
			t.Fatalf("partition %s does not verify: %v", f, err)
		}
	}
}

// The partition *map* is bounded, not just the fd budget (D6). Eviction there
// only released the handle and kept the chain state, so the map grew once per
// (tenant, workload) key ever seen and never shrank.
//
// The bound is the cheap half. What this actually has to prove is that a
// partition dropped from memory and later written to again continues its own
// chain — forgetting rebuilds seq and head with scanTail, and getting that
// wrong would splice or fork a chain rather than fail loudly.
func TestPartitionMapIsBounded(t *testing.T) {
	defer func(old int) { maxParts = old }(maxParts)
	maxParts = maxOpenParts + 8 // must exceed the fd budget or nothing is ever closed

	dir := t.TempDir()
	l, err := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	rec := func() Record {
		return Record{TS: "2026-08-15T00:00:00Z", Tool: "read_file",
			Action: "mcp/tools_call", Decision: "allow", BundleVer: "v0"}
	}
	total := maxParts * 2 // twice the cap, so w0 is long forgotten rather than merely closed
	for i := range total {
		l.Append(fmt.Sprintf("local/w%d", i), rec())
	}
	l.Append("local/w0", rec())
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	if got := l.Dropped.Load(); got != 0 {
		t.Fatalf("dropped %d records under churn", got)
	}
	if len(l.parts) > maxParts {
		t.Fatalf("map holds %d partitions, cap is %d — the bound does nothing", len(l.parts), maxParts)
	}
	if l.open > maxOpenParts {
		t.Fatalf("%d open handles exceeds budget %d", l.open, maxOpenParts)
	}

	// What survives must be the *recently used*, not an arbitrary subset. A
	// bound alone is satisfied by forgetting whatever was touched last, which
	// stays bounded and thrashes: every new partition immediately re-scanned.
	// Chains verify either way, so nothing else here would notice.
	for _, name := range []string{
		"local/w0",                        // revived last of all
		fmt.Sprintf("local/w%d", total-1), // written last in the loop
	} {
		if _, ok := l.parts[name]; !ok {
			t.Errorf("%s was forgotten though it is among the most recently used — eviction is not LRU", name)
		}
	}
	// The above two are both still *open*, so no eviction policy would drop
	// them and they cannot tell one policy from another. w1 is the case that
	// can: written once at the very start, never revived, closed long ago. LRU
	// must have forgotten it; a policy that evicts the newest closed partition
	// instead keeps precisely the oldest ones and would still pass every other
	// assertion here, because chains verify either way.
	if _, ok := l.parts["local/w1"]; ok {
		t.Errorf("local/w1 survived %d newer partitions — eviction is keeping the coldest, not the hottest", total-2)
	}

	// w0 was written, forgotten, and written again: one unbroken chain.
	res, err := VerifyFile(l.path("local/w0"), nil)
	if err != nil {
		t.Fatalf("chain broken across being forgotten: %v", err)
	}
	if res.Decisions != 2 {
		t.Fatalf("want 2 decisions in the revived chain, got %+v", res)
	}

	// And it must not have manufactured a crash signal. `resumed` means the
	// writer inherited an *unsigned* tail from a previous run, which is what a
	// crash leaves. A partition we closed deliberately was signed before its
	// handle went, so reviving it has nothing to inherit — and a reader who
	// finds `resumed` here would be told this process died when it did not.
	if n := countReason(t, l.path("local/w0"), ReasonResumed); n != 0 {
		t.Fatalf("%d 'resumed' records: forgetting a cleanly closed partition invented a crash", n)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	files = slices.DeleteFunc(files, func(f string) bool {
		return strings.HasPrefix(filepath.Base(f), ProxyPartition)
	})
	if len(files) != total {
		t.Fatalf("want %d partition files, got %d", total, len(files))
	}
	for _, f := range files {
		if _, err := VerifyFile(f, nil); err != nil {
			t.Fatalf("partition %s does not verify: %v", f, err)
		}
	}
}

func countReason(t *testing.T, path, reason string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r Record
		if json.Unmarshal([]byte(line), &r) == nil && r.Reason == reason {
			n++
		}
	}
	return n
}

func TestWriteVerifyRoundTrip(t *testing.T) {
	path := writeN(t, t.TempDir(), 100)
	res, err := VerifyFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decisions != 100 || res.Batches < 2 || res.Uncovered != 0 {
		t.Fatalf("result: %+v", res)
	}
}

// Mutation drill (§8.3): flip any byte in the export — the verifier must fail.
func TestEveryByteMutationDetected(t *testing.T) {
	path := writeN(t, t.TempDir(), 10)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path, nil); err != nil {
		t.Fatalf("baseline must verify: %v", err)
	}
	// ponytail: exhaustive per-byte flip is O(n²) verify work; fine at this
	// size, sample bytes if the fixture ever grows.
	for i := range orig {
		if orig[i] == '\n' {
			continue // deleting/mangling line structure is caught as JSON/seq errors below anyway
		}
		mut := append([]byte{}, orig...)
		mut[i] ^= 0x01
		if err := os.WriteFile(path, mut, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyFile(path, nil); err == nil {
			t.Fatalf("byte %d flip undetected (line context: %q)", i, sampleAround(orig, i))
		}
	}
}

// Removing a whole signed record must break the chain (splice detection).
func TestRecordDeletionDetected(t *testing.T) {
	path := writeN(t, t.TempDir(), 10)
	orig, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(orig), "\n")
	for cut := 1; cut < len(lines)-1; cut++ { // keep header; last elem is ""
		mut := strings.Join(append(append([]string{}, lines[:cut]...), lines[cut+1:]...), "")
		os.WriteFile(path, []byte(mut), 0o644)
		if _, err := VerifyFile(path, nil); err == nil {
			t.Fatalf("deleting record %d undetected", cut)
		}
	}
}

// Restart must continue one chain: same key, seq continuity, still verifies.
func TestRestartContinuesChain(t *testing.T) {
	dir := t.TempDir()
	writeN(t, dir, 5)
	path := writeN(t, dir, 5) // second Open on same dir
	res, err := VerifyFile(path, nil)
	if err != nil {
		t.Fatalf("chain broken across restart: %v", err)
	}
	if res.Decisions != 10 {
		t.Fatalf("want 10 decisions across restart, got %d", res.Decisions)
	}
}

// A wrong pinned key must fail even when the embedded key would verify.
func TestPinnedKeyMismatchFails(t *testing.T) {
	path := writeN(t, t.TempDir(), 5)
	other, err := Open(t.TempDir(), filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme", Instance: "i1"}) // separate key path -> different key
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := VerifyFile(path, &other.key.PublicKey); err == nil {
		t.Fatal("verified against the wrong pinned key")
	}
}

func sampleAround(b []byte, i int) string {
	lo, hi := i-20, i+20
	if lo < 0 {
		lo = 0
	}
	if hi > len(b) {
		hi = len(b)
	}
	return string(b[lo:hi])
}

// The signing key must not be placed inside the export, and the check must be
// a control rather than a comment: -state-dir and -ledger-dir are independent
// flags, so nothing but this stops them being pointed at one directory.
func TestKeyInsideExportRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, filepath.Join(dir, "key.pem"), Identity{Tenant: "acme", Instance: "i1"}); err == nil {
		t.Fatal("accepted a signing key inside the export directory")
	}
	if _, err := Open(dir, filepath.Join(dir, "keys", "key.pem"), Identity{Tenant: "acme", Instance: "i1"}); err == nil {
		t.Fatal("accepted a signing key nested inside the export directory")
	}
}

// Appending to an existing chain under a different key produces records that
// no longer verify against the pubkey in the file's header — silently, since
// the verifier reads that one key for the whole file. Open must refuse.
func TestResumeUnderDifferentKeyRejected(t *testing.T) {
	dir := t.TempDir()
	writeN(t, dir, 3)
	if _, err := Open(dir, filepath.Join(t.TempDir(), "other.pem"), Identity{Tenant: "acme", Instance: "i1"}); err == nil {
		t.Fatal("resumed an existing chain under a different signing key")
	}
	// The original key still opens it, so the check is key identity and not
	// "any reopen fails".
	l, err := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatalf("original key rejected: %v", err)
	}
	l.Close()
}

// "Answered" is the call_id join, not a row count. A response whose decision
// never made it into the chain (queue drop, or an export that starts
// mid-call) must be reported as unmatched rather than counted as an answer —
// otherwise the one number a reader uses to judge coverage is inflated by
// exactly the records that prove coverage was lost.
func TestVerifyJoinsResponsesByCallID(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	n := int64(7)
	l.Append("local", Record{TS: "t", CallID: "c1", Decision: "allow"})
	l.Append("local", Record{TS: "t", CallID: "c2", Decision: "flag"}) // never answered
	l.AppendResponse("local", Record{TS: "t", CallID: "c1", RespHash: "h", Status: 200, Bytes: &n})
	l.AppendResponse("local", Record{TS: "t", CallID: "ghost", RespHash: "h", Status: 200, Bytes: &n})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(l.path("local"), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Decisions != 2 || res.Answered != 1 || res.Unmatched != 1 {
		t.Fatalf("decisions %d, answered %d, unmatched %d — want 2/1/1",
			res.Decisions, res.Answered, res.Unmatched)
	}
}

// A zero-byte response is evidence; an uncaptured one is a gap. omitempty on
// a plain int64 would erase the difference, so Bytes is a pointer.
func TestZeroBytesDistinctFromUncaptured(t *testing.T) {
	zero := int64(0)
	empty, _ := json.Marshal(Record{Kind: KindResponse, CallID: "c", Bytes: &zero})
	if !strings.Contains(string(empty), `"bytes":0`) {
		t.Fatalf("empty response lost its byte count: %s", empty)
	}
	uncaptured, _ := json.Marshal(Record{Kind: KindResponse, CallID: "c"})
	if strings.Contains(string(uncaptured), "bytes") {
		t.Fatalf("uncaptured response claims a byte count: %s", uncaptured)
	}
}

// A request still in flight at shutdown appends after Close: http.Server.Close
// does not wait for handlers, and never waits for a hijacked connection. A
// "send on closed channel" panic there would crash the process whose whole job
// is recording what happened — the record is dropped and counted instead.
func TestAppendAfterCloseDropsRatherThanPanics(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	l.Append("local", Record{TS: "t", CallID: "c1", Decision: "allow"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l.Append("local", Record{TS: "t", CallID: "c2", Decision: "allow"})
	l.AppendResponse("local", Record{TS: "t", CallID: "c1"})
	if got := l.Dropped.Load(); got != 2 {
		t.Fatalf("post-close records dropped: %d, want 2 counted", got)
	}
	if err := l.Close(); err != nil { // idempotent: shutdown paths double-close
		t.Fatalf("second Close: %v", err)
	}
}

// A dropped record must produce a coverage record in the chain that lost it.
// The circularity is the point: the queue that dropped it cannot be the path
// that reports it, so the writer goroutine emits the finding directly (§5.5).
func TestDropsBecomeCoverageRecords(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	// Overflow the queue: many more records than it can hold, enqueued before
	// the writer can drain them.
	for i := 0; i < queueCap*3; i++ {
		l.Append("local/w", Record{TS: "t", CallID: "c", Decision: "allow"})
	}
	l.RecordIdentityGap("local/w")
	if l.Dropped.Load() == 0 {
		t.Skip("queue drained faster than it filled; nothing was dropped")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(l.path("local/w"), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Dropped == 0 {
		t.Fatal("records were dropped but the export does not say so")
	}
	if res.Dropped != l.Dropped.Load() {
		t.Errorf("export says %d dropped, counters say %d", res.Dropped, l.Dropped.Load())
	}
	if res.IdentityFail != 1 {
		t.Errorf("identity gap missing from the export: %+v", res)
	}
}

// The shutdown record is the crash signal, by its absence. A chain whose
// process died must not read the same as one that exited cleanly — that
// equivalence is precisely what §7 forbids.
func TestCrashLeavesNoShutdownRecord(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	clean, err := Open(dir, filepath.Join(keyDir, "key.pem"), Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	clean.Append("local/w", Record{TS: "t", CallID: "c1", Decision: "allow"})
	if err := clean.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyFile(clean.path(ProxyPartition), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.CleanEnd == nil || !*res.CleanEnd {
		t.Fatalf("clean shutdown not recorded: %+v", res)
	}

	// A crash is the writer never reaching Close. Simulate it by writing the
	// lifecycle chain's records without one, into a fresh directory.
	crashDir := t.TempDir()
	crashed, err := Open(crashDir, filepath.Join(keyDir, "key.pem"), Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	crashed.write(ProxyPartition, Record{Kind: KindCoverage, Reason: ReasonHeartbeat,
		TS: "2026-07-25T00:00:00Z", WindowFrom: "2026-07-25T00:00:00Z", WindowTo: "2026-07-25T00:05:00Z"})
	p := crashed.parts[ProxyPartition]
	crashed.signBatch(p)
	p.w.Flush()

	res, err = VerifyFile(crashed.path(ProxyPartition), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.CleanEnd == nil || *res.CleanEnd {
		t.Fatalf("a chain with no shutdown record must not read as a clean end: %+v", res)
	}

	// Restarting after that crash must not erase it: CleanEnd only speaks for
	// the tail, so the crash has to survive as an unclean-restart finding.
	restarted, err := Open(crashDir, filepath.Join(keyDir, "key.pem"), Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	res, err = VerifyFile(restarted.path(ProxyPartition), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.UncleanRestarts != 1 {
		t.Errorf("the crash stopped being reported once the proxy restarted: %+v", res)
	}
	if res.CleanEnd == nil || !*res.CleanEnd {
		t.Errorf("the restarted run ended cleanly and should say so: %+v", res)
	}
}

// Heartbeats are coalesced into one record per window, because an append-only
// chain cannot be compacted after the fact: an idle proxy must not write a
// line per tick forever.
func TestHeartbeatCoalescesIdleWindows(t *testing.T) {
	l, err := Open(t.TempDir(), filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	start := l.hbTS
	for i := 1; i <= 100; i++ { // 100 ticks inside one window
		l.writeHeartbeat(start.Add(time.Duration(i)*time.Second), time.Hour)
	}
	// The chain already holds the header and the start record; a coalesced
	// window must add nothing until it closes.
	atStart := l.parts[ProxyPartition].seq
	if atStart != 3 { // header + start record + its batch signature
		t.Fatalf("want header + signed start record, got %d", atStart)
	}
	l.writeHeartbeat(start.Add(2*time.Hour), time.Hour) // window elapsed
	if got := l.parts[ProxyPartition].seq; got != atStart+1 {
		t.Fatalf("want exactly one coalesced heartbeat, got %d extra records", got-atStart)
	}
}

// A clean restart is not a coverage gap, and an inherited unsigned tail is.
// Both matter for the same reason: a verifier that cries wolf over planned
// downtime trains its reader to ignore the one finding that counts.
func TestRestartIsNotAGapButAnUnsignedTailIsMarked(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	key := filepath.Join(keyDir, "key.pem")

	first, err := Open(dir, key, Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir, key, Identity{Tenant: "acme", Instance: "i1"}) // same chain, clean handover
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyFile(second.path(ProxyPartition), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.LivenessGaps != 0 || res.UncleanRestarts != 0 {
		t.Errorf("a clean restart was reported as a gap: %d liveness, %d unclean", res.LivenessGaps, res.UncleanRestarts)
	}
	if res.CleanEnd == nil || !*res.CleanEnd {
		t.Errorf("second run ended cleanly but the chain does not say so: %+v", res)
	}

	// Now the adversarial shape: someone appends to the unsigned tail a crash
	// left behind, and the next process would sign over it. The resume marker
	// is what keeps that boundary visible.
	crashDir := t.TempDir()
	crashed, err := Open(crashDir, key, Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	crashed.write("local/w", Record{Kind: KindDecision, TS: "t", CallID: "c", Decision: "allow"})
	crashed.parts["local/w"].w.Flush() // no batchsig: the shape a crash leaves

	resumed, err := Open(crashDir, key, Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	resumed.write("local/w", Record{Kind: KindDecision, TS: "t", CallID: "c2", Decision: "allow"})
	if err := resumed.Close(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(resumed.path("local/w"))
	// 2, not 1: the count is lines no signature covers, matching the verifier's
	// own Uncovered — the header is unsigned until the first batchsig too.
	if !strings.Contains(string(raw), `"reason":"resumed"`) ||
		!strings.Contains(string(raw), `"inherited_unsigned":2`) {
		t.Fatalf("resumed chain does not mark the tail it inherited:\n%s", raw)
	}
	// The inherited count must not masquerade as lost records.
	res, err = VerifyFile(resumed.path("local/w"), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Dropped != 0 {
		t.Errorf("inherited records counted as drops: %+v", res)
	}
}

// The chain must say what it is evidence *of*, inside the signature. A
// partition identity that lives only in a filename is not evidence: renaming
// the file would silently re-attribute a whole chain to another tenant, and
// nothing in the export would contradict it.
func TestIdentityIsSignedNotFilename(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme", Instance: "proc-1"})
	if err != nil {
		t.Fatal(err)
	}
	l.Append("acme/billing-agent", Record{TS: "t", CallID: "c1", Decision: "allow"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	original := l.path("acme/billing-agent")

	res, err := VerifyFile(original, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tenant != "acme" || res.Workload != "billing-agent" || res.InstanceID != "proc-1" {
		t.Fatalf("identity missing from the signed header: %+v", res)
	}
	if res.SchemaVersion != SchemaVersion || res.Kid == "" {
		t.Errorf("schema version or key id missing: %+v", res)
	}

	// Rename it to something that claims a different tenant. The file still
	// verifies — that is fine — but it must still report the tenant it was
	// actually written for.
	renamed := filepath.Join(dir, "megacorp_other-agent-deadbeef.jsonl")
	if err := os.Rename(original, renamed); err != nil {
		t.Fatal(err)
	}
	res, err = VerifyFile(renamed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tenant != "acme" || res.Workload != "billing-agent" {
		t.Fatalf("a rename changed what the chain claims: %+v", res)
	}

	// And editing the header to claim another tenant must break the chain.
	raw, _ := os.ReadFile(renamed)
	tampered := bytes.Replace(raw, []byte(`"tenant":"acme"`), []byte(`"tenant":"mega"`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("fixture wrong: no tenant field in the header")
	}
	if err := os.WriteFile(renamed, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(renamed, nil); err == nil {
		t.Fatal("a rewritten tenant claim verified")
	}
}

// A record kind this verifier does not know is counted, never fatal. The first
// record type a future proxy adds would otherwise strand every deployed
// verifier — and the integrity claim never depended on understanding a record,
// only on it being chained and signed.
func TestUnknownKindCountedNotFatal(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	l.Append("acme/w", Record{TS: "t", CallID: "c1", Decision: "allow"})
	// A kind from a future version, written through the normal path so it is
	// chained and signed exactly like everything else.
	l.enqueue("acme/w", Record{Kind: "future-thing", TS: "t", CallID: "c1"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyFile(l.path("acme/w"), nil)
	if err != nil {
		t.Fatalf("an unknown kind failed the whole export: %v", err)
	}
	if res.UnknownKinds != 1 {
		t.Errorf("unknown kinds = %d, want 1 (counted, so it cannot be mistaken for absent)", res.UnknownKinds)
	}
	if res.Decisions != 1 {
		t.Errorf("known records misread alongside the unknown one: %+v", res)
	}
}

// AppendSync is the seam the Phase 2 actuator needs: §5.5 requires an enforced
// call to be recorded *before* the effect is released, which a fire-and-forget
// API cannot express.
func TestAppendSyncIsDurableBeforeItReturns(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AppendSync("acme/w", Record{TS: "t", CallID: "c1", Decision: "block"}); err != nil {
		t.Fatalf("AppendSync: %v", err)
	}
	// On disk before the call returned — not merely queued.
	raw, err := os.ReadFile(l.path("acme/w"))
	if err != nil || !strings.Contains(string(raw), `"call_id":"c1"`) {
		t.Fatalf("record was not durable when AppendSync returned: %v %q", err, raw)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.AppendSync("acme/w", Record{TS: "t", CallID: "c2"}); err == nil {
		t.Fatal("AppendSync after Close must report failure, not swallow it")
	}
}

func TestProducerIsRecordedAndSigned(t *testing.T) {
	// Which build wrote a chain is evidence, not telemetry: if a defect is
	// found in a released build, a reader holding an export must be able to
	// tell whether theirs came from an affected one. That answer is worth
	// nothing unless forging it is detectable, so this asserts both halves.
	dir := t.TempDir()
	l, err := Open(dir, filepath.Join(t.TempDir(), "key.pem"),
		Identity{Tenant: "acme", Instance: "proc-1", Producer: "gurdy/v1.2.3+abc123def456"})
	if err != nil {
		t.Fatal(err)
	}
	l.Append("acme/agent", Record{TS: "t", CallID: "c1", Decision: "allow"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	path := l.path("acme/agent")

	res, err := VerifyFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Producer != "gurdy/v1.2.3+abc123def456" {
		t.Fatalf("producer missing from the signed header: %q", res.Producer)
	}

	// Rewrite only the producer, leaving every other byte alone. A reader who
	// trusts this field to decide whether their export is affected by a known
	// defect is relying on exactly this failing.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var hdr map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	hdr["producer"] = "gurdy/v9.9.9+notthisbuild"
	forged, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = string(forged)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path, nil); err == nil {
		t.Error("a forged producer verified — the field is outside the signature and worthless")
	}
}

func TestProducerAbsentIsNotFabricated(t *testing.T) {
	// An export written before this field existed, or by a build that did not
	// set it, must report empty rather than a plausible-looking guess. The
	// reporter renders absence as "none"; inventing a value here would make an
	// unknown build indistinguishable from a known one.
	dir := t.TempDir()
	l, err := Open(dir, filepath.Join(t.TempDir(), "key.pem"), Identity{Tenant: "acme", Instance: "p"})
	if err != nil {
		t.Fatal(err)
	}
	l.Append("acme/agent", Record{TS: "t", CallID: "c1", Decision: "allow"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyFile(l.path("acme/agent"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Producer != "" {
		t.Errorf("producer invented for a build that set none: %q", res.Producer)
	}
}

// D14: a chain too large for one file continues into the next, and the reader
// has to understand that before any writer produces one — a verifier that
// rejects segment 2 as "gap or splice" would strand every export the first
// time rotation ships. These build the continuation by hand for that reason:
// nothing rolls files yet.

// segmentTwo writes a second segment that legitimately continues `from`,
// re-signing it under the same key so it is a real chain and not a fixture
// that only looks like one.
func segmentTwo(t *testing.T, dir, from string, decisions int) string {
	t.Helper()
	prev, err := VerifyFile(from, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	next := prev.Segment + 1
	l.seedSegment("local", next, prev.LastSeq, prev.HeadHash)
	for range decisions {
		l.Append("local", Record{TS: "2026-08-10T00:00:00Z", TxnID: "T2", Tool: "read_file",
			Action: "mcp/tools_call", Decision: "allow", BundleVer: "v0"})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return l.segPath("local", next)
}

func TestContinuationSegmentVerifiesAndSaysWhatItFollows(t *testing.T) {
	dir := t.TempDir()
	first := writeN(t, dir, 3)
	head, err := VerifyFile(first, nil)
	if err != nil {
		t.Fatal(err)
	}

	seg2 := segmentTwo(t, t.TempDir(), first, 2)
	res, err := VerifyFile(seg2, nil)
	if err != nil {
		t.Fatalf("a legitimate continuation must verify: %v", err)
	}
	if res.Segment != 2 {
		t.Errorf("want segment 2, got %d", res.Segment)
	}
	// The load-bearing part: verifying clean is NOT the same as being whole,
	// and the result has to say so or a reader takes one segment for a chain.
	if res.ContinuesFrom != head.HeadHash {
		t.Errorf("continues_from %q does not name the predecessor's head %q",
			res.ContinuesFrom, head.HeadHash)
	}
	if res.FirstSeq != head.LastSeq+1 {
		t.Errorf("segment 2 starts at seq %d, predecessor ended at %d", res.FirstSeq, head.LastSeq)
	}
}

// The seam is what a caller checks, so it has to be checkable: a segment
// pointing at the wrong predecessor must not quietly line up.
func TestSeamDetectsTheWrongPredecessor(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	a := writeN(t, dirA, 3)
	b := writeN(t, dirB, 3) // a different chain, same shape

	seg2 := segmentTwo(t, t.TempDir(), a, 1)
	res, _ := VerifyFile(seg2, nil)
	other, _ := VerifyFile(b, nil)
	if res.ContinuesFrom == other.HeadHash {
		t.Fatal("two different chains produced the same head — the seam check proves nothing")
	}
}

// A chain written before segments existed says nothing about them, and must
// not read as "segment 0, predecessor unknown".
func TestAbsentSegmentReadsAsTheFirstOne(t *testing.T) {
	res, err := VerifyFile(writeN(t, t.TempDir(), 2), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Segment != 1 {
		t.Errorf("want segment 1, got %d", res.Segment)
	}
	if res.ContinuesFrom != "" {
		t.Errorf("a first segment follows nothing, got %q", res.ContinuesFrom)
	}
}

// A continuation that names no predecessor is not a continuation. Left as an
// error rather than a count: every other "begins mid-stream" case is at least
// checkable by someone holding the earlier segments, and this one is not.
func TestContinuationWithNoPredecessorIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orphan.jsonl")
	line, _ := json.Marshal(Record{Kind: KindHeader, Seq: 9, Segment: 4, PrevHash: ""})
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path, nil); err == nil {
		t.Fatal("a segment declaring no predecessor must not verify")
	}
}

// D14 part two: the writer rolls, and every segment it produces is a whole
// chain that names its predecessor. Rolling is the alternative to an
// unbounded file, never to keeping the evidence.
func TestRollingProducesVerifiableSegmentsWithProvableSeams(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	l.maxSegment = 4096 // a few records per segment, not 256 MiB
	for range 300 {
		l.Append("local", Record{TS: "2026-08-10T00:00:00Z", TxnID: "T1", Tool: "read_file",
			Action: "mcp/tools_call", Decision: "allow", BundleVer: "v0"})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := l.Dropped.Load(); got != 0 {
		t.Fatalf("rolling dropped %d records — rotation must never cost evidence", got)
	}

	var results []*VerifyResult
	for n := 1; ; n++ {
		path := l.segPath("local", n)
		if _, err := os.Stat(path); err != nil {
			break
		}
		res, err := VerifyFile(path, nil)
		if err != nil {
			t.Fatalf("segment %d does not verify on its own: %v", n, err)
		}
		if res.Segment != n {
			t.Errorf("file %d declares segment %d", n, res.Segment)
		}
		results = append(results, res)
	}
	if len(results) < 3 {
		t.Fatalf("want several segments, got %d — the bound did not trigger", len(results))
	}

	var decisions int
	for i, res := range results {
		decisions += res.Decisions
		if i == 0 {
			if res.ContinuesFrom != "" {
				t.Errorf("segment 1 follows nothing, claims %q", res.ContinuesFrom)
			}
			continue
		}
		// The seam, checked the only way it can be: across two files, by
		// whoever holds both. A single-file verify cannot do this and does not
		// pretend to.
		prev := results[i-1]
		if res.ContinuesFrom != prev.HeadHash {
			t.Errorf("segment %d links to %q, predecessor head is %q", i+1, res.ContinuesFrom, prev.HeadHash)
		}
		if res.FirstSeq != prev.LastSeq+1 {
			t.Errorf("segment %d starts at seq %d, predecessor ended at %d", i+1, res.FirstSeq, prev.LastSeq)
		}
		// Sealing: a rolled segment leaves nothing for a later process to
		// inherit. Only the final, still-open segment may carry an uncovered
		// tail, and Close signs even that.
		if prev.Uncovered != 0 {
			t.Errorf("sealed segment %d left %d records outside every signature", i, prev.Uncovered)
		}
	}
	if decisions != 300 {
		t.Errorf("300 calls produced %d decision records across %d segments", decisions, len(results))
	}
}

// Resume must continue the last segment. Appending to segment 1 of a rolled
// chain forks it into two files each claiming the same successor, and nothing
// downstream could say which was the real chain.
func TestResumeContinuesTheLastSegmentNotTheFirst(t *testing.T) {
	dir := t.TempDir()
	key := dir + ".key.pem"
	l, err := Open(dir, key, Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	l.maxSegment = 4096
	for range 200 {
		l.Append("local", Record{TS: "2026-08-10T00:00:00Z", Tool: "read_file", Decision: "allow"})
	}
	l.Close()
	before := l.latestSegment("local")
	if before < 2 {
		t.Fatalf("need a rolled chain, got %d segments", before)
	}
	head, err := VerifyFile(l.segPath("local", before), nil)
	if err != nil {
		t.Fatal(err)
	}

	l2, err := Open(dir, key, Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	l2.Append("local", Record{TS: "2026-08-10T00:01:00Z", Tool: "read_file", Decision: "allow"})
	l2.Close()

	if got := l2.latestSegment("local"); got != before {
		t.Errorf("resume started segment %d instead of continuing %d", got, before)
	}
	after, err := VerifyFile(l2.segPath("local", before), nil)
	if err != nil {
		t.Fatalf("resumed segment broken: %v", err)
	}
	if after.LastSeq <= head.LastSeq {
		t.Errorf("resume did not extend the last segment: %d -> %d", head.LastSeq, after.LastSeq)
	}
	if after.Decisions <= head.Decisions {
		t.Errorf("the resumed write landed somewhere else: %d -> %d decisions", head.Decisions, after.Decisions)
	}
}

// D14 part three: pruning is an operator act that declares itself. The
// property under test is not "files went away" — it is that what remains is
// still a chain a third party can verify, and that it says why it starts
// where it does.
func TestPruneDeclaresBeforeItDeletes(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"})
	if err != nil {
		t.Fatal(err)
	}
	l.maxSegment = 4096
	for range 400 {
		l.Append("local", Record{TS: "2026-08-10T00:00:00Z", Tool: "read_file", Decision: "allow"})
	}
	// Prune goes through the writer's queue, so it is ordered after every
	// append above; reading latestSegment from this goroutine beforehand would
	// race the writer and see a chain that has not been written yet.
	got, err := l.Prune(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want one pruned partition, got %+v", got)
	}
	segsBefore := len(got[0].Removed) + 2
	if segsBefore < 4 {
		t.Fatalf("need several segments to prune, got %d", segsBefore)
	}
	if got[0].ThroughHash == "" {
		t.Error("a declaration with no terminal hash is a claim nobody can check")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// The pruned files are gone, the survivors still verify, and the chain
	// admits where it starts and why.
	for _, n := range got[0].Removed {
		if _, err := os.Stat(l.segPath("local", n)); !os.IsNotExist(err) {
			t.Errorf("segment %d still present after prune", n)
		}
	}
	var declared bool
	for n := segsBefore - 1; n <= segsBefore; n++ {
		res, err := VerifyFile(l.segPath("local", n), nil)
		if err != nil {
			t.Fatalf("surviving segment %d does not verify: %v", n, err)
		}
		if n == segsBefore-1 && res.ContinuesFrom == "" {
			t.Error("the oldest surviving segment should still name the predecessor it no longer has")
		}
		if res.Pruned > 0 {
			declared = true
			if res.PrunedThroughSeq != got[0].ThroughSeq {
				t.Errorf("declaration says seq %d, prune reported %d", res.PrunedThroughSeq, got[0].ThroughSeq)
			}
		}
	}
	if !declared {
		t.Error("no retention record survived the prune — the deletion is now indistinguishable from tampering")
	}
}

// Keeping zero segments would delete the chain currently being written,
// including the record declaring the deletion.
func TestPruneRefusesToDeleteEverything(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"})
	defer l.Close()
	if _, err := l.Prune(0); err == nil {
		t.Fatal("keep=0 must be refused")
	}
}

// A prune with nothing to remove is a no-op, not an empty declaration: a
// retention record naming no removal would be a claim about nothing sitting
// permanently in the evidence.
func TestPruneOfAnUnrolledChainWritesNoRecord(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, dir+".key.pem", Identity{Tenant: "acme", Instance: "i1"})
	for range 5 {
		l.Append("local", Record{TS: "2026-08-10T00:00:00Z", Tool: "read_file", Decision: "allow"})
	}
	got, err := l.Prune(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("nothing to prune, but it reported %+v", got)
	}
	l.Close()
	res, err := VerifyFile(l.path("local"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pruned != 0 {
		t.Errorf("a no-op prune left %d retention records behind", res.Pruned)
	}
}
