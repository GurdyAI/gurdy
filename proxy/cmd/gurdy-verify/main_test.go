package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/GurdyAI/gurdy/proxy/internal/ledger"
)

// writeLedger produces a real signed export: n decisions across the named
// partitions, in a fresh directory.
func writeLedger(t *testing.T, parts ...string) string {
	t.Helper()
	dir := t.TempDir()
	l, err := ledger.Open(dir, filepath.Join(t.TempDir(), "key.pem"), ledger.Identity{Tenant: "test-tenant", Instance: "test-instance"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range parts {
		l.Append(p, ledger.Record{
			TS: "2026-07-25T00:00:00Z", TxnID: "T1", Tool: "read_file",
			Action: "mcp/tools_call", Decision: "allow", BundleVer: "v0",
		})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// exports lists the workload chains, excluding the _proxy lifecycle chain that
// every run produces — a test that tampers with "a partition" means a workload.
func exports(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no exports in %s: %v", dir, err)
	}
	return slices.DeleteFunc(files, func(f string) bool {
		return strings.HasPrefix(filepath.Base(f), ledger.ProxyPartition)
	})
}

// call runs the CLI exactly as a third party would and returns its contract:
// exit code plus stdout.
func call(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String()
}

// The happy path: a whole ledger directory verifies, and the chain-head
// checkpoint is printed (§5.5 — it is the truncation defense, so its absence
// would silently remove a control).
func TestVerifyDirectorySucceeds(t *testing.T) {
	dir := writeLedger(t, "acme/w1", "acme/w1", "acme/w2")
	code, out := call(t, dir)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	// Two workload chains plus the _proxy lifecycle chain, which every run
	// writes (§5.5) and a verifier must check like any other partition.
	if strings.Count(out, "OK    ") != 3 {
		t.Fatalf("want one OK line per partition:\n%s", out)
	}
	if !strings.Contains(out, "ended cleanly") {
		t.Fatalf("clean shutdown not reported — its absence is the crash signal:\n%s", out)
	}
	if !strings.Contains(out, "head: seq ") {
		t.Fatalf("chain-head checkpoint missing:\n%s", out)
	}
	if strings.Contains(out, "FAIL") {
		t.Fatalf("unexpected FAIL:\n%s", out)
	}
}

// A single export file is as valid an argument as a directory — a third party
// is often handed one partition, not the whole ledger.
func TestVerifySingleFileSucceeds(t *testing.T) {
	dir := writeLedger(t, "acme/w1")
	code, out := call(t, exports(t, dir)[0])
	if code != 0 || !strings.Contains(out, "OK    ") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

// The forged-tail attack: append fabricated decisions after the last batch
// signature with a correct seq and prev_hash. The chain link alone is
// recomputable by anyone, so only the signature boundary can reject this. A
// verifier that prints OK here is worse than no verifier at all.
func TestForgedUnsignedTailRejected(t *testing.T) {
	dir := writeLedger(t, "acme/w1", "acme/w1")
	path := exports(t, dir)[0]
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	last := lines[len(lines)-1]
	var tail struct {
		Seq uint64 `json:"seq"`
	}
	if err := json.Unmarshal(last, &tail); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(last)
	forged := fmt.Sprintf(`{"kind":"decision","seq":%d,"ts":"2026-01-01T00:00:00Z","tool":"exfiltrate",`+
		`"action":"mcp/tools_call","decision":"allow","prev_hash":"%x"}`, tail.Seq+1, h)
	if err := os.WriteFile(path, append(raw, []byte(forged+"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := call(t, path)
	if code != 1 {
		t.Fatalf("forged tail exited %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Fatalf("forged tail not reported:\n%s", out)
	}

	// The escape hatch exists for a live ledger mid-window, and must be an
	// explicit choice — never the default.
	if code, out := call(t, "-allow-unsigned-tail", path); code != 0 ||
		!strings.Contains(out, "accepted unsigned") {
		t.Fatalf("-allow-unsigned-tail: exit %d\n%s", code, out)
	}
}

// A header-only export has verified no decisions and carries no signature.
// Reporting that as success is a vacuous pass.
func TestHeaderOnlyExportFails(t *testing.T) {
	dir := writeLedger(t, "acme/w1")
	path := exports(t, dir)[0]
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := bytes.Cut(raw, []byte("\n"))
	if err := os.WriteFile(path, append(header, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := call(t, path); code != 1 {
		t.Fatalf("header-only export exited %d, want 1\n%s", code, out)
	}
}

// -h is a successful invocation, not a usage error.
func TestHelpExitsZero(t *testing.T) {
	if code, _ := call(t, "-h"); code != 0 {
		t.Fatalf("-h exited %d, want 0", code)
	}
}

// One bad partition among good ones must still fail the run: a per-file OK
// must never be mistaken for an overall pass. This is also the mutation drill
// at the CLI boundary (§8.3) — the corruption rewrites a field *value*, so the
// file stays valid JSON with consistent seq numbering and only the hash chain
// can catch it. A byte flip would also trip the JSON decoder, and would pass
// even with chain and signature checking removed entirely.
func TestOneBadPartitionFailsWholeRun(t *testing.T) {
	dir := writeLedger(t, "acme/w1", "acme/w2")
	files := exports(t, dir)
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"tool":"read_file"`), []byte(`"tool":"send_email"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("fixture changed: no tool field to tamper with")
	}
	if err := os.WriteFile(files[0], tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := call(t, dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "OK    ") {
		t.Fatalf("want both a FAIL and a surviving OK:\n%s", out)
	}
}

// Pinning is the recommended third-party mode: an attacker who rewrites an
// export can also rewrite the key embedded in its header, so the pinned key
// must be the one that decides. "key: pinned" in the output is the proof the
// pinned key actually reached VerifyFile rather than being parsed and dropped;
// rejection of a *wrong* pinned key is internal/ledger's TestPinnedKeyMismatchFails.
func TestPinnedKeyVerifies(t *testing.T) {
	dir := writeLedger(t, "acme/w1")
	path := exports(t, dir)[0]
	code, out := call(t, "-pubkey", pinFile(t, ledgerPubKey(t, path)), path)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "key: pinned") {
		t.Fatalf("did not report the key as pinned:\n%s", out)
	}
}

// Exit 2 is "the verifier could not run" and must stay distinct from 0 —
// conflating them turns a broken invocation into a silent pass.
func TestCannotRunExitsTwo(t *testing.T) {
	badPEM := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badPEM, []byte("not a pem file"), 0o644); err != nil {
		t.Fatal(err)
	}
	notAKey := filepath.Join(t.TempDir(), "rsa.pem")
	if err := os.WriteFile(notAKey, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: []byte("garbage"),
	}), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, args := range map[string][]string{
		"no arguments":     {},
		"unknown flag":     {"-nope", "x"},
		"missing key file": {"-pubkey", filepath.Join(t.TempDir(), "absent.pem"), "x"},
		"key not PEM":      {"-pubkey", badPEM, "x"},
		"PEM not a key":    {"-pubkey", notAKey, "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, out := call(t, args...); code != 2 {
				t.Fatalf("exit %d, want 2\n%s", code, out)
			}
		})
	}
}

// A path that yields no exports must fail rather than vacuously pass — "I
// verified nothing" reported as success is the worst possible output.
func TestNoExportsFails(t *testing.T) {
	for name, arg := range map[string]string{
		"empty directory": t.TempDir(),
		"missing path":    filepath.Join(t.TempDir(), "absent.jsonl"),
	} {
		t.Run(name, func(t *testing.T) {
			code, out := call(t, arg)
			if code != 1 {
				t.Fatalf("exit %d, want 1\n%s", code, out)
			}
			if !strings.Contains(out, "FAIL") {
				t.Fatalf("no FAIL reported:\n%s", out)
			}
		})
	}
}

// ledgerPubKey recovers the signing key a ledger embedded in its header, which
// is how an operator publishes it for pinning.
func ledgerPubKey(t *testing.T, export string) *ecdsa.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(export)
	if err != nil {
		t.Fatal(err)
	}
	var hdr struct {
		PubKey string `json:"pubkey"`
	}
	first, _, _ := bytes.Cut(raw, []byte("\n"))
	if err := json.Unmarshal(first, &hdr); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(hdr.PubKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PublicKey)
}

func pinFile(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pin.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersionFlagExitsZeroAndNamesTheBuild(t *testing.T) {
	// A verifier's own version is part of a verdict: an auditor repeating this
	// check months later needs to know which build reached it, and
	// docs/reproducible-builds.md tells them to rebuild the commit it names.
	// Exit 0 matters too — 2 means "broken invocation", and asking a tool what
	// it is must never look like misuse.
	var out, errOut bytes.Buffer
	if code := run([]string{"-version"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, want 0; stderr=%s", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "gurdy-verify") {
		t.Errorf("-version output does not name the binary: %q", got)
	}
	if !strings.Contains(got, runtime.Version()) {
		t.Errorf("-version omits the Go toolchain, which a reproduction needs: %q", got)
	}
	if errOut.Len() != 0 {
		t.Errorf("-version wrote to stderr: %q", errOut.String())
	}
}

// The seam check is the only place the chain-across-files claim can be tested:
// a segment verifies perfectly while everything before it is missing, so
// single-file verification cannot see any of this (§5.5 v0.8.7, D14).
func seg(segment int, first, last uint64, from, head string) segRef {
	return segRef{
		path: fmt.Sprintf("seg%d.jsonl", segment),
		res: &ledger.VerifyResult{
			Tenant: "acme", Workload: "w", InstanceID: "i1",
			Segment: segment, FirstSeq: first, LastSeq: last,
			ContinuesFrom: from, HeadHash: head,
		},
	}
}

func TestSeamAcceptsAWholeChain(t *testing.T) {
	got := seamProblems([]segRef{
		seg(1, 1, 10, "", "aaa"),
		seg(2, 11, 20, "aaa", "bbb"),
		seg(3, 21, 30, "bbb", "ccc"),
	})
	if len(got) != 0 {
		t.Fatalf("a sound chain must produce no findings: %v", got)
	}
}

// Order comes from the header, never the filename — so a shuffled argument
// order must reach the same verdict.
func TestSeamOrdersBySegmentNotByArgumentOrder(t *testing.T) {
	got := seamProblems([]segRef{
		seg(3, 21, 30, "bbb", "ccc"),
		seg(1, 1, 10, "", "aaa"),
		seg(2, 11, 20, "aaa", "bbb"),
	})
	if len(got) != 0 {
		t.Fatalf("segments arrived out of order and the check fell over: %v", got)
	}
}

func TestSeamRejectsAPredecessorItDoesNotFollow(t *testing.T) {
	got := seamProblems([]segRef{
		seg(1, 1, 10, "", "aaa"),
		seg(2, 11, 20, "SOMETHING-ELSE", "bbb"),
	})
	if len(got) != 1 || !strings.Contains(got[0], "not the same chain") {
		t.Fatalf("a segment following the wrong chain must be caught: %v", got)
	}
}

func TestSeamReportsAMissingMiddleSegment(t *testing.T) {
	got := seamProblems([]segRef{
		seg(1, 1, 10, "", "aaa"),
		seg(3, 21, 30, "bbb", "ccc"),
	})
	if len(got) != 1 || !strings.Contains(got[0], "missing from this export") {
		t.Fatalf("a hole in the middle must be reported: %v", got)
	}
}

func TestSeamReportsTwoFilesClaimingOneSegment(t *testing.T) {
	got := seamProblems([]segRef{
		seg(1, 1, 10, "", "aaa"),
		seg(2, 11, 20, "aaa", "bbb"),
		seg(2, 11, 20, "aaa", "zzz"),
	})
	if len(got) == 0 || !strings.Contains(got[0], "fork") {
		t.Fatalf("two files claiming one segment is a fork: %v", got)
	}
}

// The distinction the retention record exists for: a chain that starts at
// segment 5 is either authorised pruning or someone supplying only the part
// that suits them, and a third party must be able to tell which.
func TestSeamSeparatesDeclaredPruningFromAMissingBeginning(t *testing.T) {
	undeclared := seamProblems([]segRef{seg(5, 41, 50, "aaa", "eee")})
	if len(undeclared) != 1 || !strings.Contains(undeclared[0], "removed on purpose") {
		t.Fatalf("an unexplained missing beginning must fail: %v", undeclared)
	}

	declared := []segRef{seg(5, 41, 50, "aaa", "eee")}
	declared[0].res.Pruned = 1
	declared[0].res.PrunedThroughSeq = 40
	if got := seamProblems(declared); len(got) != 0 {
		t.Fatalf("a declared, signed pruning is operations, not tampering: %v", got)
	}
}

// The declaration has to cover the hole it excuses. A record pruning through
// seq 40 says nothing about a chain that starts at seq 900, and letting it
// pass would be the tidiest possible way to dress a partial handover up as
// retention.
func TestSeamRejectsARetentionRecordThatDoesNotReachTheGap(t *testing.T) {
	short := []segRef{seg(5, 900, 950, "aaa", "eee")}
	short[0].res.Pruned = 1
	short[0].res.PrunedThroughSeq = 40
	got := seamProblems(short)
	if len(got) != 1 || !strings.Contains(got[0], "only covers through seq 40") {
		t.Fatalf("an under-reaching retention record must not excuse the gap: %v", got)
	}
}

// The pruner appends its record to the chain's *current* segment, which is not
// the first surviving one — so a declaration found anywhere in the chain has
// to count, or every real prune would fail verification.
func TestSeamAcceptsARetentionRecordInALaterSegment(t *testing.T) {
	first := seg(5, 41, 50, "aaa", "eee")
	last := seg(6, 51, 60, "eee", "fff")
	last.res.Pruned = 1
	last.res.PrunedThroughSeq = 40
	if got := seamProblems([]segRef{first, last}); len(got) != 0 {
		t.Fatalf("the declaration lives in the segment being written, not the oldest: %v", got)
	}
}

// Two tenants' chains in one directory are two chains, not a broken one.
func TestSeamDoesNotJoinDifferentChains(t *testing.T) {
	a := seg(1, 1, 10, "", "aaa")
	b := seg(1, 1, 10, "", "zzz")
	b.res.Tenant = "other"
	if got := seamProblems([]segRef{a, b}); len(got) != 0 {
		t.Fatalf("separate chains were spliced together: %v", got)
	}
}
