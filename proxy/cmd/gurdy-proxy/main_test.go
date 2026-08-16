package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GurdyAI/gurdy/proxy/internal/ledger"
	"github.com/GurdyAI/gurdy/proxy/internal/policy"
	"github.com/GurdyAI/gurdy/proxy/internal/tis"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// syncBuffer makes the decision log safe to read while handler goroutines write.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

type harness struct {
	proxy       *httptest.Server
	tis         *tis.TIS
	led         *ledger.Ledger
	store       *policy.Store
	ledgerDir   string
	decisionLog *syncBuffer
	upstreamSaw *[]byte
	upstreamHdr *http.Header
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	var saw []byte
	var sawHdr http.Header
	// Guarded because these are written by every upstream handler goroutine.
	// Every test but the fan-out burst sends one request at a time, so two
	// handlers never overlapped and the race was latent — until a test sent a
	// thousand at once and -race found it immediately. A harness defect rather
	// than a proxy one, but a harness that races is a harness whose failures
	// get attributed to the code under test.
	var sawMu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hdr := r.Header.Clone()
		sawMu.Lock()
		saw, sawHdr = body, hdr
		sawMu.Unlock()
		w.Header().Set("X-Upstream", "yes")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
	}))
	t.Cleanup(upstream.Close)

	eval, err := policy.Load("test", policy.Starter)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tis.New("deploy-test", filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	led, err := ledger.Open(dir, filepath.Join(t.TempDir(), "key.pem"), ledger.Identity{Tenant: "test-tenant", Instance: "test-instance"})
	if err != nil {
		t.Fatal(err)
	}
	decisionLog := &syncBuffer{}
	target, _ := url.Parse(upstream.URL)
	store := policy.NewStore(eval)
	proxy := httptest.NewServer(Handler(target, store, identity, led, "test-tenant",
		slog.New(slog.NewJSONHandler(decisionLog, nil))))
	t.Cleanup(proxy.Close)
	return &harness{proxy: proxy, tis: identity, led: led, store: store, ledgerDir: dir,
		decisionLog: decisionLog, upstreamSaw: &saw, upstreamHdr: &sawHdr}
}

func slogTo(buf *syncBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

// ledgerFiles lists the *workload* partition exports written so far. Tests
// assert on partition count and content rather than on file names, so the
// (tenant, workload) key can change shape without rewriting every ledger test.
// The _proxy lifecycle chain is excluded: every run writes one, and it is not
// a workload (see proxyLedgerFile).
func (h *harness) ledgerFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(h.ledgerDir, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(files, func(f string) bool {
		return strings.HasPrefix(filepath.Base(f), ledger.ProxyPartition)
	})
}

// proxyLedgerFile returns the proxy-lifecycle chain (heartbeats, shutdown).
func (h *harness) proxyLedgerFile(t *testing.T) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(h.ledgerDir, ledger.ProxyPartition+"*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("want one _proxy chain, got %v", files)
	}
	return files[0]
}

// ledgerFile returns the sole partition export, failing if the traffic under
// test unexpectedly fanned out across chains.
func (h *harness) ledgerFile(t *testing.T) string {
	t.Helper()
	files := h.ledgerFiles(t)
	if len(files) != 1 {
		t.Fatalf("want exactly one partition, got %v", files)
	}
	return files[0]
}

func (h *harness) lastDecision(t *testing.T) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(h.decisionLog.String()), "\n")
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatalf("decision not JSON: %v: %s", err, lines[len(lines)-1])
	}
	return rec
}

const benignCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}`

const credReadCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/u/.ssh/id_rsa"}}}`

// Stage A gate (§8.2): proxied request/response byte-identical to direct
// baseline; a tools/call emits exactly one decision record.
func TestPassThroughByteIdentical(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
	if err != nil {
		t.Fatal(err)
	}
	respBody, _ := io.ReadAll(resp.Body)

	if string(*h.upstreamSaw) != credReadCall {
		t.Fatalf("upstream body mutated:\n got: %s\nwant: %s", *h.upstreamSaw, credReadCall)
	}
	if string(respBody) != `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}` {
		t.Fatalf("response mutated: %s", respBody)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Fatal("upstream header dropped")
	}
	if strings.Count(h.decisionLog.String(), `"msg":"decision"`) != 1 {
		t.Fatalf("want exactly one decision record: %s", h.decisionLog.String())
	}
	rec := h.lastDecision(t)
	if rec["decision"] != "flag" {
		t.Fatalf("credential read not flagged: %v", rec)
	}
}

// D4 (§4.3 step 6, §5.5): the response is a second chained record joined to
// the decision by call_id, and resp_hash is over the bytes the client actually
// received. A JSON-RPC batch shares one response envelope, so its calls share
// one hash — N response records, one per governed call.
func TestResponseRecordJoinsDecision(t *testing.T) {
	h := newHarness(t)
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/u/.ssh/id_rsa"}}},
	           {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/ok.txt"}}}]`
	resp, err := http.Post(h.proxy.URL, "application/json", strings.NewReader(batch))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := h.led.Close(); err != nil {
		t.Fatal(err)
	}

	decisions, responses := map[string]map[string]any{}, map[string]map[string]any{}
	raw, _ := os.ReadFile(h.ledgerFile(t))
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		json.Unmarshal([]byte(line), &rec)
		id, _ := rec["call_id"].(string)
		switch rec["kind"] {
		case "decision":
			decisions[id] = rec
		case "response":
			responses[id] = rec
		}
	}
	if len(decisions) != 2 || len(responses) != 2 {
		t.Fatalf("want 2 decisions and 2 responses, got %d/%d", len(decisions), len(responses))
	}
	want := fmt.Sprintf("%x", sha256.Sum256(body))
	for id, r := range responses {
		if _, ok := decisions[id]; !ok {
			t.Errorf("response %s joins no decision — an orphan record is worse than none", id)
		}
		if r["resp_hash"] != want {
			t.Errorf("resp_hash %v is not the hash of what the client read (%s)", r["resp_hash"], want)
		}
		if r["status"] != float64(200) || r["bytes"] != float64(len(body)) {
			t.Errorf("response attrs wrong: %v", r)
		}
		if r["req_hash"] != nil || r["tool"] != nil {
			t.Errorf("response record carries decision fields: %v", r)
		}
	}
}

// Wrapping the ResponseWriter to hash it must not turn a streamed response
// into a buffered one: monitor mode may not delay traffic (ADR-3), and an SSE
// stream held until completion is the loudest possible way to break that.
func TestStreamedResponseNotBuffered(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: first\n\n"))
		w.(http.Flusher).Flush()
		<-release // hold the response open, as a live stream would
		w.Write([]byte("data: second\n\n"))
	}))
	defer upstream.Close()

	h := newHarness(t)
	target, _ := url.Parse(upstream.URL)
	proxy := httptest.NewServer(Handler(target, h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog)))
	defer proxy.Close()
	// httptest.Server.Close blocks on the in-flight request, and on the failure
	// path that request is the one parked at <-release. Releasing it before any
	// Close — including from the timeout branch below — turns what would be a
	// 10-minute CI hang into a test failure with a message.
	defer close(release)

	// The deadline covers headers *and* the first chunk: a wrapper that hides
	// http.Flusher withholds both, and the client would otherwise wait for a
	// stream deliberately held open forever.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(proxy.URL, "application/json", strings.NewReader(benignCall))
	if err != nil {
		t.Fatalf("no response within 2s — the hashing writer is buffering the stream: %v", err)
	}
	defer resp.Body.Close()
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatalf("first chunk withheld — the hashing writer is buffering the stream: %v", err)
	}
	if string(first) != "data: first\n\n" {
		t.Fatalf("streamed chunk mutated: %q", first)
	}
}

// A wrapper that hides http.Hijacker turns every protocol upgrade into a 502:
// the reverse proxy cannot switch protocols and answers with an error instead.
// Inspection machinery breaking the traffic it exists to watch is the one
// thing monitor mode may never do (NFR-3, ADR-3). The tunnel's bytes are
// invisible after the switch, so the response record must omit resp_hash and
// bytes rather than report a whole tunnel as zero.
func TestProtocolUpgradeNotBroken(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("upstream hijack: %v", err)
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: gurdy-test\r\nConnection: Upgrade\r\n\r\nTUNNEL")
		buf.Flush()
	}))
	defer upstream.Close()

	h := newHarness(t)
	target, _ := url.Parse(upstream.URL)
	proxy := httptest.NewServer(Handler(target, h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog)))
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodPost, proxy.URL, strings.NewReader(benignCall))
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "gurdy-test")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade broken by the response wrapper: got %d, want 101", resp.StatusCode)
	}
	tunnel, _ := io.ReadAll(resp.Body)
	if string(tunnel) != "TUNNEL" {
		t.Fatalf("tunnel bytes mutated: %q", tunnel)
	}
	resp.Body.Close()

	// The response record is written after ServeHTTP returns, which for a
	// tunnel is after the connection drops — and httptest.Server.Close does
	// NOT wait for a hijacked handler, so closing the ledger immediately would
	// race the write and drop it. Wait for the record instead: the writer
	// flushes on its tick, so this converges in well under the deadline.
	proxy.Close()
	var raw []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		raw, _ = os.ReadFile(h.ledgerFile(t))
		if strings.Contains(string(raw), `"kind":"response"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := h.led.Close(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(h.ledgerFile(t))
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		json.Unmarshal([]byte(line), &rec)
		if rec["kind"] != "response" {
			continue
		}
		found = true
		if rec["resp_hash"] != nil || rec["bytes"] != nil || rec["status"] != nil {
			t.Errorf("hijacked response claims content it never saw: %v", rec)
		}
		attrs, _ := rec["resource_attrs"].(map[string]any)
		if attrs["reason"] == nil {
			t.Errorf("uncaptured response gives no reason — a blank record is a mystery: %v", rec)
		}
	}
	if !found {
		t.Error("no response record for an upgraded call")
	}
}

// Stage B gate (§8.2): SDK-minted txn -> call assertion -> provenance visible
// in the decision record, including a 3-deep sub-agent chain.
func TestAssertedProvenanceInDecision(t *testing.T) {
	h := newHarness(t)
	scope := tis.Scope{Compartments: []string{"*"}, ResourceTypes: []string{"*"},
		Actions: []string{"*"}, Purpose: "ticket-9"}
	root, err := h.tis.MintTxn("orchestrator", "alice@example.com", scope, "test", 0)
	if err != nil {
		t.Fatal(err)
	}
	mid, err := h.tis.DeriveChildTxn(root, "researcher", scope)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := h.tis.DeriveChildTxn(mid, "fetcher", scope)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(credReadCall))
	req.Header.Set(TxnHeader, leaf)
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}

	rec := h.lastDecision(t)
	// The claim is recorded, and it is recorded *as a claim*: the observed
	// principal is still the proxy's own and is not overwritten by it (§5.5).
	if rec["assertion_status"] != "valid" || rec["asserted_principal"] != "fetcher" {
		t.Fatalf("asserted principal lost: %v", rec)
	}
	if rec["principal"] != "svc:host:127.0.0.1" || rec["principal_tier"] != "attested-coarse" {
		t.Fatalf("assertion overwrote the observed principal: %v", rec)
	}
	lineage, _ := rec["lineage"].([]any)
	if len(lineage) != 3 || lineage[0] != "orchestrator" || lineage[2] != "fetcher" {
		t.Fatalf("lineage chain wrong: %v", rec["lineage"])
	}
	if rec["txn_id"] == "" || rec["assertion_jti"] == "" {
		t.Fatalf("identity fields empty: %v", rec)
	}
}

// SDK-absent traffic degrades to an attested-coarse service principal, never
// a bare orphan (§5.2); repeated calls reuse one auto-minted txn (§4.3).
func TestCoarsePrincipalWhenNoSDK(t *testing.T) {
	h := newHarness(t)
	http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
	first := h.lastDecision(t)
	if first["principal_tier"] != "attested-coarse" {
		t.Fatalf("want attested-coarse: %v", first)
	}
	if !strings.HasPrefix(first["principal"].(string), "svc:") {
		t.Fatalf("coarse principal shape: %v", first["principal"])
	}
	http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
	second := h.lastDecision(t)
	if first["txn_id"] != second["txn_id"] {
		t.Fatal("auto-minted txn not reused for same coarse principal")
	}
	if first["assertion_jti"] == second["assertion_jti"] {
		t.Fatal("call assertions must be single-use, got identical jti")
	}
}

// A forged/garbage Gurdy-Txn header is recorded as invalid-assertion, and the
// call still degrades to coarse identity — traffic is never dropped.
func TestInvalidAssertionFlaggedNotDropped(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(credReadCall))
	req.Header.Set(TxnHeader, "eyJhbGciOiJFUzI1NiJ9.garbage.sig")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("traffic dropped: %d", resp.StatusCode)
	}
	rec := h.lastDecision(t)
	if rec["assertion_status"] != "invalid" {
		t.Fatalf("want invalid assertion_status: %v", rec)
	}
	// A rejected claim must leave nothing behind that reads like a verified
	// one — no asserted principal, no lineage (§5.5).
	if rec["asserted_principal"] != "" || rec["lineage"] != nil {
		t.Fatalf("invalid assertion leaked asserted fields: %v", rec)
	}
	if rec["principal"] != "svc:host:127.0.0.1" || rec["principal_tier"] != "attested-coarse" {
		t.Fatalf("observed principal lost on invalid assertion: %v", rec)
	}
}

// Stage D gate (§8.2): traffic through the proxy lands in the ledger, the
// export verifies offline, and the record carries full provenance + req_hash.
func TestLedgerEndToEnd(t *testing.T) {
	h := newHarness(t)
	scope := tis.Scope{Compartments: []string{"*"}, ResourceTypes: []string{"*"},
		Actions: []string{"*"}, Purpose: "ticket-9"}
	txn, _ := h.tis.MintTxn("orchestrator", "alice@example.com", scope, "test", 0)
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(credReadCall))
	req.Header.Set(TxnHeader, txn)
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))

	if err := h.led.Close(); err != nil {
		t.Fatal(err)
	}
	path := h.ledgerFile(t)
	res, err := ledger.VerifyFile(path, nil)
	if err != nil {
		t.Fatalf("export failed verification: %v", err)
	}
	if res.Decisions != 2 || res.Uncovered != 0 {
		t.Fatalf("result: %+v", res)
	}

	raw, _ := os.ReadFile(path)
	var asserted map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		json.Unmarshal([]byte(line), &rec)
		if rec["kind"] == "decision" && rec["assertion_status"] == "valid" {
			asserted = rec
		}
	}
	if asserted == nil {
		t.Fatal("asserted decision missing from ledger")
	}
	if asserted["asserted_human_actor"] != "alice@example.com" || asserted["decision"] != "flag" ||
		asserted["req_hash"] == "" || asserted["txn_id"] == "" {
		t.Fatalf("provenance incomplete: %v", asserted)
	}
}

// A JSON-RPC batch array must not let tool calls dodge logging.
func TestBatchCallsAllLogged(t *testing.T) {
	h := newHarness(t)
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/u/.ssh/id_rsa"}}},
	           {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/ok.txt"}}}]`
	if _, err := http.Post(h.proxy.URL, "application/json", strings.NewReader(batch)); err != nil {
		t.Fatal(err)
	}
	logged := h.decisionLog.String()
	if strings.Count(logged, `"msg":"decision"`) != 2 {
		t.Fatalf("batch calls escaped logging: %s", logged)
	}
	if !strings.Contains(logged, `"decision":"flag"`) || !strings.Contains(logged, `"decision":"allow"`) {
		t.Fatalf("batch decisions wrong: %s", logged)
	}
}

// A body over the inspection limit is forwarded intact and logged
// indeterminate — never dropped, never inspected into an OOM.
func TestOversizeBodyForwardedIndeterminate(t *testing.T) {
	h := newHarness(t)
	big := bytes.Repeat([]byte("x"), maxInspect+100)
	resp, err := http.Post(h.proxy.URL, "application/octet-stream", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("oversize body dropped: %d", resp.StatusCode)
	}
	if len(*h.upstreamSaw) != len(big) {
		t.Fatalf("upstream got %d bytes, want %d", len(*h.upstreamSaw), len(big))
	}
	if !strings.Contains(h.decisionLog.String(), `"decision":"indeterminate"`) {
		t.Fatalf("oversize body not recorded: %s", h.decisionLog.String())
	}
}

// Stage C gate (§8.2): decisions carry the correct bundle_ver across a
// hot-reload mid-traffic, and rollback reinstates the previous bundle —
// under concurrent load (run with -race).
func TestHotReloadMidTraffic(t *testing.T) {
	h := newHarness(t)
	v2, err := policy.Load("pack@2.0.0", []byte(`@id("allow-all-v2") permit (principal, action, resource);`))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
		}
	}()
	for h.decisionLog.Len() == 0 { // ensure some traffic ran under v1
		time.Sleep(time.Millisecond)
	}
	h.store.Swap(v2) // hot-swap while traffic flows
	<-done
	// Guarantee post-swap decisions even if the swap landed late.
	http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))

	logged := h.decisionLog.String()
	if !strings.Contains(logged, `"bundle_ver":"test"`) || !strings.Contains(logged, `"bundle_ver":"pack@2.0.0"`) {
		t.Fatal("expected decisions under both bundle versions across the reload")
	}
	// Every decision under v2 must reflect v2 policy (allow — v2 has no
	// credential flag), and every flag must be attributed to the old bundle.
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		if strings.Contains(line, `"decision":"flag"`) && !strings.Contains(line, `"bundle_ver":"test"`) {
			t.Fatalf("flag decision attributed to wrong bundle: %s", line)
		}
		if strings.Contains(line, `"bundle_ver":"pack@2.0.0"`) && !strings.Contains(line, `"decision":"allow"`) {
			t.Fatalf("v2 decision not evaluated by v2 policy: %s", line)
		}
	}

	if _, err := h.store.Rollback(); err != nil {
		t.Fatal(err)
	}
	h.decisionLog.Reset()
	http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
	rec := h.lastDecision(t)
	if rec["bundle_ver"] != "test" || rec["decision"] != "flag" {
		t.Fatalf("rollback did not reinstate previous bundle: %v", rec)
	}
}

// Admin API: reload swaps a real bundle in, a broken bundle leaves the
// current one in force (keep-last-good), rollback walks history.
func TestAdminReloadAndRollback(t *testing.T) {
	h := newHarness(t)
	policyPath := filepath.Join(t.TempDir(), "local.cedar")
	os.WriteFile(policyPath, []byte(`@id("v2") permit (principal, action, resource);`), 0o644)
	admin := httptest.NewServer(adminMux(h.store, h.led, h.tis, policyPath))
	defer admin.Close()

	post := func(path string) (int, string) {
		resp, err := http.Post(admin.URL+path, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, body := post("/policy/reload"); code != http.StatusOK || !strings.Contains(body, "file:") {
		t.Fatalf("reload: %d %s", code, body)
	}

	os.WriteFile(policyPath, []byte("permit(broken"), 0o644)
	code, body := post("/policy/reload")
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "bundle_unchanged") {
		t.Fatalf("broken bundle: %d %s", code, body)
	}
	cur, _ := h.store.Versions()
	if !strings.HasPrefix(cur, "file:") {
		t.Fatalf("broken reload disturbed bundle in force: %q", cur)
	}

	if code, _ := post("/policy/rollback"); code != http.StatusOK {
		t.Fatalf("rollback: %d", code)
	}
	if cur, _ = h.store.Versions(); cur != "test" {
		t.Fatalf("rollback landed on %q, want original", cur)
	}
	if code, _ := post("/policy/rollback"); code != http.StatusConflict {
		t.Fatalf("empty-history rollback should 409, got %d", code)
	}
}

// Browser-originated requests must not reach the admin API (CSRF / DNS
// rebinding); plain CLI requests must.
func TestAdminRejectsCrossOrigin(t *testing.T) {
	h := newHarness(t)
	admin := httptest.NewServer(adminMux(h.store, h.led, h.tis, ""))
	defer admin.Close()

	req, _ := http.NewRequest(http.MethodPost, admin.URL+"/policy/rollback", nil)
	req.Header.Set("Origin", "http://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST accepted: %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, admin.URL+"/policy/rollback", nil)
	req.Host = "attacker.example" // DNS rebinding shape
	if resp, err = http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign-Host request accepted: %d", resp.StatusCode)
	}

	// No Origin, localhost Host: normal CLI call goes through (409: empty history).
	if resp, err = http.Post(admin.URL+"/policy/rollback", "", nil); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("plain localhost request blocked: %d", resp.StatusCode)
	}
}

// NFR-8: the decision span joins the agent's own trace — same trace ID as the
// inbound traceparent, parented on the agent's span, decision in attributes.
func TestDecisionSpanJoinsAgentTrace(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	h := newHarness(t)
	const agentTrace = "0af7651916cd43dd8448eb211c80319c"
	const agentSpan = "b7ad6b7169203331"
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(credReadCall))
	req.Header.Set("traceparent", "00-"+agentTrace+"-"+agentSpan+"-01")
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 || spans[0].Name != "gurdy.decision" {
		t.Fatalf("want one gurdy.decision span, got %v", spans)
	}
	s := spans[0]
	if s.SpanContext.TraceID().String() != agentTrace {
		t.Fatalf("span did not join agent trace: %s", s.SpanContext.TraceID())
	}
	if s.Parent.SpanID().String() != agentSpan {
		t.Fatalf("span not parented on agent span: %s", s.Parent.SpanID())
	}
	attrs := map[string]string{}
	for _, kv := range s.Attributes {
		attrs[string(kv.Key)] = kv.Value.Emit()
	}
	if attrs["gurdy.decision"] != "flag" || attrs["gurdy.bundle_ver"] != "test" {
		t.Fatalf("span attributes: %v", attrs)
	}
}

// Stage E gate (§8.2): the full demo scenario — scripted dangerous tool calls
// (secret read, destructive fs op, egress to an unlisted host) produce the
// expected flags with full provenance, and the ledger verifies.
func TestDemoScenarioDangerousCallsFlagged(t *testing.T) {
	h := newHarness(t)
	// Demo bundle: starter policies + the egress-allowlist policy (the
	// agent-security pack shape; too noisy for bare starter defaults).
	demo := string(policy.Starter) + `
@id("flag-egress-unlisted-host")
forbid (principal, action == Action::"mcp/tools_call", resource)
when { context has resource_host && !(context.resource_host == "api.allowed.example") };
`
	ev, err := policy.Load("demo-v1", []byte(demo))
	if err != nil {
		t.Fatal(err)
	}
	h.store.Swap(ev)

	scope := tis.Scope{Compartments: []string{"*"}, ResourceTypes: []string{"*"},
		Actions: []string{"*"}, Purpose: "demo"}
	root, _ := h.tis.MintTxn("orchestrator", "alice@example.com", scope, "demo-v1", 0)
	worker, err := h.tis.DeriveChildTxn(root, "worker", scope)
	if err != nil {
		t.Fatal(err)
	}

	script := []struct {
		call     string
		decision string
		policy   string
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/u/.ssh/id_rsa"}}}`, "flag", "flag-credential-read"},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/workspace/data"}}}`, "flag", "flag-destructive-op"},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http_get","arguments":{"url":"https://exfil.example/drop"}}}`, "flag", "flag-egress-unlisted-host"},
		{`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"http_get","arguments":{"url":"https://api.allowed.example/v1"}}}`, "allow", "allow-all-monitor"},
		{`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}`, "allow", "allow-all-monitor"},
	}
	for i, s := range script {
		req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(s.call))
		req.Header.Set(TxnHeader, worker)
		if _, err := http.DefaultClient.Do(req); err != nil {
			t.Fatal(err)
		}
		rec := h.lastDecision(t)
		if rec["decision"] != s.decision {
			t.Fatalf("call %d: decision %v, want %s (%v)", i, rec["decision"], s.decision, rec)
		}
		ids, _ := rec["policy_ids"].([]any)
		if len(ids) == 0 || ids[0] != s.policy {
			t.Fatalf("call %d: policy_ids %v, want %s", i, rec["policy_ids"], s.policy)
		}
		lineage, _ := rec["lineage"].([]any)
		if rec["assertion_status"] != "valid" || len(lineage) != 2 {
			t.Fatalf("call %d: provenance incomplete: %v", i, rec)
		}
	}

	if err := h.led.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := ledger.VerifyFile(h.ledgerFile(t), nil)
	if err != nil || res.Decisions != len(script) {
		t.Fatalf("ledger: %+v err=%v", res, err)
	}
}

// ADR-6: chains are partitioned per (tenant, workload) from v1. Two workloads
// under one tenant get two independently sequenced, independently verifiable
// chains — not one interleaved chain that serializes every writer.
func TestPartitionPerWorkload(t *testing.T) {
	h := newHarness(t)
	// Same gateway, two workloads: the HTTP client (a loopback address) and a
	// stdio-shim child. Both route through decideCall.
	http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
	g := newGateway(h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog))
	if err := runShim(g, []string{"cat"}, strings.NewReader(credReadCall+"\n"), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := h.led.Close(); err != nil {
		t.Fatal(err)
	}

	files := h.ledgerFiles(t)
	if len(files) != 2 {
		t.Fatalf("want one chain per workload, got %v", files)
	}
	for _, f := range files {
		if !strings.HasPrefix(filepath.Base(f), "test-tenant") {
			t.Fatalf("partition %s not keyed by tenant", f)
		}
		// Each chain verifies standalone: seq restarts at 1 with its own
		// header and batch signature, so one partition is a complete export.
		res, err := ledger.VerifyFile(f, nil)
		if err != nil {
			t.Fatalf("partition %s does not verify independently: %v", f, err)
		}
		if res.Decisions != 1 {
			t.Fatalf("partition %s: want 1 decision, got %+v", f, res)
		}
	}
}

// Non-tool-call and non-JSON traffic must pass through undisturbed, no decision.
func TestNonToolCallPassesQuietly(t *testing.T) {
	h := newHarness(t)
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`not json at all`,
	} {
		resp, err := http.Post(h.proxy.URL, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("body %q: status %d", body, resp.StatusCode)
		}
	}
	if h.decisionLog.Len() != 0 {
		t.Fatalf("unexpected decision records: %s", h.decisionLog.String())
	}
}

// Gurdy-Txn is a bearer credential for the whole transaction: an upstream tool
// server that receives one can mint call assertions in the agent's name. The
// proxy consumes it and must not pass it on — while still deciding on it, so
// this cannot pass by the header being ignored altogether.
func TestTxnHeaderNotForwardedUpstream(t *testing.T) {
	h := newHarness(t)
	txn, err := h.tis.MintTxn("agent-x", "alice",
		tis.Scope{Compartments: []string{"*"}, ResourceTypes: []string{"*"},
			Actions: []string{"*"}, Purpose: "*"}, "v0", 0)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(credReadCall))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(TxnHeader, txn)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := h.upstreamHdr.Get(TxnHeader); got != "" {
		t.Fatalf("transaction token leaked to upstream: %q", got)
	}
	// The proxy still used it: the decision carries the asserted agent, not
	// the coarse fallback principal.
	rec := h.lastDecision(t)
	if rec["asserted_principal"] != "agent-x" {
		t.Fatalf("header was stripped without being used: %v", rec)
	}
}

// The end-to-end form of §5.5's rule: whatever an agent puts in its own token,
// Cedar's principal is the one the proxy observed. An agent that could name
// its own policy principal could name one no rule forbids, which under local
// enforce (ADR-14) is an authorization bypass rather than a reporting lie.
func TestPolicyEvaluatesObservedPrincipalNotAsserted(t *testing.T) {
	h := newHarness(t)
	ev, err := policy.Load("split-test", []byte(`
@id("allow-all") permit (principal, action, resource);

// Would fire only if the agent's self-chosen name reached Cedar as principal.
@id("forbid-asserted-name")
forbid (principal == Agent::"quarantined-agent", action, resource);

// The supported way to act on an agent-side claim: read it from context, and
// gate on the assertion having verified.
@id("forbid-asserted-name-via-context")
forbid (principal, action, resource) when {
    context has asserted_principal &&
    context.asserted_principal == "quarantined-agent" &&
    context.assertion_status == "valid"
};`))
	if err != nil {
		t.Fatal(err)
	}
	h.store.Swap(ev)

	scope := tis.Scope{Compartments: []string{"*"}, ResourceTypes: []string{"*"},
		Actions: []string{"*"}, Purpose: "*"}
	txn, err := h.tis.MintTxn("quarantined-agent", "mallory", scope, "split-test", 0)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(benignCall))
	req.Header.Set(TxnHeader, txn)
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}

	rec := h.lastDecision(t)
	ids, _ := rec["policy_ids"].([]any)
	var got []string
	for _, id := range ids {
		got = append(got, id.(string))
	}
	if slices.Contains(got, "forbid-asserted-name") {
		t.Fatalf("asserted name reached Cedar as the request principal: %v", rec)
	}
	if !slices.Contains(got, "forbid-asserted-name-via-context") {
		t.Fatalf("asserted name unreachable from policy context: %v", rec)
	}
}

// A forged token riding a body that defeats parsing must still be recorded as
// a forged token. Malformed-MCP evasion (§8.4) is precisely the attempt to buy
// silence on one axis by breaking another.
func TestIndeterminateStillClassifiesAssertion(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":123}}`))
	req.Header.Set(TxnHeader, "eyJhbGciOiJFUzI1NiJ9.garbage.sig")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	rec := h.lastDecision(t)
	if rec["decision"] != "indeterminate" {
		t.Fatalf("want indeterminate: %v", rec)
	}
	if rec["assertion_status"] != "invalid" {
		t.Fatalf("forged assertion unrecorded on an indeterminate call: %v", rec)
	}
}

// decision / policy_mode / action_applied are three separate facts (§4.2) and
// the record has to keep them apart: a policy that concluded "block" while the
// traffic was forwarded is a shadow observation, and reading it as an
// enforcement claim would be the most damaging misreading of this evidence.
// Everything this build produces is monitor + forwarded — the assertion that
// matters is that no path leaves the trio blank or inconsistent.
func TestDecisionModeAndActionRecordedSeparately(t *testing.T) {
	h := newHarness(t)
	blocking, err := policy.Load("shadow@1", []byte(`
@id("would-block") @enforce_action("block") @on_error("closed")
forbid (principal, action, resource) when { context has resource_path && context.resource_path like "*/.ssh/*" };
@id("allow-rest") permit (principal, action, resource);`))
	if err != nil {
		t.Fatal(err)
	}
	h.store.Swap(blocking)

	// One call each: shadow-blocked, allowed, and uninspectable (fail-open).
	http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
	// action_applied=forwarded has to be true of the wire, not just of the
	// record: a "would have blocked" call is still delivered (ADR-3), and the
	// day an actuator makes that false the record must change with it.
	if string(*h.upstreamSaw) != credReadCall {
		t.Fatalf("shadow-blocked call did not reach upstream intact: %q", *h.upstreamSaw)
	}
	http.Post(h.proxy.URL, "application/json", strings.NewReader(benignCall))
	http.Post(h.proxy.URL, "application/octet-stream", bytes.NewReader(bytes.Repeat([]byte("x"), maxInspect+1)))
	if err := h.led.Close(); err != nil {
		t.Fatal(err)
	}

	want := map[string][2]string{ // decision -> {action_applied, fail_mode_applied}
		"block":         {"forwarded", ""},
		"allow":         {"forwarded", ""},
		"indeterminate": {"failed-open", "open"},
	}
	seen := map[string]bool{}
	raw, _ := os.ReadFile(h.ledgerFile(t))
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		json.Unmarshal([]byte(line), &rec)
		if rec["kind"] != "decision" {
			continue
		}
		d, _ := rec["decision"].(string)
		w, ok := want[d]
		if !ok {
			t.Fatalf("unexpected decision %q: %v", d, rec)
		}
		seen[d] = true
		if rec["policy_mode"] != "monitor" {
			t.Errorf("%s: policy_mode %v, want monitor — nothing here can enforce", d, rec["policy_mode"])
		}
		if rec["action_applied"] != w[0] {
			t.Errorf("%s: action_applied %v, want %s", d, rec["action_applied"], w[0])
		}
		if fm, _ := rec["fail_mode_applied"].(string); fm != w[1] {
			// on_error("closed") above is declared but unhonorable in monitor
			// mode; the record must say what was applied, not what was asked.
			t.Errorf("%s: fail_mode_applied %q, want %q", d, fm, w[1])
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("missing decisions: saw %v", seen)
	}
}

// D7 (§7): a coverage gap must be visible to the operator *today*, not only to
// whoever reads the export later. /health reports the run's findings and flips
// to degraded — which never means traffic stopped, only that this run recorded
// less than it saw.
func TestHealthReportsCoverageGaps(t *testing.T) {
	h := newHarness(t)
	admin := httptest.NewServer(adminMux(h.store, h.led, h.tis, ""))
	defer admin.Close()

	health := func() map[string]any {
		resp, err := http.Get(admin.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		return body
	}

	if got := health(); got["status"] != "ok" {
		t.Fatalf("clean run should not report degraded: %v", got)
	}
	h.led.RecordIdentityGap("test-tenant/host:127.0.0.1")

	got := health()
	if got["status"] != "degraded" {
		t.Errorf("identity gap did not reach /health: %v", got)
	}
	cov, _ := got["coverage"].(map[string]any)
	if cov["identity_failed"] != float64(1) {
		t.Errorf("coverage counters wrong: %v", cov)
	}
}

// v0.8.4: the model call is an action in the same ledger, in the same chain,
// under the same identity as the agent's tool calls. That joint record is the
// point — neither an application-layer LLM log nor a tool-only proxy can
// produce it, because neither sees both halves under one principal.
func TestModelCallGovernedInSameChain(t *testing.T) {
	h := newHarness(t)
	modelCall := `{"model":"claude-opus-4-6","max_tokens":512,` +
		`"messages":[{"role":"user","content":"read my notes"}]}`

	// One task: a tool call, then the model call it feeds.
	if _, err := http.Post(h.proxy.URL, "application/json", strings.NewReader(benignCall)); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, h.proxy.URL+"/v1/messages", strings.NewReader(modelCall))
	req.Header.Set("Content-Type", "application/json")
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	if err := h.led.Close(); err != nil {
		t.Fatal(err)
	}

	var actions []string
	var llm map[string]any
	raw, _ := os.ReadFile(h.ledgerFile(t))
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		json.Unmarshal([]byte(line), &rec)
		if rec["kind"] != "decision" {
			continue
		}
		actions = append(actions, rec["action"].(string))
		if rec["action"] == "llm/completion" {
			llm = rec
		}
	}
	if !slices.Equal(actions, []string{"mcp/tools_call", "llm/completion"}) {
		t.Fatalf("tool call and model call are not both governed in one chain: %v", actions)
	}
	if llm["tool"] != "claude-opus-4-6" || llm["principal"] == "" || llm["req_hash"] == "" {
		t.Fatalf("model call record incomplete: %v", llm)
	}
	attrs, _ := llm["resource_attrs"].(map[string]any)
	if attrs["model"] != "claude-opus-4-6" || attrs["max_tokens"] != "512" {
		t.Errorf("model metadata missing: %v", attrs)
	}
	// Metadata only: the prompt itself must never reach the ledger (NFR-7).
	if strings.Contains(string(raw), "read my notes") {
		t.Error("prompt content leaked into the export")
	}
}

// The destination is where the request goes, not the Host header the client
// sent to the proxy. Deriving the provider from the proxy's own hostname would
// name the wrong end of the hop — and "which provider received this prompt" is
// the whole point of the attribute.
func TestModelProviderIsTheDestinationNotTheProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	h := newHarness(t)
	target, _ := url.Parse(upstream.URL)
	proxy := httptest.NewServer(Handler(target, h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog)))
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/messages",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"x"}]}`))
	req.Host = "api.anthropic.com" // the client claims a provider the hop does not go to
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	rec := h.lastDecision(t)
	if rec["action"] != "llm/completion" {
		t.Fatalf("model call not governed: %v", rec)
	}
	// The upstream here is a local httptest server, so the honest answer is
	// "local" — never "anthropic", which is only what the header claimed.
	if got := rec["resource"]; got != "local/m" {
		t.Errorf("resource %v — provider taken from the client's Host header, not the destination", got)
	}
}

// The Act stage exists as an object so "this build cannot block" is one thing
// a reader can find, rather than an absence spread across two transports. The
// seam is what makes Phase 2 an addition instead of a simultaneous refactor —
// so the test is that the seam is actually consulted, and that monitor mode
// answers the same way for every decision it can reach.
func TestActuatorSeamIsConsulted(t *testing.T) {
	for _, d := range []policy.Decision{policy.Allow, policy.Flag, policy.Block, policy.Indeterminate} {
		plan := monitorActuator{}.Plan(d)
		if !plan.Forward {
			t.Fatalf("%s: monitor mode planned not to forward — ADR-3 says nothing here may stop traffic", d)
		}
		if plan.Durable {
			t.Errorf("%s: monitor mode required a synchronous record; that is the enforce path's cost", d)
		}
		want := ledger.ActionForwarded
		if d == policy.Indeterminate {
			want = ledger.ActionFailedOpen
		}
		if plan.Applied != want {
			t.Errorf("%s: action_applied %q, want %q", d, plan.Applied, want)
		}
	}

	// And the gateway must actually route through it: a gateway built without
	// an Act stage would forward everything while looking like it had consulted
	// a policy, which is the confusion the interface exists to prevent.
	h := newHarness(t)
	g := newGateway(h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog))
	if g.act == nil {
		t.Fatal("newGateway produced a gateway with no Act stage")
	}
}

// Retention is an operator act with a signed record behind it (D14), and the
// endpoint that performs it deletes evidence — so what is under test is that
// it refuses nonsense, reports what it did, and never becomes automatic.
func TestAdminPruneIsExplicitAndReportsWhatItRemoved(t *testing.T) {
	h := newHarness(t)
	admin := httptest.NewServer(adminMux(h.store, h.led, h.tis, ""))
	defer admin.Close()

	post := func(path string) (int, string) {
		resp, err := http.Post(admin.URL+path, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// Nonsense is refused rather than interpreted. keep=0 would delete the
	// chain being written, including the record declaring the deletion.
	for _, bad := range []string{"?keep=0", "?keep=-3", "?keep=nope"} {
		if code, body := post("/retention/prune" + bad); code != http.StatusBadRequest {
			t.Errorf("keep%s: want 400, got %d %s", bad, code, body)
		}
	}

	// An unrolled chain has nothing to prune, and says so with an empty list
	// rather than inventing a retention record about nothing.
	http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
	code, body := post("/retention/prune?keep=4")
	if code != http.StatusOK {
		t.Fatalf("prune: %d %s", code, body)
	}
	var got struct {
		Keep   int              `json:"keep"`
		Pruned []map[string]any `json:"pruned"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("prune response not JSON: %v: %s", err, body)
	}
	if got.Keep != 4 {
		t.Errorf("keep not echoed back: %s", body)
	}
	if len(got.Pruned) != 0 {
		t.Errorf("nothing should have been pruned from an unrolled chain: %s", body)
	}
}

// The admin API's key surface (§5.2). /jwks is the one route here a third
// party has reason to read, so it must expose the public halves and nothing
// else; /keys/rotate is the drill and incident path the ≤24h timer cannot
// serve on demand (§8.3).
func TestAdminJWKSAndRotate(t *testing.T) {
	h := newHarness(t)
	admin := httptest.NewServer(adminMux(h.store, h.led, h.tis, ""))
	defer admin.Close()

	get := func(path string) (int, string) {
		resp, err := http.Get(admin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	code, body := get("/jwks")
	if code != http.StatusOK {
		t.Fatalf("GET /jwks = %d: %s", code, body)
	}
	var before struct {
		Keys []tis.JWK `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &before); err != nil {
		t.Fatal(err)
	}
	if len(before.Keys) != 1 || before.Keys[0].Kid != h.tis.CurrentKid() {
		t.Fatalf("want the single current key, got %+v", before.Keys)
	}
	// Nothing private may appear in a payload published for verification. The
	// JWK type has no private field, so this guards the shape of the *response*
	// rather than the struct — a future hand-rolled encoder is what would break
	// it, and by then the payload is already leaving the process.
	for _, forbidden := range []string{`"d"`, "PRIVATE", "BEGIN EC"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("JWKS response contains %q: %s", forbidden, body)
		}
	}

	resp, err := http.Post(admin.URL+"/keys/rotate", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /keys/rotate = %d", resp.StatusCode)
	}

	code, body = get("/jwks")
	var after struct {
		Keys []tis.JWK `json:"keys"`
	}
	json.Unmarshal([]byte(body), &after)
	if len(after.Keys) != 2 {
		t.Fatalf("after rotation want 2 published keys, got %d: %s", len(after.Keys), body)
	}
	if after.Keys[0].Kid == before.Keys[0].Kid {
		t.Error("rotation did not change the signing key")
	}
	// The displaced key stays published: a verifier holding a token signed a
	// moment before the rotation must still be able to find its key.
	if after.Keys[1].Kid != before.Keys[0].Kid {
		t.Errorf("the displaced key %s is not published as previous; got %+v",
			before.Keys[0].Kid, after.Keys)
	}
}
