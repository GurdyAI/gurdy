package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// stdio shim (§4.4): byte-identical relay through the wrapped process, with
// a decision per tools/call line. `cat` stands in as the MCP server.
func TestShimPassThroughAndDecisions(t *testing.T) {
	h := newHarness(t) // reuse gateway wiring; its HTTP server goes unused here
	g := newGateway(h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog))

	input := credReadCall + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/ok.txt"}}}` + "\n"

	var out bytes.Buffer
	if err := runShim(g, []string{"cat"}, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != input {
		t.Fatalf("relay not byte-identical:\n got: %q\nwant: %q", out.String(), input)
	}
	logged := h.decisionLog.String()
	if strings.Count(logged, `"msg":"decision"`) != 2 {
		t.Fatalf("want 2 decisions (tools/list is not one): %s", logged)
	}
	if !strings.Contains(logged, `"decision":"flag"`) || !strings.Contains(logged, `"decision":"allow"`) {
		t.Fatalf("decisions wrong: %s", logged)
	}
	if !strings.Contains(logged, `"principal":"svc:stdio:cat"`) {
		t.Fatalf("stdio coarse principal missing: %s", logged)
	}
}

// An oversized line is relayed byte-identically but recorded indeterminate,
// never buffered whole for inspection — same semantics as the HTTP path.
func TestShimOversizeLineForwardedIndeterminate(t *testing.T) {
	h := newHarness(t)
	g := newGateway(h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog))

	big := strings.Repeat("x", maxInspect+100) + "\n"
	input := big + credReadCall + "\n"
	var out bytes.Buffer
	if err := runShim(g, []string{"cat"}, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != input {
		t.Fatalf("oversize relay not byte-identical (got %d bytes, want %d)", out.Len(), len(input))
	}
	logged := h.decisionLog.String()
	if !strings.Contains(logged, `"decision":"indeterminate"`) {
		t.Fatalf("oversize line not recorded: %s", logged)
	}
	if !strings.Contains(logged, `"decision":"flag"`) {
		t.Fatalf("line after oversize line escaped inspection: %s", logged)
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// stdioSession drives both relay directions over one pending map, the way
// runShim wires them, without a child process — the correlation logic needs
// exact frames, and no stand-in server echoes what a given case requires.
//
// send and recv are separate calls so a test can *interleave* turns. That is
// not cosmetic: the failures that matter here only appear across turns, when a
// pending entry left over from turn 1 meets an id reused in turn 3.
type stdioSession struct {
	h    *harness
	g    *gateway
	pend *pending
}

func newStdioSession(t *testing.T) *stdioSession {
	t.Helper()
	h := newHarness(t)
	return &stdioSession{h: h,
		g:    newGateway(h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog)),
		pend: &pending{m: map[string]*slot{}}}
}

// send plays client→server frames; each line is decided, then forwarded.
func (s *stdioSession) send(t *testing.T, lines ...string) {
	t.Helper()
	in := strings.Join(lines, "\n") + "\n"
	if err := relay(s.g, "stdio:x", s.pend, strings.NewReader(in), nopWriteCloser{io.Discard}); err != nil {
		t.Fatal(err)
	}
}

// recv plays server→client frames, asserting the relay stays byte-identical.
func (s *stdioSession) recv(t *testing.T, lines ...string) {
	t.Helper()
	want := strings.Join(lines, "\n") + "\n"
	var out bytes.Buffer
	if err := relayOut(s.g, "stdio:x", s.pend, strings.NewReader(want), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("child output mutated:\n got: %q\nwant: %q", out.String(), want)
	}
}

// records closes the ledger and returns the export.
func (s *stdioSession) records(t *testing.T) []map[string]any {
	t.Helper()
	if err := s.h.led.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.h.ledgerFile(t))
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("ledger line not JSON: %v", err)
		}
		recs = append(recs, rec)
	}
	return recs
}

// kinds tallies a record set by kind.
func kinds(recs []map[string]any) map[string]int {
	out := map[string]int{}
	for _, r := range recs {
		out[fmt.Sprint(r["kind"])]++
	}
	return out
}

// call is a tools/call frame with the given id, reading path.
func call(id, path string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, id, path)
}

func runStdio(t *testing.T, h *harness, requests, responses string) []map[string]any {
	t.Helper()
	s := &stdioSession{h: h,
		g:    newGateway(h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog)),
		pend: &pending{m: map[string]*slot{}}}
	s.send(t, strings.TrimSuffix(requests, "\n"))
	s.recv(t, strings.TrimSuffix(responses, "\n"))
	return s.records(t)
}

// D4, stdio half: a response record joined to the call it answers by JSON-RPC
// id (§5.5). The frames come back in the *opposite* order to the requests and
// with ids of two different JSON types, because positional pairing would pass
// a same-order test while attributing every out-of-order server's evidence to
// the wrong call.
func TestShimResponseRecordsJoinByJSONRPCID(t *testing.T) {
	h := newHarness(t)
	const (
		respB = `{"jsonrpc":"2.0","id":"tok-2","result":{"content":["bbbbbbbb"]}}`
		respA = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
	)
	recs := runStdio(t, h,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a.txt"}}}`+"\n"+
			`{"jsonrpc":"2.0","id":"tok-2","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/b.txt"}}}`+"\n",
		respB+"\n"+respA+"\n")

	callOf := map[string]string{} // resource_path → call_id
	answers := map[string]map[string]any{}
	for _, r := range recs {
		switch r["kind"] {
		case "decision":
			attrs, _ := r["resource_attrs"].(map[string]any)
			callOf[fmt.Sprint(attrs["resource_path"])] = fmt.Sprint(r["call_id"])
		case "response":
			answers[fmt.Sprint(r["call_id"])] = r
		}
	}
	if len(callOf) != 2 || len(answers) != 2 {
		t.Fatalf("want 2 decisions and 2 responses, got %d/%d", len(callOf), len(answers))
	}
	for path, frame := range map[string]string{"/a.txt": respA, "/b.txt": respB} {
		got := answers[callOf[path]]
		if got == nil {
			t.Fatalf("%s unanswered", path)
		}
		if want := fmt.Sprintf("%x", sha256.Sum256([]byte(frame))); got["resp_hash"] != want {
			t.Errorf("%s joined to the wrong frame: resp_hash %v, want %v", path, got["resp_hash"], want)
		}
		if got["bytes"] != float64(len(frame)) {
			t.Errorf("%s: bytes %v, want %d", path, got["bytes"], len(frame))
		}
	}
}

// A client that reuses an id while the first call is still in flight makes the
// next frame ambiguous. Both calls must stay *unanswered*: a response record on
// a guessed call_id is misattributed evidence, and a reader cannot tell it is
// wrong, which is worse than a visibly missing half.
func TestShimDuplicateInFlightIDIsNotGuessed(t *testing.T) {
	h := newHarness(t)
	recs := runStdio(t, h,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a.txt"}}}`+"\n"+
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/b.txt"}}}`+"\n",
		`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`+"\n")

	var decisions, responses int
	for _, r := range recs {
		switch r["kind"] {
		case "decision":
			decisions++
		case "response":
			responses++
		}
	}
	if decisions != 2 {
		t.Fatalf("both calls must still be decided, got %d", decisions)
	}
	if responses != 0 {
		t.Errorf("ambiguous id was guessed: %d response records", responses)
	}
}

// A JSON-RPC batch shares one line, so the HTTP path gives every call in it
// the same envelope hash. stdio can do better: the ids are right there, so each
// call is joined to the element that actually answered it — which is what makes
// a batched call's evidence mean the same thing as an unbatched one's, rather
// than N records that only look distinct.
func TestShimBatchResponseHashesPerElement(t *testing.T) {
	h := newHarness(t)
	const (
		elemA = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
		elemB = `{"jsonrpc":"2.0","id":2,"result":{"content":["bbbb"]}}`
	)
	recs := runStdio(t, h,
		`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a.txt"}}},`+
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/b.txt"}}}]`+"\n",
		`[`+elemB+`,`+elemA+`]`+"\n")

	hashes := map[string]bool{}
	for _, r := range recs {
		if r["kind"] == "response" {
			hashes[fmt.Sprint(r["resp_hash"])] = true
		}
	}
	for _, elem := range []string{elemA, elemB} {
		if want := fmt.Sprintf("%x", sha256.Sum256([]byte(elem))); !hashes[want] {
			t.Errorf("no response record hashes the element %s (got %v)", elem, hashes)
		}
	}
	if len(hashes) != 2 {
		t.Errorf("want two distinct per-element hashes, got %v", hashes)
	}
}

// The child's own requests to the client (sampling, elicitation) carry an id
// and must never be claimed as an answer — they are a second question, not a
// reply, and consuming the pending entry would leave the real call unanswered.
func TestShimServerRequestIsNotAnAnswer(t *testing.T) {
	h := newHarness(t)
	const answer = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
	recs := runStdio(t, h,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a.txt"}}}`+"\n",
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}`+"\n"+answer+"\n")

	var responses int
	for _, r := range recs {
		if r["kind"] != "response" {
			continue
		}
		responses++
		if want := fmt.Sprintf("%x", sha256.Sum256([]byte(answer))); r["resp_hash"] != want {
			t.Errorf("joined to the server's own request, not its reply: %v", r["resp_hash"])
		}
	}
	if responses != 1 {
		t.Errorf("want exactly one response record, got %d", responses)
	}
}

// Reusing an id *sequentially* — send 1, read the answer to 1, send 1 again —
// is ordinary client behaviour, not the ambiguous case, and every call must
// still be answered. This is what forces the claim to happen before the frame
// reaches the client: write first and a client that reuses ids can legally
// re-send id 1 while this side still has 1 pending, and its own correctness
// would cost it its evidence.
func TestShimSequentialIDReuseStaysCorrelated(t *testing.T) {
	s := newStdioSession(t)
	for i := range 3 {
		s.send(t, call("1", fmt.Sprintf("/f%d.txt", i)))
		s.recv(t, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	}
	if k := kinds(s.records(t)); k["decision"] != 3 || k["response"] != 3 {
		t.Fatalf("sequential id reuse lost evidence: %d decisions, %d responses", k["decision"], k["response"])
	}
}

// The same property under real concurrency, which is the only place it can
// actually break: relay and relayOut run in separate goroutines, and a client
// that reuses ids races the shim's own bookkeeping. If the answer reaches the
// client before this side has retired the pending entry, the client's next
// request lands on an id that still looks in flight and the call is refused
// correlation it deserved. Sequential-turn tests cannot see this ordering at
// all — they hand the two directions the lock one after the other.
func TestShimSequentialIDReuseUnderConcurrency(t *testing.T) {
	const rounds = 300
	s := newStdioSession(t)
	clientIn, clientInW := io.Pipe()
	childInR, childIn := io.Pipe()
	childOutR, childOut := io.Pipe()
	clientOutR, clientOut := io.Pipe()

	// The wrapped MCP server: one response per request, as fast as it can.
	go func() {
		sc := bufio.NewScanner(childInR)
		for sc.Scan() {
			fmt.Fprintln(childOut, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
		}
		childOut.Close()
	}()
	go func() { relay(s.g, "stdio:x", s.pend, clientIn, childIn); childInR.Close() }()
	go func() { relayOut(s.g, "stdio:x", s.pend, childOutR, clientOut); clientOut.Close() }()

	// The client: send, wait for the answer, immediately reuse the id.
	sc := bufio.NewScanner(clientOutR)
	for i := range rounds {
		fmt.Fprintln(clientInW, call("1", fmt.Sprintf("/f%d.txt", i)))
		if !sc.Scan() {
			t.Fatalf("round %d: no answer: %v", i, sc.Err())
		}
	}
	clientInW.Close()
	clientOutR.Close()

	if k := kinds(s.records(t)); k["decision"] != rounds || k["response"] != rounds {
		t.Fatalf("racing the client's own id reuse lost evidence: %d decisions, %d responses (want %d each)",
			k["decision"], k["response"], rounds)
	}
}

// Ambiguity has to outlive the *first* answer. Two calls share id 1, so one
// response retires neither of them — a second frame for id 1 is still owed, and
// the id must stay unusable until it arrives. Clearing on the first response
// frees id 1 for call C, and then the delayed answer to B lands on C's
// call_id: a join that is wrong and that no reader could detect.
func TestShimAmbiguityOutlivesTheFirstAnswer(t *testing.T) {
	s := newStdioSession(t)
	s.send(t, call("1", "/a.txt"), call("1", "/b.txt")) // both in flight under id 1
	s.recv(t, `{"jsonrpc":"2.0","id":1,"result":{"content":["one"]}}`)
	s.send(t, call("1", "/c.txt")) // reused while an answer is still owed
	s.recv(t, `{"jsonrpc":"2.0","id":1,"result":{"content":["two"]}}`)

	if k := kinds(s.records(t)); k["decision"] != 3 || k["response"] != 0 {
		t.Fatalf("ambiguous id was reused: %d decisions, %d responses (want 3/0)", k["decision"], k["response"])
	}
}

// ...and once everything owed under an id has arrived, the id is clean again:
// there is no delayed frame left to cross a later call, so refusing forever
// would throw away evidence for no gain.
func TestShimAmbiguityClearsWhenNothingIsOutstanding(t *testing.T) {
	s := newStdioSession(t)
	s.send(t, call("1", "/a.txt"), call("1", "/b.txt"))
	s.recv(t, `{"jsonrpc":"2.0","id":1,"result":{"content":["one"]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":["two"]}}`) // both retired
	s.send(t, call("1", "/c.txt"))
	s.recv(t, `{"jsonrpc":"2.0","id":1,"result":{"content":["three"]}}`)

	if k := kinds(s.records(t)); k["decision"] != 3 || k["response"] != 1 {
		t.Fatalf("want the two ambiguous calls unanswered and the clean one answered, got %d decisions %d responses",
			k["decision"], k["response"])
	}
}

// A frame carrying a pending id but neither result nor error is not an answer.
// Claiming it would consume the pending entry and record *its* hash, and the
// real response would then arrive unrecorded — evidence replaced by a decoy
// rather than merely missing.
func TestShimFrameWithoutResultOrErrorIsNotAnAnswer(t *testing.T) {
	s := newStdioSession(t)
	const answer = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
	s.send(t, call("1", "/a.txt"))
	s.recv(t, `{"jsonrpc":"2.0","id":1,"progress":0.5}`, answer)

	var n int
	for _, r := range s.records(t) {
		if r["kind"] != "response" {
			continue
		}
		n++
		if want := fmt.Sprintf("%x", sha256.Sum256([]byte(answer))); r["resp_hash"] != want {
			t.Errorf("a decoy frame consumed the call: %v", r["resp_hash"])
		}
	}
	if n != 1 {
		t.Errorf("want one response record, got %d", n)
	}
}

// `null` is the id a peer sends when it could not read the request well enough
// to know one, so it names no call. Correlating on it joins a parse-error frame
// to whichever malformed call happened to carry a null id.
func TestShimNullIDCorrelatesNothing(t *testing.T) {
	s := newStdioSession(t)
	s.send(t, call("null", "/a.txt"))
	s.recv(t, `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`)

	if k := kinds(s.records(t)); k["decision"] != 1 || k["response"] != 0 {
		t.Fatalf("null id was correlated: %d decisions, %d responses (want 1/0)", k["decision"], k["response"])
	}
}

// An id is raw JSON and a client picks it, so a count-only bound on the pending
// map leaves memory to the client: 4096 multi-megabyte ids is gigabytes held by
// a process whose job is to keep running. Oversized ids are refused in both
// directions, so the call is unanswered and no state accumulates.
func TestShimOversizedIDIsNotRetained(t *testing.T) {
	s := newStdioSession(t)
	huge := `"` + strings.Repeat("z", maxIDLen*4) + `"`
	s.send(t, call(huge, "/a.txt"))
	s.recv(t, `{"jsonrpc":"2.0","id":`+huge+`,"result":{"content":[]}}`)

	s.pend.mu.Lock()
	held := len(s.pend.m)
	s.pend.mu.Unlock()
	if held != 0 {
		t.Errorf("oversized id retained: %d entries", held)
	}
	if k := kinds(s.records(t)); k["decision"] != 1 || k["response"] != 0 {
		t.Fatalf("want the call decided and unanswered, got %d/%d", k["decision"], k["response"])
	}
}

// Running out of room for new ids means we can no longer record that a call is
// outstanding — and an unrecorded outstanding call is exactly what crosses a
// later reuse of its id. Correlation stops for the session rather than
// continuing to serve joins it can no longer prove.
// The answered id here is one that was tracked *successfully*, before the
// bound was hit. Merely skipping the insert that overflows would leave it
// joinable, and the run would look healthy while every id dropped at the bound
// silently waited to cross its next reuse. Stopping is the whole claim, so the
// assertion has to be on an id that would otherwise still work.
func TestShimPendingOverflowStopsCorrelating(t *testing.T) {
	s := newStdioSession(t)
	for i := range maxPending {
		s.send(t, call(fmt.Sprint(i), "/a.txt")) // never answered: all stay in flight
	}
	s.send(t, call(`"one-too-many"`, "/b.txt")) // no room left to record it

	s.recv(t, `{"jsonrpc":"2.0","id":0,"result":{"content":[]}}`) // an id tracked cleanly
	if k := kinds(s.records(t)); k["response"] != 0 {
		t.Errorf("correlation continued past the bound: %d response records", k["response"])
	}
}

func TestShimChildFailurePropagates(t *testing.T) {
	h := newHarness(t)
	g := newGateway(h.store, h.tis, h.led, "test-tenant", slogTo(h.decisionLog))
	var out bytes.Buffer
	if err := runShim(g, []string{"false"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("child exit failure not propagated")
	}
}
