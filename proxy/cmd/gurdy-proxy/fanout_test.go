package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/GurdyAI/gurdy/proxy/internal/tis"
)

// The §3.G fan-out burst: 20 sub-agents derived from one root, 50 concurrent
// calls each, correct lineage on every record.
//
// It is a *correctness*-under-concurrency test, not a latency one. The failure
// it hunts is attribution crossing between agents under load — a record that
// says agent-07 made a call agent-03 made. That is the worst possible defect in
// an evidence product: not a missing record, which a reader can see, but a
// present and plausible record naming the wrong actor.
//
// Self-consistency is not enough to catch it. A record whose `lineage[1]` and
// `asserted_principal` agree can still be attached to another agent's call, and
// both fields would look right. So each agent calls a tool named after itself
// and the assertion is that the *tool* and the *identity* agree — the tool name
// comes off the wire and the identity off the credential, so they can only
// agree if nothing crossed between the two.
func TestFanOutBurstAttributesEveryRecord(t *testing.T) {
	const (
		agents          = 20
		callsPerAgent   = 50
		wantTotalRecord = agents * callsPerAgent
	)
	h := newHarness(t)
	scope := tis.Scope{Compartments: []string{"*"}, ResourceTypes: []string{"*"},
		Actions: []string{"*"}, Purpose: "fan-out"}
	root, err := h.tis.MintTxn("orchestrator", "alice@example.com", scope, "test", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Derived up front. Deriving inside the burst would test the mint path's
	// concurrency too, and a failure would not say which half broke.
	child := make([]string, agents)
	for i := range child {
		if child[i], err = h.tis.DeriveChildTxn(root, agentName(i), scope); err != nil {
			t.Fatal(err)
		}
	}

	// One gate for all 1,000 goroutines: staggered starts would let the burst
	// drain as it arrives, which is the load pattern that does *not* find this.
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := range agents {
		for range callsPerAgent {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				body := fmt.Sprintf(
					`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{"path":"/tmp/x"}}}`,
					agentName(i))
				req, _ := http.NewRequest(http.MethodPost, h.proxy.URL, strings.NewReader(body))
				req.Header.Set(TxnHeader, child[i])
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Errorf("%s: %v", agentName(i), err)
					return
				}
				resp.Body.Close()
			}()
		}
	}
	close(gate)
	wg.Wait()

	if err := h.led.Close(); err != nil { // flush the queue before reading it
		t.Fatal(err)
	}

	seen := map[string]int{}
	var decisions int
	for _, line := range readLines(t, h.ledgerFile(t)) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("undecodable ledger line: %v", err)
		}
		if rec["kind"] != nil && rec["kind"] != "decision" {
			continue // response, batchsig, header, coverage
		}
		tool, _ := rec["tool"].(string)
		if !strings.HasPrefix(tool, "agent-") {
			continue // not one of ours
		}
		decisions++

		// The load-bearing assertion. `tool` came off the wire, `lineage` and
		// `asserted_principal` came off the credential; they can only agree if
		// no attribution crossed between two calls in flight.
		lineage, _ := rec["lineage"].([]any)
		if len(lineage) != 2 || lineage[0] != "orchestrator" || lineage[1] != tool {
			t.Fatalf("%s: lineage does not match the caller: %v", tool, rec["lineage"])
		}
		if rec["asserted_principal"] != tool {
			t.Fatalf("%s: asserted principal is %v", tool, rec["asserted_principal"])
		}
		if rec["assertion_status"] != "valid" {
			t.Fatalf("%s: assertion not valid: %v", tool, rec["assertion_status"])
		}
		// Observed identity is never replaced by the claim (§5.5), no matter
		// how many claims arrive at once.
		if rec["principal_tier"] != "attested-coarse" {
			t.Fatalf("%s: observed identity degraded under load: %v", tool, rec["principal_tier"])
		}
		seen[tool]++
	}

	// Drops are legal — the queue is bounded and monitor mode never blocks
	// traffic (NFR-3) — so a shortfall is reported against the drop counter
	// rather than asserted away. What may never happen is a record landing
	// under the wrong agent, which the per-agent counts would show as a
	// surplus somewhere.
	dropped := h.led.Dropped.Load()
	// Logged unconditionally, not just on a drop: a reader of a passing run
	// should be able to see that it checked ~1,000 records rather than zero.
	t.Logf("%d calls -> %d decision records checked, %d dropped",
		wantTotalRecord, decisions, dropped)
	if uint64(decisions)+dropped < wantTotalRecord {
		t.Errorf("records unaccounted for: %d decisions + %d dropped < %d calls",
			decisions, dropped, wantTotalRecord)
	}
	for i := range agents {
		if n := seen[agentName(i)]; n > callsPerAgent {
			t.Errorf("%s has %d records for %d calls — attribution crossed",
				agentName(i), n, callsPerAgent)
		}
	}
}

func agentName(i int) string { return fmt.Sprintf("agent-%02d", i) }

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
