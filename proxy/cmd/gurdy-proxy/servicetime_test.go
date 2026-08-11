package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GurdyAI/gurdy/proxy/internal/clock"
	"github.com/GurdyAI/gurdy/proxy/internal/extract"
)

// TestDecisionServiceTimeDistribution reports the *distribution* of the proxy's
// own decision work, not its mean.
//
// This exists because the end-to-end harness cannot resolve a 5ms p99 on a
// shared machine: the loopback stack and the OS scheduler contribute a tail an
// order of magnitude larger than the budget, so `p99(proxied) − p99(direct)`
// measures the host, not the proxy. But that noise is all in the *hop*. The
// work the proxy actually performs — derive + extract + eval + enqueue — is
// in-process, on a monotonic clock, with no syscall in the measured region, and
// its tail is therefore attributable and resolvable right here.
//
// So NFR-1's budget splits cleanly into a part we can certify anywhere and a
// part that needs a deployment:
//
//	hop + derive + extract + eval  ≤ 5ms p99
//	└─ needs a real     ┘ └─ this test ─────┘
//	   network to measure
//
// A `go test -bench` cannot do this: it reports ns/op averaged over the run, and
// an average is exactly what hides a tail. Reported rather than asserted,
// because a threshold here would be a threshold on whatever machine CI happens
// to schedule — the numbers go in the roadmap and a regression shows up as a
// change in them.
func TestDecisionServiceTimeDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("saturation run; -short skips it")
	}
	h := newHarness(t)
	g := newGateway(h.store, h.tis, h.led, "svc", slogTo(&syncBuffer{}))
	body := []byte(credReadCall)
	call := extract.Call{
		Tool: "read_file", Arguments: map[string]any{"path": "/home/u/.ssh/id_rsa"},
		Host: "upstream.local", Path: "/", Body: body,
	}

	// Two arms, because they answer different questions. Serial is the cost of
	// the work itself. Saturated is the cost with every core competing for the
	// locks on this path — the pessimistic bound, and the one that would expose
	// contention as a tail rather than as a throughput number.
	for _, arm := range []struct {
		name    string
		workers int
		each    int
	}{
		{"serial", 1, 20000},
		{"saturated", runtime.GOMAXPROCS(0), 4000},
	} {
		t.Run(arm.name, func(t *testing.T) {
			samples := make([][]time.Duration, arm.workers)
			var wg sync.WaitGroup
			for w := 0; w < arm.workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					mine := make([]time.Duration, 0, arm.each)
					for i := 0; i < arm.each; i++ {
						t0 := time.Now()
						g.decideCall(context.Background(), "", "host:127.0.0.1", call, body)
						mine = append(mine, time.Since(t0))
					}
					samples[w] = mine
				}(w)
			}
			wg.Wait()

			var all []time.Duration
			for _, s := range samples {
				all = append(all, s...)
			}
			sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
			pct := func(p float64) time.Duration {
				i := int(p / 100 * float64(len(all)))
				if i >= len(all) {
					i = len(all) - 1
				}
				return all[i].Round(time.Microsecond)
			}
			t.Logf("n=%d workers=%d  p50 %v  p90 %v  p99 %v  p99.9 %v  max %v",
				len(all), arm.workers, pct(50), pct(90), pct(99), pct(99.9),
				all[len(all)-1].Round(time.Microsecond))

			// The one thing worth failing on: evidence. If this saturated the
			// ledger queue then the latency above was bought by dropping
			// records, and the number is not the number.
			if d := h.led.Dropped.Load(); d > 0 {
				t.Errorf("%d ledger records dropped during the run — this latency was bought by losing evidence", d)
			}
		})
	}
}

// The live clocking surface. Two things are worth pinning: that a real call
// actually populates it, and that the payload states its own scope — the
// numbers exclude the hop, which is the larger term of NFR-1's budget, and a
// reader who takes them as the gate figure has been misled by us.
func TestLatencyEndpointReportsStagesAndItsOwnLimits(t *testing.T) {
	clock.Reset()
	h := newHarness(t)
	admin := httptest.NewServer(adminMux(h.store, h.led, ""))
	defer admin.Close()

	resp, err := http.Post(h.proxy.URL, "application/json", strings.NewReader(credReadCall))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	r, err := http.Get(admin.URL + "/latency")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var got clock.Report
	if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(got.Excludes, "hop") {
		t.Error("the report must say that it excludes the hop, in the payload and not only in a doc")
	}
	stages := map[string]clock.Snapshot{}
	for _, s := range got.Stages {
		stages[s.Stage] = s
	}
	for _, want := range []string{"decide", "identify", "classify", "evaluate", "attest"} {
		s, ok := stages[want]
		if !ok {
			t.Errorf("no %q stage in the report", want)
			continue
		}
		if s.Count == 0 {
			t.Errorf("stage %q recorded nothing for a call that certainly ran it", want)
		}
	}
	// The stage totals must sit inside the whole decision; a sub-stage reported
	// as larger than `decide` would mean the timers are nested wrong.
	if d, i := stages["decide"], stages["identify"]; d.MeanUS < i.MeanUS {
		t.Errorf("identify (%.1fµs) reported above the decision that contains it (%.1fµs)", i.MeanUS, d.MeanUS)
	}

	// DELETE starts a fresh window, which is what an operator watching a change
	// land actually wants.
	req, _ := http.NewRequest(http.MethodDelete, admin.URL+"/latency", nil)
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	if got := clock.Decide.Snapshot().Count; got != 0 {
		t.Errorf("after reset, count %d", got)
	}
}
