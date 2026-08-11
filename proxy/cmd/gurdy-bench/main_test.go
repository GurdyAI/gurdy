package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The load-generation loop is not unit-testable — it needs a real listener and
// real time. Its arithmetic is, and that is where a silent error would be worst:
// every number this tool prints, and the pass/fail decision behind it, comes out
// of these four functions. A percentile off by one index makes the whole gate a
// guess dressed as a measurement.

func durs(ms ...int) []time.Duration {
	out := make([]time.Duration, len(ms))
	for i, m := range ms {
		out[i] = time.Duration(m) * time.Millisecond
	}
	return out
}

func TestPercentileIndexing(t *testing.T) {
	// 100 samples, 1..100ms. With nearest-rank on a sorted slice the p50 is the
	// 50th sample and the p99 the 99th, so the values are readable by eye — the
	// point being that an off-by-one is visible here rather than as a 1% error
	// nobody notices.
	lat := make([]time.Duration, 100)
	for i := range lat {
		lat[i] = time.Duration(i+1) * time.Millisecond
	}
	r := result{lat: lat}
	for _, tc := range []struct {
		p    float64
		want time.Duration
	}{
		{50, 50 * time.Millisecond},
		{90, 90 * time.Millisecond},
		{99, 99 * time.Millisecond},
		{99.9, 100 * time.Millisecond},
		{100, 100 * time.Millisecond},
	} {
		if got := r.pct(tc.p); got != tc.want {
			t.Errorf("p%v = %s, want %s", tc.p, got, tc.want)
		}
	}
}

func TestPercentileOfEmptyIsZeroNotAPanic(t *testing.T) {
	// An arm that recorded nothing must not take the tool down before it can
	// report *why* it recorded nothing.
	if got := (result{}).pct(99); got != 0 {
		t.Errorf("got %s, want 0", got)
	}
	if got := (result{}).achieved(); got != 0 {
		t.Errorf("achieved on an empty result = %v", got)
	}
}

func TestPoolMergesAndSorts(t *testing.T) {
	a := result{lat: durs(1, 5, 9), window: time.Second}
	b := result{lat: durs(2, 6), window: time.Second}
	got := pool(a, b)
	if len(got.lat) != 5 {
		t.Fatalf("pooled %d samples, want 5", len(got.lat))
	}
	for i := 1; i < len(got.lat); i++ {
		if got.lat[i-1] > got.lat[i] {
			t.Fatalf("pooled samples not sorted: %v", got.lat)
		}
	}
	if got.max != 9*time.Millisecond {
		t.Errorf("max %s, want 9ms", got.max)
	}
	// The window is the sum, so achieved() describes the pooled rate rather than
	// double-counting one arm's throughput.
	if got.window != 2*time.Second {
		t.Errorf("window %s, want 2s", got.window)
	}
}

// The checks that decide whether a number means anything at all.
func TestResolvableRefusesAGateItCannotJudge(t *testing.T) {
	gate50, gate99 := 3*time.Millisecond, 5*time.Millisecond

	quiet := result{lat: durs(1, 1, 1, 1, 2), window: time.Second}
	if p := resolvable(quiet, quiet, pool(quiet, quiet), gate50, gate99); len(p) != 0 {
		t.Errorf("a quiet host should resolve the gate, got %v", p)
	}

	// The baseline's own tail is above the budget for the *added* cost: the
	// effect is smaller than the measurement error, so no verdict is available.
	noisy := result{lat: durs(1, 1, 1, 1, 40), window: time.Second}
	probs := resolvable(noisy, noisy, pool(noisy, noisy), gate50, gate99)
	if len(probs) == 0 || !strings.Contains(probs[0], "INCONCLUSIVE") {
		t.Errorf("a baseline p99 above the gate must be inconclusive, got %v", probs)
	}

	// Two baseline arms that disagree by more than the budget mean the host's
	// run-to-run swing exceeds the effect, whatever either arm says on its own.
	lo := result{lat: durs(1, 1, 1, 1, 1), window: time.Second}
	hi := result{lat: durs(1, 1, 1, 1, 20), window: time.Second}
	probs = resolvable(lo, hi, pool(lo, hi), gate50, gate99)
	if len(probs) == 0 {
		t.Error("disagreeing baselines must be reported, not averaged away")
	}
}

// Evidence loss must fail the run even when the latency looks good — a proxy
// that sheds records under pressure gets *faster*, so this is the one check that
// a flattering number must not be able to satisfy.
func TestDroppedRecordsFailTheRunRegardlessOfLatency(t *testing.T) {
	fast := result{lat: durs(1, 1, 1), window: time.Second}
	before := counters{dropped: 0}
	after := counters{dropped: 7}

	probs := verdict(fast, fast, before, after, 3, time.Second, time.Second)
	var found bool
	for _, p := range probs {
		if strings.Contains(p, "dropped 7 records") {
			found = true
		}
	}
	if !found {
		t.Errorf("a run that dropped evidence must fail: %v", probs)
	}
}

func TestScheduleLagIsReportedBecauseItUnderstatesTheTail(t *testing.T) {
	behind := result{lat: durs(1, 1, 1), maxLag: 500 * time.Millisecond, window: time.Second}
	probs := verdict(behind, behind, counters{}, counters{}, 3, time.Second, time.Second)
	var found bool
	for _, p := range probs {
		if strings.Contains(p, "behind schedule") {
			found = true
		}
	}
	if !found {
		t.Errorf("a generator that fell behind offered less load than requested: %v", probs)
	}
}

func TestBodyIsRealMCPAtEverySize(t *testing.T) {
	// The proxy must actually parse what the harness sends; a body it cannot
	// decode is recorded indeterminate and skips the policy path, which would
	// measure the wrong thing entirely and look fast doing it.
	for _, size := range []int{0, 1, 128, 1 << 10, 64 << 10} {
		body := mcpBody(size)
		var frame struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &frame); err != nil {
			t.Fatalf("size %d: not valid JSON: %v", size, err)
		}
		if frame.Method != "tools/call" || frame.Params.Name != "read_file" {
			t.Fatalf("size %d: not a tools/call the proxy would inspect: %s", size, body)
		}
		if size > 200 && len(body) < size {
			t.Errorf("size %d: body is only %d bytes", size, len(body))
		}
	}
}

// The soak's whole claim is that it can see a trend. A drift summary that
// compared a window to itself would report "+0.0%" for every run forever, look
// exactly like a healthy result, and be believed — so these assert that the
// two windows are actually distinguished and in the right direction.
func TestDriftSummaryComparesFirstToLastAndNotToItself(t *testing.T) {
	first := result{lat: durs(100, 100, 100), window: time.Second}
	last := result{lat: durs(150, 150, 150), window: time.Second}

	got := strings.Join(driftLines(first, last), "\n")
	if !strings.Contains(got, "+50.0%") {
		t.Errorf("a 100 -> 150 window should read +50.0%%: %s", got)
	}
	// Reversed, the same data must read as an improvement. If the summary were
	// reading one window twice, both directions would print +0.0%.
	rev := strings.Join(driftLines(last, first), "\n")
	if !strings.Contains(rev, "-33.3%") {
		t.Errorf("reversed windows should read -33.3%%: %s", rev)
	}
}

// A soak that creeps only in the tail is the interesting case: p50 flat is what
// makes an operator stop reading, so p99 has to be reported independently.
func TestDriftSummaryReportsTheTailSeparatelyFromTheMedian(t *testing.T) {
	// Two outliers, not one, and the reason is worth stating: pct(99) over 100
	// sorted samples indexes 98, so a single slow sample lands at 99 and the
	// percentile never sees it. Getting this wrong is how a tail test passes
	// while measuring the median twice.
	flat := make([]time.Duration, 0, 100)
	tail := make([]time.Duration, 0, 100)
	for range 98 {
		flat = append(flat, 100*time.Microsecond)
		tail = append(tail, 100*time.Microsecond)
	}
	flat = append(flat, 100*time.Microsecond, 100*time.Microsecond)
	tail = append(tail, 400*time.Microsecond, 400*time.Microsecond)

	got := strings.Join(driftLines(result{lat: flat, window: time.Second}, result{lat: tail, window: time.Second}), "\n")
	p50Line, p99Line := lineWith(got, "p50"), lineWith(got, "p99")
	if !strings.Contains(p50Line, "+0.0%") {
		t.Errorf("median did not move; summary says otherwise: %s", p50Line)
	}
	if strings.Contains(p99Line, "+0.0%") {
		t.Errorf("the tail quadrupled and the summary hid it: %s", p99Line)
	}
}

// pctChange divides by the first window. An empty or zero baseline is a real
// possibility (a window where every sample landed under the clock's
// resolution), and it must not be a panic or a NaN in the report.
func TestPercentChangeOfZeroBaselineIsNotAPanic(t *testing.T) {
	if got := pctChange(0, time.Second); got != 0 {
		t.Errorf("zero baseline should report 0, got %v", got)
	}
	lines := driftLines(result{window: time.Second}, result{window: time.Second})
	for _, l := range lines {
		if strings.Contains(l, "NaN") || strings.Contains(l, "Inf") {
			t.Errorf("empty windows produced an unreadable report: %s", l)
		}
	}
}

func lineWith(s, want string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, want) {
			return l
		}
	}
	return ""
}
