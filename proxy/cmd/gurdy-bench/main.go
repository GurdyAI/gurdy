// gurdy-bench measures the composed per-call cost of governing traffic, under
// concurrency, against a running proxy — the §8.2 performance gate.
//
// It exists because §8.2 forbids the easy version: "never certify NFR-1 by
// summing standalone microbenchmarks". Tail latency compounds worse than
// linearly under contention, so the only defensible number comes from the whole
// path under load.
//
// Three things it does that a naive load generator does not, each because the
// naive version produces a number that is wrong in the flattering direction:
//
//  1. **Open loop.** Requests are emitted on a fixed schedule and latency is
//     measured from the moment each one was *due*, not from when it was sent.
//     A closed-loop harness — send, await, send the next — cannot enqueue work
//     faster than the system drains it, so it never observes queueing delay and
//     reports a p99 that describes a system under no pressure. That is
//     coordinated omission, and it is the single most common way a load test
//     lies.
//
//  2. **It refuses to subtract percentiles.** `p99(proxied) − p99(direct)` is
//     not the p99 of the added latency: percentiles do not subtract, and the
//     two tails may not even come from the same requests. Both distributions
//     are printed in full and the delta is labelled an estimate.
//
//  3. **It says when the host cannot resolve the gate.** A 5ms p99 budget is
//     not judgeable on a machine whose own idle loopback p99 swings between
//     1.6ms and 14ms; the effect is smaller than the ruler's markings. Reported
//     as INCONCLUSIVE, because a FAIL produced by noise reads exactly like a
//     FAIL produced by the proxy and only one of those is worth chasing.
//
//     A related artifact, worth knowing before reading any number below ~2000
//     req/s on a laptop: at 1000 req/s the inter-arrival gap is 1ms, which is at
//     the edge of the platform's timer resolution, so each measurement carries
//     sleep-wakeup jitter that has nothing to do with the proxy. It shows up as
//     the tail being *worse* at 1000/s than at 3000/s — measured here as 10.5ms
//     versus 896µs, which is not a load response, it is the clock. Throughput
//     and p50 are trustworthy at any rate; the tail needs either a quiet
//     dedicated host or a rate high enough that the generator never sleeps.
//
//  4. **It reads the ledger's drop counters.** The append queue is
//     non-blocking and drops on overflow, so a proxy under pressure gets
//     *faster* while losing evidence. A latency result with a nonzero drop
//     count is not a good result, it is a failed one, and the gate says so.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var (
		proxyURL  = flag.String("proxy", "", "proxy base URL (the governed path)")
		direct    = flag.String("direct", "", "upstream base URL (the ungoverned baseline)")
		admin     = flag.String("admin", "", "proxy admin base URL, for the ledger drop counters")
		rate      = flag.Int("rate", 1000, "requests per second (open loop); §3.2 NFR-2 is 1000")
		dur       = flag.Duration("duration", 30*time.Second, "measurement window per arm")
		warmup    = flag.Duration("warmup", 3*time.Second, "unmeasured warm-up per arm")
		bodyKiB   = flag.Int("body", 1, "request body size in KiB")
		maxFlight = flag.Int("max-in-flight", 512, "cap on concurrent requests before the harness reports itself saturated")
		p50Gate   = flag.Duration("gate-p50", 3*time.Millisecond, "NFR-1 added p50 (sidecar, gated)")
		p99Gate   = flag.Duration("gate-p99", 5*time.Millisecond, "NFR-1 added p99 (sidecar, gated)")
		gated     = flag.Bool("gate", false, "exit nonzero if the added-latency estimate or drops fail the gate")

		// Soak mode answers a different question from the rest of this tool,
		// and deliberately does NOT compare against a baseline. A/B/A exists to
		// attribute *added* latency; a soak asks whether anything drifts over
		// time — memory, file descriptors, latency creep, ledger rotation, an
		// append queue that slowly falls behind. None of that is observable in
		// a 60-second window, and none of it needs an ungoverned arm to see:
		// the comparison is between this proxy at minute 1 and the same proxy
		// at minute 30.
		soak       = flag.Duration("soak", 0, "sustained single-arm run against -proxy for this long; reports per-window drift instead of added latency")
		soakWindow = flag.Duration("soak-window", time.Minute, "reporting window within a soak")
	)
	flag.Parse()

	if *soak > 0 {
		soakRun(*proxyURL, *admin, mcpBody(*bodyKiB<<10), *rate, *warmup, *soakWindow, *soak, *maxFlight)
		return
	}

	if *proxyURL == "" || *direct == "" {
		fmt.Fprintln(os.Stderr, "need -proxy and -direct: the whole measurement is the comparison")
		os.Exit(2)
	}

	body := mcpBody(*bodyKiB << 10)
	fmt.Printf("gurdy-bench: %d req/s open loop, %s per arm, %d KiB bodies, GOMAXPROCS=%d\n",
		*rate, *dur, *bodyKiB, runtime.GOMAXPROCS(0))

	before := dropCounters(*admin)

	// A/B/A, not A/B. The first version of this tool ran the baseline once and
	// then the proxy, and reported a p99 that condemned the proxy — until both
	// arms were pointed at the *same* upstream and the second one still came
	// back seven times worse. The second arm inherits the first's cooling
	// connections, its garbage and its scheduler state, so a fixed order does
	// not compare two systems, it compares two moments. Running the baseline on
	// both sides of the measurement brackets it in time and makes the
	// instability visible instead of charging it to whatever ran second.
	first := run("baseline", *direct, body, *rate, *warmup, *dur, *maxFlight)
	settle()
	governed := run("proxied ", *proxyURL, body, *rate, *warmup, *dur, *maxFlight)
	settle()
	second := run("baseline", *direct, body, *rate, *warmup, *dur, *maxFlight)

	after := dropCounters(*admin)

	// Pooled, because the proxied arm ran between them: the combination is the
	// closest thing to "what this machine was doing while the proxy was measured".
	baseline := pool(first, second)

	fmt.Println()
	first.print()
	governed.print()
	second.print()

	fmt.Println("\nadded per call (estimate — see below):")
	fmt.Printf("  p50 %8s   p99 %8s   max %8s\n",
		round(governed.pct(50)-baseline.pct(50)),
		round(governed.pct(99)-baseline.pct(99)),
		round(governed.max-baseline.max))
	fmt.Println("  Percentiles do not subtract. These deltas are the difference between")
	fmt.Println("  two independent distributions, not the distribution of the added cost,")
	fmt.Println("  and they are only meaningful because both arms ran the same schedule")
	fmt.Println("  against the same upstream on the same machine. The directly measured")
	fmt.Println("  in-process cost is BenchmarkDecideCall in cmd/gurdy-proxy.")

	problems := verdict(baseline, governed, before, after, *rate, *p50Gate, *p99Gate)
	problems = append(resolvable(first, second, baseline, *p50Gate, *p99Gate), problems...)
	fmt.Println()
	if len(problems) == 0 {
		fmt.Println("PASS  no drops, schedule held, added latency within the sidecar budget")
	}
	for _, p := range problems {
		fmt.Println("FAIL  " + p)
	}
	if *gated && len(problems) > 0 {
		os.Exit(1)
	}
}

// settle lets the previous arm's connections close and its garbage go, so the
// next arm is not charged for it.
func settle() {
	runtime.GC()
	time.Sleep(2 * time.Second)
}

// pool merges the two baseline arms into one distribution.
func pool(a, b result) result {
	out := result{label: "baseline", window: a.window + b.window}
	out.lat = append(append([]time.Duration{}, a.lat...), b.lat...)
	sort.Slice(out.lat, func(i, j int) bool { return out.lat[i] < out.lat[j] })
	if len(out.lat) > 0 {
		out.max = out.lat[len(out.lat)-1]
	}
	out.maxLag = max(a.maxLag, b.maxLag)
	return out
}

// resolvable answers the question the numbers cannot answer for themselves: is
// this machine quiet enough for the gate to mean anything?
//
// A 5ms p99 budget cannot be judged on a host whose *own* idle loopback p99 is
// 9ms — the thing being measured is smaller than the ruler's markings. Saying
// so is the whole point: a FAIL produced by measurement noise reads exactly
// like a FAIL produced by the proxy, and the second is actionable while the
// first is a wild goose chase. These come back as problems rather than as a
// pass, but they name the environment rather than the code.
func resolvable(first, second, baseline result, p50Gate, p99Gate time.Duration) (problems []string) {
	// Do the two baseline arms even agree with each other? If they differ by
	// more than the budget, the run-to-run swing is larger than the effect.
	drift := first.pct(99) - second.pct(99)
	if drift < 0 {
		drift = -drift
	}
	if drift > p99Gate {
		problems = append(problems, fmt.Sprintf(
			"INCONCLUSIVE: the two baseline arms disagree at p99 by %s, more than the %s budget — "+
				"this host's run-to-run swing is larger than the effect being measured",
			round(drift), p99Gate))
	}
	if baseline.pct(99) > p99Gate {
		problems = append(problems, fmt.Sprintf(
			"INCONCLUSIVE: the ungoverned baseline's own p99 is %s, above the %s added-latency budget — "+
				"a p99 gate cannot be resolved on this host. NFR-1 gates a deployed sidecar; measure it there. "+
				"The p50 comparison and the drop checks below are still meaningful",
			round(baseline.pct(99)), p99Gate))
	}
	if baseline.pct(50) > p50Gate {
		problems = append(problems, fmt.Sprintf(
			"INCONCLUSIVE: the baseline's own p50 is %s, above the %s budget — even the median is unresolvable here",
			round(baseline.pct(50)), p50Gate))
	}
	return problems
}

// verdict is where the harness refuses to flatter itself. Every check here is a
// reason a good-looking latency number would not mean what it appears to.
func verdict(baseline, governed result, before, after counters, rate int,
	p50Gate, p99Gate time.Duration) (problems []string) {

	if governed.errors > 0 {
		problems = append(problems, fmt.Sprintf("%d requests failed", governed.errors))
	}
	// Evidence loss beats latency. A proxy that sheds records under pressure
	// gets faster, so this check has to come before any celebration of the p99.
	if d := after.dropped - before.dropped; d > 0 {
		problems = append(problems, fmt.Sprintf(
			"the ledger dropped %d records during the run — the latency above was bought by losing evidence", d))
	}
	if d := after.writeErrors - before.writeErrors; d > 0 {
		problems = append(problems, fmt.Sprintf("%d ledger write errors", d))
	}
	// If the harness could not keep to its own schedule, the latency figures
	// describe a slower offered load than the one requested, and the tail is
	// understated. This is the coordinated-omission tripwire.
	if governed.maxLag > 50*time.Millisecond {
		problems = append(problems, fmt.Sprintf(
			"the generator fell %s behind schedule — offered load was below %d/s, so the tail is understated",
			round(governed.maxLag), rate))
	}
	if governed.saturated > 0 {
		problems = append(problems, fmt.Sprintf(
			"in-flight cap hit %d times — the harness, not the proxy, may be the bottleneck", governed.saturated))
	}
	if got := governed.achieved(); float64(got) < float64(rate)*0.95 {
		problems = append(problems, fmt.Sprintf(
			"achieved %.0f req/s against a %d/s target", got, rate))
	}
	if d := governed.pct(50) - baseline.pct(50); d > p50Gate {
		problems = append(problems, fmt.Sprintf("added p50 %s exceeds %s", round(d), p50Gate))
	}
	if d := governed.pct(99) - baseline.pct(99); d > p99Gate && baseline.pct(99) <= p99Gate {
		// Only claimed when the baseline was quiet enough for it to mean
		// something; resolvable() reports the other case as inconclusive rather
		// than letting noise read as a proxy defect.
		problems = append(problems, fmt.Sprintf("added p99 %s exceeds %s", round(d), p99Gate))
	}
	return problems
}

type result struct {
	label     string
	lat       []time.Duration // measured from each request's *scheduled* time
	max       time.Duration
	maxLag    time.Duration // worst gap between scheduled and actual start
	errors    int64
	saturated int64
	window    time.Duration
}

func (r result) achieved() float64 {
	if r.window == 0 {
		return 0
	}
	return float64(len(r.lat)) / r.window.Seconds()
}

func (r result) pct(p float64) time.Duration {
	if len(r.lat) == 0 {
		return 0
	}
	i := int(math.Ceil(p/100*float64(len(r.lat)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(r.lat) {
		i = len(r.lat) - 1
	}
	return r.lat[i]
}

func (r result) print() {
	fmt.Printf("%s n=%-7d %.0f/s   p50 %8s  p90 %8s  p99 %8s  p999 %8s  max %8s   lag %8s\n",
		r.label, len(r.lat), r.achieved(),
		round(r.pct(50)), round(r.pct(90)), round(r.pct(99)), round(r.pct(99.9)),
		round(r.max), round(r.maxLag))
}

// run emits requests on a fixed schedule and measures each from the instant it
// was due. Falling behind is recorded rather than absorbed.
func run(label, url string, body []byte, rate int, warmup, dur time.Duration, maxFlight int) result {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// Sized so connection setup is not what is being measured, and so
			// the client does not silently serialise onto two sockets.
			MaxIdleConns:        maxFlight,
			MaxIdleConnsPerHost: maxFlight,
			MaxConnsPerHost:     maxFlight,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	var (
		mu        sync.Mutex
		lat       []time.Duration
		maxLag    time.Duration
		errors    atomic.Int64
		saturated atomic.Int64
		wg        sync.WaitGroup
	)
	sem := make(chan struct{}, maxFlight)
	interval := time.Second / time.Duration(rate)

	fire := func(due time.Time, measure bool) {
		select {
		case sem <- struct{}{}:
		default:
			// No slot free at the moment this request was due. Waiting for one
			// is what a real client would do, and the wait belongs in the
			// latency — but it also means the harness may be the constraint, so
			// it is counted and reported.
			saturated.Add(1)
			sem <- struct{}{}
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			started := time.Now()
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				errors.Add(1)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				errors.Add(1)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				errors.Add(1)
				return
			}
			if !measure {
				return
			}
			// From `due`, not from `started`: the difference between them is
			// exactly the queueing delay a closed-loop harness throws away.
			mu.Lock()
			lat = append(lat, time.Since(due))
			if lag := started.Sub(due); lag > maxLag {
				maxLag = lag
			}
			mu.Unlock()
		}()
	}

	start := time.Now()
	warmEnd := start.Add(warmup)
	end := warmEnd.Add(dur)
	for i := 0; ; i++ {
		due := start.Add(time.Duration(i) * interval)
		if due.After(end) {
			break
		}
		if d := time.Until(due); d > 0 {
			time.Sleep(d)
		}
		fire(due, !due.Before(warmEnd))
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	r := result{label: label, lat: lat, maxLag: maxLag,
		errors: errors.Load(), saturated: saturated.Load(), window: dur}
	if len(lat) > 0 {
		r.max = lat[len(lat)-1]
	}
	return r
}

type counters struct{ dropped, writeErrors, identityFailed int64 }

// dropCounters reads /health. Absent an admin URL the run still reports latency
// but cannot make the evidence-loss check, and says so.
func dropCounters(admin string) counters {
	if admin == "" {
		return counters{}
	}
	resp, err := http.Get(strings.TrimRight(admin, "/") + "/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: no /health (%v) — cannot check for dropped records\n", err)
		return counters{}
	}
	defer resp.Body.Close()
	var h struct {
		Dropped        int64 `json:"dropped"`
		WriteErrors    int64 `json:"write_errors"`
		IdentityFailed int64 `json:"identity_failed"`
	}
	json.NewDecoder(resp.Body).Decode(&h)
	return counters{h.Dropped, h.WriteErrors, h.IdentityFailed}
}

// mcpBody builds a real tools/call frame of approximately the requested size,
// so the proxy parses what it would really parse rather than skipping a body it
// cannot read.
func mcpBody(size int) []byte {
	const shell = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt","pad":""}}}`
	if pad := size - len(shell); pad > 0 {
		return []byte(strings.Replace(shell, `"pad":""`,
			`"pad":"`+strings.Repeat("x", pad)+`"`, 1))
	}
	return []byte(shell)
}

func round(d time.Duration) time.Duration { return d.Round(time.Microsecond) }

// soakRun drives one sustained arm at -proxy and reports each window on its own
// line, because the question is a *trend*: a single aggregate over thirty
// minutes would average away exactly the creep it is meant to expose. A p99
// that doubles between window 1 and window 30 and a p99 that is flat produce
// the same number when you pool them.
//
// It reports rather than judges. There is no pass/fail here because the
// thresholds worth gating on are not known yet — this run is what establishes
// them, and a gate invented before the first measurement is a guess wearing a
// number's clothes.
func soakRun(proxyURL, admin string, body []byte, rate int, warmup, window, total time.Duration, maxFlight int) {
	if proxyURL == "" {
		fmt.Fprintln(os.Stderr, "soak needs -proxy")
		os.Exit(2)
	}
	windows := int(total / window)
	if windows < 2 {
		fmt.Fprintln(os.Stderr, "soak needs at least two windows to show a trend")
		os.Exit(2)
	}
	fmt.Printf("gurdy-bench soak: %d req/s open loop, %d x %s = %s, %d KiB bodies, GOMAXPROCS=%d\n",
		rate, windows, window, total, len(body)>>10, runtime.GOMAXPROCS(0))
	fmt.Println("drift, not attribution: no baseline arm, no gate — see -soak in the source")
	fmt.Println()

	start := dropCounters(admin)
	var first, last result
	for i := range windows {
		// Warm up only the first window. Warming up each one would insert a
		// gap in the load every window, which is precisely the recovery a soak
		// must not hand the system under test.
		w := time.Duration(0)
		if i == 0 {
			w = warmup
		}
		r := run(fmt.Sprintf("w%02d", i+1), proxyURL, body, rate, w, window, maxFlight)
		r.print()
		if i == 0 {
			first = r
		}
		last = r
	}
	end := dropCounters(admin)

	fmt.Println("\ndrift, first window -> last:")
	for _, line := range driftLines(first, last) {
		fmt.Println(line)
	}

	// Evidence loss over the whole soak. A proxy that sheds records under
	// sustained load is not "fast", it has stopped being the thing it is for.
	if admin == "" {
		fmt.Println("\n  no -admin: evidence-loss over the soak was NOT checked")
		return
	}
	fmt.Printf("\nledger over the soak: dropped %+d, write errors %+d, identity failures %+d\n",
		end.dropped-start.dropped, end.writeErrors-start.writeErrors, end.identityFailed-start.identityFailed)
	if end.dropped > start.dropped || end.writeErrors > start.writeErrors {
		fmt.Println("EVIDENCE LOST during the soak — latency figures above are secondary to this")
	}
}

// driftLines renders the first-window-to-last comparison. Extracted from
// soakRun so the arithmetic is testable without a thirty-minute run — and the
// failure worth testing for is not a wrong percentage, it is a summary that
// compares a window to *itself*. That reports "+0.0%, no drift" for every run
// forever, looks exactly like a healthy result, and is the vacuous-pass shape
// this repo keeps finding in its own gates.
func driftLines(first, last result) []string {
	return []string{
		fmt.Sprintf("  p50  %8s -> %-8s   %+.1f%%", round(first.pct(50)), round(last.pct(50)), pctChange(first.pct(50), last.pct(50))),
		fmt.Sprintf("  p99  %8s -> %-8s   %+.1f%%", round(first.pct(99)), round(last.pct(99)), pctChange(first.pct(99), last.pct(99))),
		fmt.Sprintf("  rate %8.0f -> %-8.0f", first.achieved(), last.achieved()),
	}
}

func pctChange(from, to time.Duration) float64 {
	if from == 0 {
		return 0
	}
	return (float64(to) - float64(from)) / float64(from) * 100
}
