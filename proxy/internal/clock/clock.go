// Package clock records how long the proxy's own work takes, live, per stage.
//
// It exists because of a question the offline harness could not answer: of the
// latency an agent sees, how much did *we* add? `cmd/gurdy-bench` answers that
// for a controlled run on a quiet host. This answers it continuously, in
// production, for the part of the budget the proxy actually owns.
//
// Three properties are load-bearing.
//
// **It measures our work, not the call.** Every stage here is in-process, timed
// on a monotonic clock with no network in the measured region. That is the whole
// reason the numbers mean anything: the hop, the upstream and the OS scheduler
// contribute a tail an order of magnitude larger than the proxy's own work, so a
// figure that includes them describes the deployment rather than the code. What
// this package cannot see is stated in its own output, because a reader who
// mistakes "decide p99 = 300µs" for the NFR-1 number has been misled by us.
//
// **Percentiles, never averages.** An average is precisely what hides a tail,
// and the tail is the gated quantity (§3.2 NFR-1 is a p50/p99 budget). A mean
// service time would have shown nothing wrong in any of the defects found so
// far.
//
// **Free enough to leave on.** One monotonic clock read and atomic adds into a
// fixed bucket array: no locks, no allocation, no map lookup. Measured at
// **~100ns per observation with every core contending** and zero allocations —
// 0.03% of the ~300µs stage it instruments, and less than that uncontended.
// Measuring latency with something that costs latency is self-defeating, so
// there is no flag to turn it off: a knob for a cost this size is a knob nobody
// should have to think about, and one that defaults off is a tool nobody has
// when they need it.
package clock

import (
	"math/bits"
	"sync/atomic"
	"time"
)

// Bucket layout: log-linear, 16 sub-buckets per power of two. The widest bucket
// in an octave is 1/16 of its lower bound, so a reported percentile is within
// **6.25%** of the true value — stated rather than implied, because a histogram
// percentile is an estimate and one presented as exact is a small lie.
const (
	subBits   = 4
	subCount  = 1 << subBits // 16
	octaves   = 32           // covers 1ns to ~68s
	numBucket = subCount + octaves*subCount
)

// bucketFor maps a nanosecond duration to its bucket.
func bucketFor(ns int64) int {
	if ns < 0 {
		return 0
	}
	if ns < subCount {
		return int(ns)
	}
	octave := bits.Len64(uint64(ns)) - 1 // floor(log2)
	k := octave - subBits
	if k >= octaves {
		return numBucket - 1 // saturate rather than panic; 68s is not a latency
	}
	base := int64(subCount) << k
	sub := (ns - base) >> k
	return subCount + k*subCount + int(sub)
}

// lowerBound is the smallest duration a bucket can hold, used to report
// percentiles. Conservative on purpose: a percentile is reported as the low edge
// of its bucket, so the tool understates rather than overstates.
func lowerBound(i int) int64 {
	if i < subCount {
		return int64(i)
	}
	k := (i - subCount) / subCount
	sub := (i - subCount) % subCount
	return (int64(subCount) << k) + int64(sub)<<k
}

// Stage is one timed step of the governance loop.
type Stage struct {
	name    string
	buckets [numBucket]atomic.Uint64
	count   atomic.Uint64
	sum     atomic.Int64
	maximum atomic.Int64
}

// The stages, declared rather than looked up: a map lookup per observation would
// cost more than the measurement. Names match the §4.2 loop so a reader can line
// a number up against the stage that produced it.
var (
	Decide   = &Stage{name: "decide"}   // the whole in-process decision
	Identify = &Stage{name: "identify"} // txn verify + derive + verify (three ES256 ops)
	Classify = &Stage{name: "classify"} // the extractor registry
	Evaluate = &Stage{name: "evaluate"} // Cedar
	Attest   = &Stage{name: "attest"}   // handing the record to the ledger queue
	Respond  = &Stage{name: "respond"}  // hashing the response on its way back
)

var all = []*Stage{Decide, Identify, Classify, Evaluate, Attest, Respond}

// Observe records one duration. Safe from any goroutine; never blocks.
func (s *Stage) Observe(d time.Duration) {
	ns := int64(d)
	s.buckets[bucketFor(ns)].Add(1)
	s.count.Add(1)
	s.sum.Add(ns)
	// Racy under contention — two goroutines can both read a stale max — which
	// is acceptable for a diagnostic and is why the percentiles, not this, are
	// the number to trust. A CAS loop here would put a contended write on the
	// hot path to improve a field nobody gates on.
	if m := s.maximum.Load(); ns > m {
		s.maximum.Store(ns)
	}
}

// Time is the ergonomic form: `defer clock.Decide.Time()()`.
func (s *Stage) Time() func() {
	start := time.Now()
	return func() { s.Observe(time.Since(start)) }
}

// Snapshot is one stage's distribution at a point in time.
type Snapshot struct {
	Stage string `json:"stage"`
	Count uint64 `json:"count"`
	// Durations in microseconds: nanoseconds are noise at this resolution and
	// milliseconds lose the stages that matter (classify runs in ~160ns).
	MeanUS float64 `json:"mean_us"`
	P50US  float64 `json:"p50_us"`
	P90US  float64 `json:"p90_us"`
	P99US  float64 `json:"p99_us"`
	P999US float64 `json:"p999_us"`
	MaxUS  float64 `json:"max_us"`
}

func (s *Stage) Snapshot() Snapshot {
	n := s.count.Load()
	out := Snapshot{Stage: s.name, Count: n}
	if n == 0 {
		return out
	}
	out.MeanUS = float64(s.sum.Load()) / float64(n) / 1000
	out.MaxUS = float64(s.maximum.Load()) / 1000

	// One pass, reading each bucket once: re-walking per percentile could see
	// different totals for each and report a p50 above the p99.
	counts := make([]uint64, numBucket)
	var total uint64
	for i := range counts {
		counts[i] = s.buckets[i].Load()
		total += counts[i]
	}
	if total == 0 {
		return out
	}
	targets := []struct {
		p   float64
		dst *float64
	}{{50, &out.P50US}, {90, &out.P90US}, {99, &out.P99US}, {99.9, &out.P999US}}
	var cum uint64
	ti := 0
	for i, c := range counts {
		if c == 0 {
			continue
		}
		cum += c
		for ti < len(targets) && float64(cum) >= targets[ti].p/100*float64(total) {
			*targets[ti].dst = float64(lowerBound(i)) / 1000
			ti++
		}
		if ti == len(targets) {
			break
		}
	}
	return out
}

// Report is everything the tool knows, including what it does not.
type Report struct {
	// Measures says what these numbers cover. It ships in the payload rather
	// than only in documentation because the failure mode is someone reading
	// "decide p99 = 300µs" as the NFR-1 figure and concluding the budget is
	// spent, or safe, on a number that excludes the largest term.
	Measures string     `json:"measures"`
	Excludes string     `json:"excludes"`
	Accuracy string     `json:"accuracy"`
	Stages   []Snapshot `json:"stages"`
}

func Snapshots() Report {
	out := Report{
		Measures: "the proxy's own in-process work, per stage of the governance loop (§4.2), " +
			"timed on a monotonic clock",
		Excludes: "the network hop to and from the proxy, the upstream's own service time, and OS " +
			"scheduling delay. NFR-1's budget is hop + derive + extract + eval; only the terms " +
			"after 'hop' appear here, so these numbers are a lower bound on added latency and " +
			"cannot certify the gate on their own",
		Accuracy: "log-linear buckets, 16 per octave: reported percentiles are within 6.25% of the " +
			"true value and are the low edge of their bucket, so they understate rather than overstate",
	}
	for _, s := range all {
		out.Stages = append(out.Stages, s.Snapshot())
	}
	return out
}

// Reset clears every stage. For tests, and for an operator who wants a window
// rather than the process lifetime.
func Reset() {
	for _, s := range all {
		for i := range s.buckets {
			s.buckets[i].Store(0)
		}
		s.count.Store(0)
		s.sum.Store(0)
		s.maximum.Store(0)
	}
}
