package clock

import (
	"math"
	"sync"
	"testing"
	"time"
)

// A histogram that reports the wrong percentile is worse than no histogram: it
// is a number someone will act on. These check the bucket arithmetic against
// known distributions, the concurrency safety, and the one property that lets
// this run in production — that observing costs almost nothing.

func TestBucketsAreMonotonicAndWithinStatedError(t *testing.T) {
	// The claim in the package doc is 6.25%. If the bucket layout drifts, this
	// is where it gets caught rather than in a report someone trusts.
	var prev int64 = -1
	for i := 0; i < numBucket; i++ {
		lb := lowerBound(i)
		if lb <= prev {
			t.Fatalf("bucket %d lower bound %d not above previous %d", i, lb, prev)
		}
		prev = lb
		if b := bucketFor(lb); b != i {
			t.Fatalf("bucket %d's own lower bound %dns maps to bucket %d", i, lb, b)
		}
		if i >= subCount {
			next := lowerBound(i + 1)
			if i+1 >= numBucket {
				break
			}
			if width, base := next-lb, lb; float64(width)/float64(base) > 0.0625+1e-9 {
				t.Fatalf("bucket %d spans %.4f of its base, above the stated 6.25%%",
					i, float64(width)/float64(base))
			}
		}
	}
}

func TestPercentilesTrackAKnownDistribution(t *testing.T) {
	Reset()
	// 1..1000µs, uniform. p50 ≈ 500µs, p99 ≈ 990µs — within the bucket error.
	for i := 1; i <= 1000; i++ {
		Decide.Observe(time.Duration(i) * time.Microsecond)
	}
	got := Decide.Snapshot()
	if got.Count != 1000 {
		t.Fatalf("count %d, want 1000", got.Count)
	}
	for _, tc := range []struct {
		name string
		got  float64
		want float64
	}{
		{"p50", got.P50US, 500},
		{"p90", got.P90US, 900},
		{"p99", got.P99US, 990},
	} {
		// One bucket width of tolerance, on the low side only: percentiles are
		// reported as the low edge, so they must never come out *above* truth.
		if tc.got > tc.want+1 || tc.got < tc.want*0.9375-1 {
			t.Errorf("%s = %.1fµs, want ≈%.0fµs (within 6.25%%, never above)", tc.name, tc.got, tc.want)
		}
	}
	if got.MeanUS < 480 || got.MeanUS > 520 {
		t.Errorf("mean %.1fµs, want ≈500µs", got.MeanUS)
	}
}

func TestPercentilesNeverInvertUnderConcurrentObservation(t *testing.T) {
	// A snapshot that re-read the buckets per percentile could see a growing
	// total between reads and report a p50 above the p99. Observing while
	// snapshotting is the case that would expose it.
	Reset()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				Decide.Observe(time.Duration(1+i%5000) * time.Microsecond)
			}
		}(w)
	}
	for i := 0; i < 200; i++ {
		s := Decide.Snapshot()
		if s.Count == 0 {
			continue
		}
		if s.P50US > s.P90US || s.P90US > s.P99US || s.P99US > s.P999US {
			t.Fatalf("percentiles inverted mid-flight: p50=%.0f p90=%.0f p99=%.0f p999=%.0f",
				s.P50US, s.P90US, s.P99US, s.P999US)
		}
	}
	close(stop)
	wg.Wait()
}

func TestExtremesDoNotPanic(t *testing.T) {
	Reset()
	for _, d := range []time.Duration{
		0, time.Nanosecond, -time.Second, // a clock that went backwards
		time.Hour, // beyond the bucket range: saturates, does not crash
		math.MaxInt64,
	} {
		Decide.Observe(d)
	}
	if got := Decide.Snapshot(); got.Count != 5 {
		t.Errorf("count %d, want 5", got.Count)
	}
}

func TestReportSaysWhatItCannotMeasure(t *testing.T) {
	// The most important field in the payload. Someone reading a 300µs p99 as
	// the NFR-1 number has been misled by us, so the exclusion travels with the
	// data rather than living only in a doc they did not open.
	r := Snapshots()
	if r.Excludes == "" || r.Measures == "" || r.Accuracy == "" {
		t.Fatal("a report that does not state its own scope is a trap")
	}
	if len(r.Stages) != len(all) {
		t.Errorf("reported %d stages, have %d", len(r.Stages), len(all))
	}
}

// The property that decides whether this can be left on in production. If
// observing ever costs a material fraction of the work it measures, the tool has
// changed the thing it was built to report. Asserted relative to the machine it
// runs on, never in absolute nanoseconds — see inside.
func TestObserveIsCheapEnoughToLeaveOn(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}

	// Two assertions, because neither alone covers the regression this test
	// exists for, and both are deliberately machine-independent.
	//
	// This used to assert an absolute budget ("under 1µs per call") and it
	// failed in CI on code that had not regressed at all. Measured:
	//
	//     local, no -race     4ns      the number the claim is actually about
	//     local, -race      157ns      the detector instruments every atomic
	//     CI,    -race     1937ns      plus a slower shared runner
	//
	// 480x, none of it ours. An absolute nanosecond budget measures the host
	// and the toolchain; under -race it measures instrumented atomics, so it
	// cannot speak to production cost at any threshold. gurdy-bench already
	// refuses to blame the proxy for the machine (§8.2) and reports
	// INCONCLUSIVE instead — the same rule has to apply to our own unit test,
	// or the gate teaches people to ignore it.

	// 1. Zero allocations. Exact, and identical with and without -race, so it
	//    is the right tool for the one regression the ratio below cannot see:
	//    an added allocation is cheap enough to hide inside timing noise.
	Reset()
	if n := testing.AllocsPerRun(1000, func() { Decide.Observe(287 * time.Microsecond) }); n != 0 {
		t.Errorf("Observe allocates %v times per call — it must not allocate on the hot path", n)
	}

	// 2. Cost relative to the cheapest thing Observe could possibly be: one
	//    atomic add. Calibrating against the same machine in the same run
	//    cancels both the runner's speed and the race detector's overhead.
	//
	//    Skipped under -race, which is not a convenience: the detector
	//    instruments every atomic access, and it does not merely add noise — it
	//    *compresses the signal*. Measured with a mutex added to Observe:
	//
	//                      baseline   + mutex   + map    + alloc
	//        -race  arm64     1.3        3.1      2.0       —
	//        -race  amd64     1.3        2.5      1.6       —
	//        clean  arm64     1.2        2.2      3.1      4.6
	//        clean  amd64     1.6        3.0      3.3      5.9
	//
	//    Under -race a real mutex regression (2.5) sits below where a clean
	//    build puts a *map lookup* (3.1), so no threshold separates them. Clean,
	//    the worst baseline is 1.6 and the cheapest regression is 2.2 on both
	//    architectures. CI runs this test in a separate non-race pass.
	//
	//    The reference is not "one atomic add" — that was the first attempt and
	//    is not architecture-neutral: a bare atomic add is one LOCK XADD on x86
	//    but an LL/SC loop on arm64, which scored an unregressed Observe at 4.1x
	//    on arm64 and 16.1x on x86_64. Mirroring Observe's own atomics makes the
	//    ratio ~1 by construction anywhere.
	const maxRatio = 2.0
	if raceDetector {
		t.Log("timing ratio skipped under -race; the allocation check above still ran")
		return
	}
	ratio := observeRatio()
	t.Logf("Observe costs %.1fx the same atomic work done inline", ratio)
	if ratio > maxRatio {
		t.Errorf("Observe costs %.1fx its own atomic work (limit %.1fx) — someone added a lock or a map lookup",
			ratio, maxRatio)
	}
}

// observeRatio times Observe against a reference doing the *same* atomic work.
//
// The reference is not "one atomic add". That was the first attempt and it is
// not architecture-neutral: a bare atomic add is a single LOCK XADD on x86 but
// an LL/SC loop on arm64, so the baseline is disproportionately cheap on x86
// and inflates the ratio. Measured under -race: 4.1x on arm64 and 16.1x on
// x86_64 for identical, unregressed code — a single threshold cannot serve both.
//
// Comparing against the same operations Observe performs makes the ratio ~1 by
// construction on any architecture, because both sides get whatever treatment
// that architecture and the race detector give atomics. What is left is exactly
// what this test is for: structural additions — a lock, a map lookup — which
// show up as a clear multiple regardless of the machine underneath.
func observeRatio() float64 {
	const n = 500_000
	best := func(f func()) time.Duration {
		lowest := time.Duration(math.MaxInt64)
		for i := 0; i < 3; i++ {
			start := time.Now()
			f()
			// Minimum of each side independently, not the minimum of the
			// ratios: a slow baseline sample and a fast Observe sample are not
			// a matched pair, and pairing them flatters the result. That error
			// let a map-lookup regression pass at 4.1x.
			if d := time.Since(start); d < lowest {
				lowest = d
			}
		}
		return lowest
	}

	// Mirrors Observe: three atomic adds, one load, one conditional store.
	var ref Stage
	base := best(func() {
		for i := 0; i < n; i++ {
			ns := int64(i % 100000)
			ref.buckets[0].Add(1)
			ref.count.Add(1)
			ref.sum.Add(ns)
			if m := ref.maximum.Load(); ns > m {
				ref.maximum.Store(ns)
			}
		}
	})
	obs := best(func() {
		Reset()
		for i := 0; i < n; i++ {
			Decide.Observe(time.Duration(i%100000) * time.Nanosecond)
		}
	})
	return float64(obs) / float64(base)
}
