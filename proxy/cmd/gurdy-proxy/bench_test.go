package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GurdyAI/gurdy/proxy/internal/extract"
	"github.com/GurdyAI/gurdy/proxy/internal/tis"
)

// The per-call hot path, benchmarked as the proxy actually runs it.
//
// §3.2 NFR-1 defines that path as "hop + derive + extract + eval", with mint
// explicitly per-task and amortized. These measure everything except the hop —
// the hop needs a real listener and real concurrency, which is gurdy-bench's
// job, because §8.2 forbids certifying NFR-1 by summing standalone numbers.
//
// What these are for is the opposite of certification: finding which component
// dominates, and catching a change that makes one of them an order of magnitude
// worse. A composed measurement tells you whether you passed; only these tell
// you why.

// BenchmarkDecideCall is the whole in-process decision: identify (verify the
// txn, derive a call assertion, verify it), classify, evaluate, and enqueue the
// record. Everything the proxy does between reading the body and forwarding it.
func BenchmarkDecideCall(b *testing.B) {
	h := newHarness(b)
	g := newGateway(h.store, h.tis, h.led, "bench", slogTo(&syncBuffer{}))
	body := []byte(credReadCall)
	call := extract.Call{
		Tool:      "read_file",
		Arguments: map[string]any{"path": "/home/u/.ssh/id_rsa"},
		Host:      "upstream.local",
		Path:      "/",
		Body:      body,
	}
	b.ReportAllocs()
	for b.Loop() {
		g.decideCall(context.Background(), "", "host:127.0.0.1", call, body)
	}
}

// BenchmarkDecideCallParallel is the same work under contention, which is where
// a shared lock stops being free.
//
// `identify` reaches `autoMint` on every call that arrives without a
// `Gurdy-Txn` header — the no-SDK path, and therefore the common one — and
// autoMint takes a process-wide mutex and performs an ES256 *verify* of the
// cached token while holding it. That serialises every concurrent request
// behind one signature check. This benchmark against the serial one above is
// what makes the cost of that visible rather than theoretical.
func BenchmarkDecideCallParallel(b *testing.B) {
	h := newHarness(b)
	g := newGateway(h.store, h.tis, h.led, "bench", slogTo(&syncBuffer{}))
	body := []byte(credReadCall)
	call := extract.Call{
		Tool:      "read_file",
		Arguments: map[string]any{"path": "/home/u/.ssh/id_rsa"},
		Host:      "upstream.local",
		Path:      "/",
		Body:      body,
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			g.decideCall(context.Background(), "", "host:127.0.0.1", call, body)
		}
	})
}

// BenchmarkIdentify isolates the identity work, which the numbers say dominates
// everything else on this path: three ES256 operations per call (verify the
// incoming txn, sign the call assertion, verify that assertion).
func BenchmarkIdentify(b *testing.B) {
	h := newHarness(b)
	g := newGateway(h.store, h.tis, h.led, "bench", slogTo(&syncBuffer{}))
	b.ReportAllocs()
	for b.Loop() {
		g.identify("", "host:127.0.0.1", "read_file")
	}
}

// BenchmarkExtract is the classify stage. Included because §8.2 names extract
// as one of the four hot-path components, and because a registry that grew an
// expensive matcher should show up here rather than in a composed number where
// it would hide behind the crypto.
func BenchmarkExtract(b *testing.B) {
	body := []byte(credReadCall)
	call := extract.Call{
		Tool:      "read_file",
		Arguments: map[string]any{"path": "/home/u/.ssh/id_rsa"},
		Host:      "upstream.local",
		Path:      "/",
		Body:      body,
	}
	b.ReportAllocs()
	for b.Loop() {
		extract.Default.Classify(call)
	}
}

// BenchmarkBodyInspection measures roadmap D5 — the request body is read whole
// before anything is forwarded, capped at 4MB.
//
// The cost is what decides whether D5 is debt or a defect. Buffering is not
// free, but it is also not obviously the thing that blows the NFR-1 budget when
// three ES256 operations are on the same path; this is the measurement that
// settles which.
func BenchmarkBodyInspection(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20, 4 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			// A real MCP frame of the requested size: the padding rides in an
			// argument, so the parser does the work it would really do.
			pad := strings.Repeat("x", size)
			body := []byte(fmt.Sprintf(
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x","pad":%q}}}`,
				pad))
			h := newHarness(b)
			g := newGateway(h.store, h.tis, h.led, "bench", slogTo(&syncBuffer{}))
			call := extract.Call{
				Tool: "read_file", Arguments: map[string]any{"path": "/tmp/x"},
				Host: "upstream.local", Path: "/", Body: body,
			}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				g.decideCall(context.Background(), "", "host:127.0.0.1", call, body)
			}
		})
	}
}

// BenchmarkDecideCallParallelWithTxn is the same parallel load, but with a
// valid Gurdy-Txn supplied — the SDK-present path, which skips autoMint and
// therefore skips the process-wide lock.
//
// Against BenchmarkDecideCallParallel this isolates the cost of that lock. The
// two paths do the same number of ES256 operations, so a large difference is
// contention and nothing else.
func BenchmarkDecideCallParallelWithTxn(b *testing.B) {
	h := newHarness(b)
	g := newGateway(h.store, h.tis, h.led, "bench", slogTo(&syncBuffer{}))
	scope := tis.Scope{Compartments: []string{"*"}, ResourceTypes: []string{"*"},
		Actions: []string{"*"}, Purpose: "*"}
	txn, err := h.tis.MintTxn("agent", "alice", scope, "v0", 0)
	if err != nil {
		b.Fatal(err)
	}
	body := []byte(credReadCall)
	call := extract.Call{
		Tool: "read_file", Arguments: map[string]any{"path": "/home/u/.ssh/id_rsa"},
		Host: "upstream.local", Path: "/", Body: body,
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			g.decideCall(context.Background(), txn, "host:127.0.0.1", call, body)
		}
	})
}

// BenchmarkResponseHashing bounds the *response*-side cost, which the decision
// benchmarks miss entirely and which behaves differently from all of them.
//
// Every byte returned to the client is hashed on the way past (§4.3 step 6).
// That is a per-byte cost with **no cap** — the request body stops being
// inspected past maxInspect, but a response is hashed however large it is,
// because a partial hash is not evidence of anything. Measured at ~2.1 GB/s, so
// roughly 0.45µs per KiB: nothing for a typical MCP reply of a few KB, ~3ms for
// an 8 MB one, which is most of the NFR-1 p99 budget on its own.
//
// One nuance the number does not show: hashingWriter writes to the client
// *before* it hashes, so time-to-first-byte is unaffected. What grows is total
// transfer time, because the hash serialises between chunks.
func BenchmarkResponseHashing(b *testing.B) {
	chunk := make([]byte, 32<<10) // a realistic streaming chunk
	for _, size := range []int{4 << 10, 64 << 10, 1 << 20, 8 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				rw := &hashingWriter{
					ResponseWriter: httptest.NewRecorder(),
					h:              sha256.New(),
					status:         http.StatusOK,
				}
				for written := 0; written < size; written += len(chunk) {
					n := min(len(chunk), size-written)
					rw.Write(chunk[:n])
				}
				rw.h.Sum(nil)
			}
		})
	}
}
