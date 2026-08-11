package main

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncWriter counts writes as well as collecting bytes, because "how many times
// did this touch the underlying writer" is the property the buffering exists for.
type syncWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
	delay  time.Duration
}

func (s *syncWriter) Write(p []byte) (int, error) {
	if s.delay > 0 {
		time.Sleep(s.delay) // stand in for a slow disk
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	return s.buf.Write(p)
}

func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *syncWriter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func TestFlushWriterLosesNothingOnClose(t *testing.T) {
	out := &syncWriter{}
	// A long tick, so only Close can be responsible for the bytes arriving.
	f := newFlushWriter(out, time.Hour)
	for i := 0; i < 500; i++ {
		fmt.Fprintf(f, "line %d\n", i)
	}
	if out.count() != 0 {
		t.Fatalf("wrote through before a flush was due: %d writes", out.count())
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), "\n"); got != 500 {
		t.Errorf("recovered %d lines, want 500 — buffered log lines were lost", got)
	}
}

func TestFlushWriterCloseIsIdempotent(t *testing.T) {
	// Close runs from a defer that a signal path can reach twice; a second call
	// must not panic on a closed channel or duplicate the buffer.
	out := &syncWriter{}
	f := newFlushWriter(out, time.Hour)
	fmt.Fprint(f, "once\n")
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "once\n" {
		t.Errorf("got %q, want %q", got, "once\n")
	}
}

func TestFlushWriterConcurrentWritersKeepWholeLines(t *testing.T) {
	// slog writes one record per Write call; interleaving them would corrupt the
	// log into unparseable fragments, which is worse than dropping it.
	out := &syncWriter{}
	f := newFlushWriter(out, 5*time.Millisecond)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				fmt.Fprintf(f, "writer-%d-line-%d\n", w, i)
			}
		}(w)
	}
	wg.Wait()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 8*200 {
		t.Fatalf("got %d lines, want %d", len(lines), 8*200)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "writer-") || strings.Count(l, "writer-") != 1 {
			t.Fatalf("interleaved write corrupted a line: %q", l)
		}
	}
}

// The property the whole type exists for: a slow underlying writer must not
// block the callers. This is what the bufio version got wrong — it held the lock
// across the flush, so every logger queued behind one disk write.
func TestFlushWriterDoesNotBlockCallersOnSlowIO(t *testing.T) {
	out := &syncWriter{delay: 150 * time.Millisecond}
	f := newFlushWriter(out, 5*time.Millisecond)
	defer f.Close()

	fmt.Fprint(f, "prime the buffer so a flush is pending\n")
	time.Sleep(20 * time.Millisecond) // let the flusher pick it up and stall in Write

	start := time.Now()
	for i := 0; i < 100; i++ {
		fmt.Fprintf(f, "line %d\n", i)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("callers waited %s on a flush to a slow writer — the lock is held across I/O", elapsed)
	}
}
