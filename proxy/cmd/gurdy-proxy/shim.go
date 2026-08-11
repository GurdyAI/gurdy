package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/GurdyAI/gurdy/proxy/internal/extract"
	"github.com/GurdyAI/gurdy/proxy/internal/ledger"
	"github.com/GurdyAI/gurdy/proxy/internal/mcp"
)

// runShim wraps an MCP stdio server (§4.4 stdio shim): spawns argv, relays
// in→child-stdin and child-stdout→out unmodified, records a decision for every
// tools/call on the way in and a response record for the frame that answers it
// on the way out (D4, §5.5).
//
// The child's exit — not the relay — ends the shim: child-stdout EOF is the
// exit signal, so a crashed child never leaves the shim hung on an open
// client stdin (the blocked relay goroutine dies with the process).
func runShim(g *gateway, argv []string, in io.Reader, out io.Writer) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("shim: start %q: %w", argv[0], err)
	}

	coarse := "stdio:" + filepath.Base(argv[0])
	pend := &pending{m: map[string]*slot{}}
	outDone := make(chan error, 1)
	go func() { outDone <- relayOut(g, coarse, pend, childOut, out) }()
	relayDone := make(chan error, 1)
	go func() { relayDone <- relay(g, coarse, pend, in, childIn) }()

	copyErr := <-outDone
	waitErr := cmd.Wait()
	var relayErr error
	select {
	case relayErr = <-relayDone:
	default: // child exited with client stdin still open; nothing more to relay
	}
	return errors.Join(waitErr, copyErr, relayErr)
}

// pending joins a stdio decision to the frame that answers it, keyed by the
// JSON-RPC id (D4). HTTP gets this pairing from the transport; stdio is two
// independent byte streams, so the id is the only thing tying a response to
// the call it answers.
//
// Written by the input relay and read by the output relay — two goroutines,
// hence the lock. What makes it *correct* is elsewhere, and it is the same rule
// in both directions: the map is updated before the frame leaves. A call is
// tracked before its line reaches the child, so no response can arrive for an
// untracked call; an answer is claimed before it reaches the client, so the
// client cannot reuse an id this side still believes is in flight.
type pending struct {
	mu sync.Mutex
	m  map[string]*slot
	// off latches when correlation can no longer be trusted at all; see track.
	off bool
}

// slot is one id's state. inflight counts calls decided under this id and not
// yet seen answered — a *count*, not a flag, because the question that decides
// whether a later reuse is safe is "is anything still outstanding that could
// answer with this id", and one response does not retire two requests.
//
// ambiguous latches the moment a second call joins the id: from then on no
// frame carrying it can be attributed to a particular call. It clears only by
// the slot being dropped at inflight 0 — with nothing outstanding there is no
// delayed frame left to cross a later reuse, so the id becomes usable again.
type slot struct {
	callID    string
	inflight  int
	ambiguous bool
}

// maxPending bounds distinct in-flight ids, maxIDLen bounds one id's key. The
// second is not redundant: an id is raw JSON and may be a multi-megabyte
// string, so a count-only bound leaves memory unbounded.
const (
	maxPending = 4096
	maxIDLen   = 512
)

// track registers callID as decided under id.
//
// A duplicate id that is still in flight makes the *next* frame carrying it
// ambiguous, so neither call may be joined to it: a response record on the
// wrong call_id is misattributed evidence — strictly worse than none, because
// a reader cannot tell it is wrong. Both calls stay unanswered instead.
// JSON-RPC forbids reusing an in-flight id, but a client that does it is
// exactly the client whose evidence must not be trusted.
func (p *pending) track(id, callID string) {
	if !trackable(id) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.off {
		return
	}
	s := p.m[id]
	if s == nil {
		if len(p.m) >= maxPending {
			// No room for a new id means we cannot record that a call under it
			// is outstanding — and an unrecorded outstanding call is precisely
			// what crosses a later reuse of the same id. There is no state left
			// to be conservative *with*, so correlation stops for the session:
			// every call from here is unanswered, which is a reading a reporter
			// can act on, where a crossed join is not. Reaching this needs 4096
			// distinct un-answered ids on one stdio pipe.
			p.off, p.m = true, map[string]*slot{}
			return
		}
		s = &slot{}
		p.m[id] = s
	}
	s.inflight++
	if s.inflight > 1 {
		s.ambiguous, s.callID = true, ""
		return
	}
	s.callID = callID
}

// claim consumes the pending call for id, "" when there is none — an untracked
// frame, or an id whose outstanding calls make it ambiguous.
func (p *pending) claim(id string) string {
	if !trackable(id) {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.m[id]
	if s == nil {
		return ""
	}
	if s.inflight--; s.inflight <= 0 {
		delete(p.m, id) // nothing outstanding: a later reuse starts clean
	}
	if s.ambiguous {
		return ""
	}
	callID := s.callID
	s.callID = ""
	return callID
}

// trackable rejects the ids that cannot be correlated, in *both* directions —
// consistent refusal, so there is never state on one side that the other side
// could cross. An oversized id is refused for memory (see maxIDLen); "" is a
// notification, which nothing answers.
func trackable(id string) bool { return id != "" && len(id) <= maxIDLen }

// relay forwards newline-delimited frames to the child, deciding each
// tools/call. Lines beyond maxInspect are forwarded uninspected and recorded
// indeterminate (§5.1) — same bound and semantics as the HTTP path.
func relay(g *gateway, coarse string, pend *pending, in io.Reader, childIn io.WriteCloser) error {
	defer childIn.Close()
	rd := bufio.NewReaderSize(in, maxInspect)
	skipping := false // inside an oversized line, forwarding until its newline
	for {
		chunk, err := rd.ReadSlice('\n')
		if len(chunk) > 0 {
			if !skipping {
				if err == bufio.ErrBufferFull {
					// No id was parsed, so nothing can answer this: the call is
					// recorded indeterminate and left unanswered.
					g.indeterminateCall(coarse, ledger.AssertionAbsent, "line exceeds inspection limit")
				} else {
					for _, tc := range mcp.ParseToolsCalls(chunk) {
						if tc.Name == "" {
							pend.track(tc.ID, g.indeterminateCall(coarse, ledger.AssertionAbsent, "undecodable tools/call params"))
							continue
						}
						pend.track(tc.ID, g.decideCall(context.Background(), "", coarse, extract.Call{
							Tool: tc.Name, Arguments: tc.Arguments,
						}, chunk))
					}
				}
			}
			if _, werr := childIn.Write(chunk); werr != nil {
				return fmt.Errorf("shim: write to child: %w", werr)
			}
		}
		switch err {
		case nil:
			skipping = false
		case bufio.ErrBufferFull:
			skipping = true
		case io.EOF:
			return nil
		default:
			return fmt.Errorf("shim: read client: %w", err)
		}
	}
}

// relayOut forwards the child's frames to the client and records the response
// half of every call they answer.
//
// The claim happens *before* the frame reaches the client, same order as
// relay(). It is tempting to write first — nothing may act on a response, so
// inspection here can only cost time — but the client is a participant, not an
// observer: let it see the answer to id 1 first and it may legally reuse id 1
// before this side has retired the pending entry, at which point track() sees
// an id apparently still in flight and refuses to correlate a call that was
// never ambiguous. A sequential-id client would lose most of its response
// records to a race with itself. The cost of claiming first is one JSON parse
// and a non-blocking enqueue, which is not a delay any protocol can observe.
func relayOut(g *gateway, coarse string, pend *pending, childOut io.Reader, out io.Writer) error {
	rd := bufio.NewReaderSize(childOut, maxInspect)
	skipping := false
	for {
		chunk, err := rd.ReadSlice('\n')
		if len(chunk) > 0 {
			// An oversized frame is relayed but not parsed, so the call it
			// answers stays unanswered — same bound, same visibility as the
			// request direction.
			if !skipping && err != bufio.ErrBufferFull {
				g.recordResponses(coarse, pend, chunk)
			}
			if _, werr := out.Write(chunk); werr != nil {
				return fmt.Errorf("shim: write to client: %w", werr)
			}
		}
		switch err {
		case nil:
			skipping = false
		case bufio.ErrBufferFull:
			skipping = true
		case io.EOF:
			return nil
		default:
			return fmt.Errorf("shim: read child: %w", err)
		}
	}
}

// recordResponses writes the response half of each call the line answers
// (§5.5). Unlike the HTTP path, correlation here is per frame rather than per
// envelope, so a batched call's resp_hash covers only the element that
// answered it.
func (g *gateway) recordResponses(coarse string, pend *pending, line []byte) {
	// Trim the delimiter before parsing: it is framing, not content. A batch
	// element never carries one, so leaving it on would make the same response
	// hash differently depending on whether it arrived batched.
	for _, r := range mcp.ParseResponses(bytes.TrimRight(line, "\r\n")) {
		callID := pend.claim(r.ID)
		if callID == "" {
			continue // answers nothing we decided, or an ambiguous id (pending.track)
		}
		n := int64(len(r.Raw))
		g.led.AppendResponse(g.partition(coarse), ledger.Record{
			TS:       time.Now().UTC().Format(time.RFC3339Nano),
			CallID:   callID,
			RespHash: fmt.Sprintf("%x", sha256.Sum256(r.Raw)),
			Bytes:    &n,
		})
	}
}
