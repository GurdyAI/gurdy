// Package ledger is the tamper-evident decision ledger (§5.5): per-partition
// hash-chained JSONL with ES256 batch signatures, offline-verifiable from the
// export alone (NFR-4, BR-5).
//
// Stream layout per partition file: one header record, then decision,
// response and coverage records (a call's response is a separate line joined
// by call_id, and a coverage record is the writer's own statement of what it
// lost — §5.5), with a batchsig record after every batch (N records, T
// seconds, or Close).
// Every record's prev_hash = SHA-256 of the previous line, so a batchsig's
// signature over its own record (whose prev_hash is the chain head) covers
// every prior record — the per-record "sig" of §5.5 is this batch reference,
// realized structurally rather than as a copied field.
//
// ponytail: storage is append-only JSONL, not SQLite-per-partition — the
// export format IS the store; add SQLite when the dashboard needs queries.
package ledger

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GurdyAI/gurdy/proxy/internal/keyfile"
)

const (
	KindHeader   = "header"
	KindDecision = "decision"
	KindResponse = "response"
	KindCoverage = "coverage"
	// KindFinding is an async, advisory classification attached to a call by
	// call_id (§5.5 v0.8.4). No emitter yet: the fields land before evidence
	// exists, because adding one afterwards is a migration, and because the
	// verifier must already know the kind or the first classifier record would
	// make every deployed verifier reject a whole export.
	KindFinding  = "finding"
	KindBatchSig = "batchsig"
	// KindRetention declares that earlier evidence was deliberately removed
	// (D14, §5.5). No emitter yet, and the same reasoning as KindFinding: the
	// fields land before evidence exists because adding them afterwards is a
	// migration.
	//
	// It exists because the two ways a chain can begin mid-stream must be
	// distinguishable by someone holding only the export. Deleting segments
	// *without* this record leaves a chain whose head links to a line nobody
	// has — which fails verification, and should. Deleting them *with* it
	// leaves a signed statement of what went and how far, which a reader can
	// weigh. Silent loss and declared retention look identical on disk
	// otherwise, and only one of them is operations.
	KindRetention = "retention"

	// Coverage reasons (§5.5, v0.8.3). A coverage record is the writer's own
	// statement about its completeness over a window.
	ReasonGap       = "gap"       // records the proxy observed and then lost
	ReasonStart     = "start"     // this writer opened the export
	ReasonResumed   = "resumed"   // it inherited an unsigned tail from a previous run
	ReasonHeartbeat = "heartbeat" // it was alive and writing, and lost nothing
	ReasonShutdown  = "shutdown"  // clean exit; its absence means the opposite

	// ProxyPartition carries proxy-lifecycle records. Workload partitions come
	// from the gateway as "tenant/workload", so a name with no slash cannot
	// collide with one. Heartbeats live here rather than per-partition because
	// liveness is a property of the process, not of one chain — and a shutdown
	// marker written per-partition would brand every evicted-but-healthy
	// partition as an abnormal end.
	ProxyPartition = "_proxy"

	// SchemaVersion is stamped in every chain header. A reader that meets a
	// version it does not know can say so rather than guess, which is the
	// difference between "this export is newer than me" and a false verdict.
	SchemaVersion = 1

	batchMaxRecords = 64
	batchMaxWait    = 2 * time.Second
	// heartbeatMax bounds how long an idle proxy can go without saying so.
	// Coalescing a window into one record is the only compaction available: an
	// append-only hash chain cannot be rewritten afterwards, so the saving has
	// to happen before the append rather than by pruning later.
	heartbeatMax = 5 * time.Minute
	queueCap     = 1024
	// maxSegmentBytes rolls a partition into a new file (D14, §5.5 v0.8.7).
	// The soak measured ~65 MB/min per partition at NFR-2's rated 1,000 req/s,
	// so an unrolled chain is ~92 GB/day in one file. 256 MiB is roughly four
	// minutes at that rate and a size a reader can still open, verify and move.
	//
	// It bounds the *file*, never the evidence: rolling is the alternative to
	// dropping, and nothing here deletes anything. Pruning is a separate,
	// declared act (KindRetention).
	maxSegmentBytes = 256 << 20
	// maxOpenParts bounds file descriptors against workload churn. Partition
	// count is driven by distinct (tenant, workload) keys — a client address
	// on the HTTP path — so it is not proxy-controlled. A monitor-mode proxy
	// that runs out of fds stops governing traffic altogether (NFR-3), which
	// is strictly worse than a re-open syscall on a cold partition.
	maxOpenParts = 64
)

// Assertion status: whether an SDK transaction assertion accompanied the call
// (§5.5). Distinct from PrincipalTier, which rates the proxy's own observation
// — the two answer different questions and a single field cannot carry both.
const (
	AssertionAbsent  = "absent"
	AssertionValid   = "valid"
	AssertionInvalid = "invalid"
)

// Policy rollout state, and what the actuator actually did (§4.2, §5.5). Kept
// distinct from Decision on purpose: decision=block + policy_mode=monitor +
// action_applied=forwarded is a shadow observation, and the same decision with
// action_applied=blocked is an enforcement claim. A record that cannot tell
// those apart is ambiguous exactly where it matters.
//
// Only the monitor-mode half exists here — ModeWarn/ModeEnforce and
// ActionBlocked/ActionFailedClosed land with the Phase 2 actuator (ADR-14),
// which is the first thing able to produce them. The *fields* land now: adding
// one after evidence exists is a migration, not an edit.
const (
	ModeMonitor = "monitor"

	ActionForwarded  = "forwarded"
	ActionFailedOpen = "failed-open"

	FailOpen = "open"
)

// Principal tiers: confidence in the *observed* principal (§5.2).
// TierAttested awaits real workload identity (K8s SA / SPIFFE); TierOrphan is
// currently unreachable on both transports, which always derive a coarse
// principal — it stays in the schema because §5.2 defines it.
const (
	TierAttested = "attested"
	TierCoarse   = "attested-coarse"
	TierOrphan   = "orphan"
)

// Record is one ledger line, of kind header, decision, response, or batchsig.
// Field order is the canonical form (§5.5 schema; classification lands with
// the packs). One struct covers every kind because the export is one JSONL
// stream and omitempty keeps each line to its own fields.
//
// Observed and asserted identity are separate fields and the observed one
// never degrades (§5.2): Principal is what the proxy saw and is the identity
// policy evaluates on, so an agent cannot choose what it is authorized as.
// The Asserted* fields and Lineage are agent-side claims, written only when
// AssertionStatus is valid — recording an auto-minted lineage as though an SDK
// supplied it would launder the proxy's own inference into an assertion.
type Record struct {
	Kind string `json:"kind"`
	Seq  uint64 `json:"seq"`
	TS   string `json:"ts,omitempty"`
	// CallID joins a decision to its response record (§5.5). Deliberately not
	// the decision's Seq: Seq is assigned by the writer goroutine after the
	// caller has moved on, and the queue drops on overflow, so a seq guessed at
	// decide time could name someone else's record.
	CallID             string   `json:"call_id,omitempty"`
	TxnID              string   `json:"txn_id,omitempty"`
	AssertionJTI       string   `json:"assertion_jti,omitempty"`
	AssertionStatus    string   `json:"assertion_status,omitempty"`
	Principal          string   `json:"principal,omitempty"`
	PrincipalTier      string   `json:"principal_tier,omitempty"`
	AssertedPrincipal  string   `json:"asserted_principal,omitempty"`
	Lineage            []string `json:"lineage,omitempty"`
	AssertedHumanActor string   `json:"asserted_human_actor,omitempty"`
	// AssertedScope is the claimed scope descriptor, carried opaquely so the
	// ledger does not depend on the identity package for a field it only
	// records. Verification hashes raw lines, so round-trip typing is moot.
	AssertedScope any               `json:"asserted_scope,omitempty"`
	Tool          string            `json:"tool,omitempty"`
	Action        string            `json:"action,omitempty"`
	ResourceAttrs map[string]string `json:"resource_attrs,omitempty"`
	Decision      string            `json:"decision,omitempty"`
	PolicyMode    string            `json:"policy_mode,omitempty"`
	ActionApplied string            `json:"action_applied,omitempty"`
	// PolicyEffects carries what *each* determining policy concluded. Staged
	// graduation means policies with different rollout states fire on one
	// call, and a single record-level policy_mode cannot say which of them was
	// enforcing and which was still shadowing — unreconstructable once the
	// evidence is written (§5.5 v0.8.5, FR-7).
	PolicyEffects []PolicyEffect `json:"policy_effects,omitempty"`
	BundleVer     string         `json:"bundle_ver,omitempty"`
	// FailModeApplied is which way an undecidable call went, not which way the
	// policy asked to go (FR-11) — in a monitor build those differ whenever a
	// policy declares on_error=closed, and the record states what happened.
	FailModeApplied string `json:"fail_mode_applied,omitempty"`
	ReqHash         string `json:"req_hash,omitempty"`
	// Response records only. No body ever, and no content classification —
	// Bytes is here because response *size* is the exfiltration signal a hash
	// cannot reconstruct (NFR-7, §4.2 non-goals).
	RespHash string `json:"resp_hash,omitempty"`
	Status   int    `json:"status,omitempty"`
	Bytes    *int64 `json:"bytes,omitempty"` // pointer: absent = not captured, 0 = empty body
	// Finding records only (§5.5): an async classifier's opinion about a call,
	// joined by CallID. Advisory, never a decision input (ADR-7, permanent).
	Source        string   `json:"source,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	Confidence    float64  `json:"confidence,omitempty"`
	ClassifierVer string   `json:"classifier_ver,omitempty"`
	// DeclaredClassification is the *deterministic* pack lookup (a data
	// classification map resolving a resource to a label) and may drive a
	// decision. An inferred label never appears here — it arrives as a finding
	// (§5.5 v0.8.5).
	DeclaredClassification string `json:"declared_classification,omitempty"`
	// Coverage records only (§5.5): what the writer knows it lost, or that it
	// was alive and lost nothing, over [WindowFrom, WindowTo].
	Reason       string `json:"reason,omitempty"`
	WindowFrom   string `json:"window_from,omitempty"`
	WindowTo     string `json:"window_to,omitempty"`
	Dropped      uint64 `json:"dropped,omitempty"`
	WriteErrors  uint64 `json:"write_errors,omitempty"`
	IdentityFail uint64 `json:"identity_failed,omitempty"`
	// InheritedUnsigned is how many trailing lines this process found covered
	// by no signature when it resumed the chain — the same count the verifier
	// reports as Uncovered, so the header line counts too. Its own signatures
	// will cover them from here, so the count is the only remaining marker of
	// which records it did not write (reason=resumed). Deliberately not folded
	// into Dropped: nothing was lost, and inflating the drop total would make
	// a resumed chain look like a lossy one.
	InheritedUnsigned uint64 `json:"inherited_unsigned,omitempty"`
	// HeartbeatS declares the heartbeat window bound in the header, so a gap
	// between windows is judgeable from the export alone rather than against
	// the reader's clock or a constant compiled into their verifier.
	// Header only: what this chain is evidence *of*, and which key signs it.
	// These are in the signature; the filename is a convenience for humans and
	// carries no evidentiary weight (§5.5 v0.8.5).
	SchemaVersion int `json:"schema_version,omitempty"`
	// Producer is the build that wrote this chain. Header only, inside the
	// signature. See Identity.Producer for why it is evidence rather than
	// telemetry.
	Producer   string `json:"producer,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	Workload   string `json:"workload,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
	HeartbeatS int    `json:"heartbeat_s,omitempty"`
	PubKey     string `json:"pubkey,omitempty"` // base64 PKIX
	// Kid names the signing key on the header and on every batchsig, so a
	// rotation with a 2-key overlap (NFR-5) is a keyring change rather than a
	// schema migration.
	Kid string `json:"kid,omitempty"`
	// Segment numbers this file within its chain, header only and inside the
	// signature (D14). A chain too large for one file continues into the next,
	// and the seam is already expressible: a continuation header's PrevHash is
	// the hash of the previous segment's last line, exactly like any other
	// record's. No second "prev_segment_hash" field, because it would be the
	// same value under another name, and two fields that must agree are one
	// field plus a way to disagree.
	//
	// Absent means 1 — chains written before segmenting existed are segment 1
	// by construction, and a verifier must not treat their silence as unknown.
	Segment  int    `json:"segment,omitempty"`
	FirstSeq uint64 `json:"first_seq,omitempty"` // batchsig only
	// Retention records only (D14): what was removed, and how far. The hash is
	// what makes the claim checkable — a reader who *does* hold the pruned
	// segments can confirm this names their real terminal line rather than an
	// invented one.
	PrunedThroughSeq  uint64 `json:"pruned_through_seq,omitempty"`
	PrunedThroughHash string `json:"pruned_through_hash,omitempty"`
	RetentionPolicy   string `json:"retention_policy,omitempty"`
	PrevHash          string `json:"prev_hash"`
	Sig               string `json:"sig,omitempty"` // batchsig only: base64 ASN.1 ES256
}

// partition holds one chain's state. f/w are nil while the partition is
// evicted (fd released); the chain state around them survives eviction, so
// reopening continues the same chain rather than starting a new one.
type partition struct {
	f          *os.File
	w          *bufio.Writer
	seq        uint64
	headHash   string // hex SHA-256 of last written line
	unsigned   int    // decisions since last batchsig
	firstUnsig uint64 // seq of first unsigned decision
	used       uint64 // writer-goroutine clock at last use; LRU key
	segment    int    // this file's position in the chain (D14)
	bytes      int64  // bytes written to this segment, for the roll bound
}

// Ledger owns one writer goroutine; Append never blocks the caller (§5.1
// bounded queue: monitor mode drops-with-counter, never blocks traffic).
// Identity is what a chain is evidence *of* (§5.5 v0.8.5). It goes in the
// header, inside the signature: a partition identity that lives only in a
// filename is not evidence, because a filename is unsigned and renaming one
// silently re-attributes a whole chain to another tenant.
type Identity struct {
	Tenant   string
	Instance string
	// Producer names the build that wrote the chain (`gurdy/v1.2.3+abc123def`).
	// Passed in rather than read from a global so the ledger stays testable and
	// so nothing here depends on how a binary was stamped.
	//
	// It is here, in the signature, for the same reason tenant is: a reader
	// judging an export needs to know which code produced it. If a defect turns
	// up in a released build, every chain that build wrote is suspect, and
	// without this the reader cannot tell whether theirs is one of them. It is
	// also what makes NFR-9's reproducibility claim executable — "rebuild the
	// verifier that produced this verdict" needs the artifact to name a commit.
	Producer string
}

type Ledger struct {
	dir    string
	id     Identity
	kid    string
	key    *ecdsa.PrivateKey
	pubB64 string
	queue  chan queued
	done   chan struct{}
	// seeds carries pending segment continuations, keyed by partition name and
	// consumed when the next file for that partition is created (D14).
	seeds map[string]segmentSeed
	// maxSegment is the roll bound, a field rather than a package var so tests
	// can shrink it without a mutable global two parallel tests could race on.
	maxSegment int64
	// Monotonic run totals, for /health and the shutdown log (§7). The
	// per-window detail that reaches the export lives in gaps below.
	Dropped      atomic.Uint64
	WriteErrors  atomic.Uint64
	IdentityFail atomic.Uint64

	// closeMu guards the queue against a send racing its close. A request in
	// flight at shutdown still appends — http.Server.Close does not wait for
	// handlers, and never waits for hijacked connections — and "send on closed
	// channel" would panic the process whose job is to record what happened.
	// A record that arrives after Close is a counted drop, like any other.
	closeMu sync.RWMutex
	closed  bool

	// gapMu guards the pending gap counts. Contended only on paths that are
	// already failing — a full queue, a write error, a TIS derivation failure —
	// so the cost never lands on a healthy call, and each finding is attributed
	// to the partition that actually lost the evidence.
	gapMu sync.Mutex
	gaps  map[string]*gapCounts

	// parts is owned exclusively by the run() goroutine; Close touches it only
	// after run() has exited (<-done) — no lock needed. Same for clock/open
	// and the two window clocks.
	parts map[string]*partition
	clock uint64
	open  int
	// Deliberately independent: gap windows follow the findings, heartbeats
	// keep a fixed cadence in _proxy. Sharing one clock would let a busy but
	// degraded proxy suppress its own heartbeats, and a verifier reading
	// _proxy would then report a liveness gap that never happened.
	hbTS  time.Time
	gapTS time.Time
}

// PolicyEffect is one determining policy's contribution to a decision.
type PolicyEffect struct {
	PolicyID      string `json:"policy_id"`
	Decision      string `json:"decision"`
	Mode          string `json:"mode"`
	EnforceAction string `json:"enforce_action,omitempty"`
	OnError       string `json:"on_error,omitempty"`
}

type gapCounts struct{ dropped, writeErrors, identityFail uint64 }

type queued struct {
	part string
	rec  Record
	done chan error // non-nil for AppendSync: the caller is waiting on durability
	// ctl runs on the writer goroutine instead of appending rec. Pruning has
	// to be serialized against writes — it appends a record, signs it, and
	// unlinks files the writer may hold open — and the queue is already the
	// one place that serialization exists.
	ctl func() error
}

// Open creates/reopens a ledger directory. Existing partition files are
// resumed: chain continues from the last line. The signing key persists at
// keyPath so restarts keep one verifiable chain identity (NFR-5 KMS-wrapping
// and ≤24h rotation come with the team tier). keyPath must live OUTSIDE dir:
// the ledger directory *is* the export handed to a third-party verifier, so a
// private key stored in it would ship with the evidence and let the recipient
// forge the chain they were sent to check (§8.5).
func Open(dir, keyPath string, id Identity) (*Ledger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := keyOutsideExport(dir, keyPath); err != nil {
		return nil, err
	}
	key, err := keyfile.LoadOrCreate(keyPath)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	l := &Ledger{
		dir:    dir,
		id:     id,
		kid:    keyID(pub),
		key:    key,
		pubB64: base64.StdEncoding.EncodeToString(pub),
		queue:  make(chan queued, queueCap),

		maxSegment: maxSegmentBytes,
		done:       make(chan struct{}),
		parts:      map[string]*partition{},
		gaps:       map[string]*gapCounts{},
		hbTS:       time.Now().UTC(),
		gapTS:      time.Now().UTC(),
	}
	if err := l.checkChainKeys(); err != nil {
		return nil, err
	}
	// Open the lifecycle chain immediately, before the writer goroutine exists
	// — no concurrency yet, so this is the one safe direct write. A crash in
	// the first heartbeat window would otherwise leave no _proxy chain at all,
	// and "no lifecycle chain" reads identically to "no proxy ever ran": the
	// absence of a shutdown record only means something if a start record
	// promised one (§5.5 v0.8.3).
	l.write(ProxyPartition, Record{
		Kind: KindCoverage, Reason: ReasonStart,
		TS:         l.hbTS.Format(time.RFC3339Nano),
		WindowFrom: l.hbTS.Format(time.RFC3339Nano),
		WindowTo:   l.hbTS.Format(time.RFC3339Nano),
	})
	// Sign and flush it now rather than at the first tick: a kill in the next
	// two seconds would otherwise leave the record in a buffer, and the whole
	// point of writing it at startup is to survive exactly that.
	if p, ok := l.parts[ProxyPartition]; ok && p.unsigned > 0 {
		if err := l.signBatch(p); err != nil {
			return nil, fmt.Errorf("ledger: cannot record process start: %w", err)
		}
	}
	go l.run()
	return l, nil
}

// checkChainKeys refuses to resume an export signed by a different key.
// A partition writes its pubkey once, in the header (§5.5), and the verifier
// checks every batch signature in the file against that one key — so appending
// under a new key does not produce a rejected record, it produces a chain that
// silently stops verifying from that point on. Losing or repointing -state-dir
// is the ordinary way to hit this, and evidence that quietly became
// unverifiable is the one failure this ledger exists to make impossible.
//
// ponytail: this is also what a real key rotation looks like from here, so
// NFR-5's ≤24h rotation with 2-key overlap has to land as a keyring in the
// header plus a multi-key verifier — not as relaxing this check.
func (l *Ledger) checkChainKeys() error {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(l.dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f) // default 64KB dwarfs a header line
		var hdr Record
		if sc.Scan() {
			json.Unmarshal(sc.Bytes(), &hdr) // a corrupt header is verify's job to report
		}
		f.Close()
		if hdr.Kind == KindHeader && hdr.PubKey != "" && hdr.PubKey != l.pubB64 {
			return fmt.Errorf("ledger: %s was signed by a different key — appending under the "+
				"current key would make the chain unverifiable from here; point -state-dir at the "+
				"original key or start a new ledger directory", path)
		}
	}
	return nil
}

// Append enqueues a decision record. Non-blocking: on overflow the record is
// dropped and counted (monitor-mode semantics; enforce mode revisits this).
func (l *Ledger) Append(part string, rec Record) {
	rec.Kind = KindDecision
	l.enqueue(part, rec)
}

// AppendResponse enqueues the response half of a call, joined to its decision
// by CallID (§5.5). It is a separate record because the response is not known
// when the decision is made, and an append-only chain does not go back and
// amend a line. Same drop semantics: a response is an observation, and a lost
// one is a counted gap, not a reason to hold up traffic.
func (l *Ledger) AppendResponse(part string, rec Record) {
	rec.Kind = KindResponse
	l.enqueue(part, rec)
}

// AppendSync writes a record and waits for it to be durable, returning the
// error if it could not be. Nothing calls it in monitor mode, and that is the
// point: §5.5 requires an enforced call to be recorded *before* the actuator's
// effect is released, and an API that can only fire-and-forget cannot express
// that. The Phase 2 actuator depends on this signature existing before it does.
//
// ponytail: implemented by handing the writer goroutine a done channel rather
// than a second write path — one writer keeps the chain single-threaded, which
// is the property the whole file is built on.
func (l *Ledger) AppendSync(part string, rec Record) error {
	rec.Kind = KindDecision
	done := make(chan error, 1)
	l.closeMu.RLock()
	if l.closed {
		l.closeMu.RUnlock()
		return fmt.Errorf("ledger: closed")
	}
	select {
	case l.queue <- queued{part: part, rec: rec, done: done}:
	default:
		l.closeMu.RUnlock()
		l.countGap(part, &l.Dropped, func(g *gapCounts) { g.dropped++ })
		return fmt.Errorf("ledger: queue full")
	}
	l.closeMu.RUnlock()
	return <-done
}

func (l *Ledger) enqueue(part string, rec Record) {
	l.closeMu.RLock()
	defer l.closeMu.RUnlock()
	if l.closed {
		l.countGap(part, &l.Dropped, func(g *gapCounts) { g.dropped++ })
		return
	}
	select {
	case l.queue <- queued{part: part, rec: rec}:
	default:
		l.countGap(part, &l.Dropped, func(g *gapCounts) { g.dropped++ })
	}
}

// RecordIdentityGap notes a proxy-internal identity failure against a
// partition (§5.5 v0.8.3). The call still produced a decision record — with
// empty txn fields and nothing else to separate it from a call that simply
// carried no assertion. Counting it is what makes the difference visible, and
// it is deliberately not a fourth assertion_status: the claim was fine, the
// proxy's own derivation was not.
func (l *Ledger) RecordIdentityGap(part string) {
	l.countGap(part, &l.IdentityFail, func(g *gapCounts) { g.identityFail++ })
}

// countGap accumulates a pending finding against the partition that suffered
// it, and bumps the matching run total. The map is a *window* — the writer
// drains it into a record — while the totals are monotonic, because /health
// and the shutdown log report the run, not the last window.
func (l *Ledger) countGap(part string, total *atomic.Uint64, add func(*gapCounts)) {
	l.gapMu.Lock()
	g, ok := l.gaps[part]
	if !ok {
		g = &gapCounts{}
		l.gaps[part] = g
	}
	add(g)
	l.gapMu.Unlock()
	total.Add(1) // one call, one finding
}

// takeGaps drains the pending findings for the writer goroutine to record.
func (l *Ledger) takeGaps() map[string]gapCounts {
	l.gapMu.Lock()
	defer l.gapMu.Unlock()
	if len(l.gaps) == 0 {
		return nil
	}
	out := make(map[string]gapCounts, len(l.gaps))
	for part, g := range l.gaps {
		out[part] = *g
	}
	clear(l.gaps)
	return out
}

// Close drains the queue, signs all unsigned tails, and syncs files.
// Idempotent, and safe against concurrent appends (see closeMu).
func (l *Ledger) Close() error {
	l.closeMu.Lock()
	if l.closed {
		l.closeMu.Unlock()
		return nil
	}
	l.closed = true
	close(l.queue)
	l.closeMu.Unlock()
	<-l.done

	// Last findings, then the marker whose *absence* is the crash signal
	// (§5.5 v0.8.3). Both before the final batch signatures, so they are signed
	// like everything else — "this chain ended cleanly" is exactly the claim
	// worth forging, and an unsigned trailing record is forgeable by anyone.
	l.writeGaps()
	now := time.Now().UTC()
	l.write(ProxyPartition, Record{
		Kind: KindCoverage, Reason: ReasonShutdown,
		TS:         now.Format(time.RFC3339Nano),
		WindowFrom: l.hbTS.Format(time.RFC3339Nano),
		WindowTo:   now.Format(time.RFC3339Nano),
	})

	var firstErr error
	for _, p := range l.parts {
		if p.f == nil { // evicted: fully signed and already flushed
			continue
		}
		if p.unsigned > 0 {
			if err := l.signBatch(p); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := p.w.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := p.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (l *Ledger) run() {
	defer close(l.done)
	tick := time.NewTicker(batchMaxWait)
	defer tick.Stop()
	for {
		select {
		case q, ok := <-l.queue:
			if !ok {
				return
			}
			var err error
			if q.ctl != nil {
				err = q.ctl()
			} else {
				err = l.write(q.part, q.rec)
			}
			if q.done != nil {
				// Durable means on disk, not in a buffer: a caller about to
				// release an actuator's effect is asking whether the record
				// survives a crash one instruction later.
				if err == nil {
					if p, ok := l.parts[q.part]; ok && p.w != nil {
						err = p.w.Flush()
					}
				}
				q.done <- err
			}
		case <-tick.C:
			// Findings first, so a gap is signed by the same batch as the
			// records around it rather than trailing the window it describes.
			l.writeGaps()
			l.writeHeartbeat(time.Now().UTC(), heartbeatMax)
			for _, p := range l.parts {
				if p.f == nil { // evicted: fully signed and already flushed
					continue
				}
				if p.unsigned > 0 {
					l.signBatch(p)
				}
				p.w.Flush()
			}
		}
	}
}

// writeGaps turns pending findings into coverage records — on the writer
// goroutine, bypassing the queue. That is the whole point: the queue that
// dropped a record cannot also be the path that reports the drop (§5.5).
// Counts are a lower bound; a crash before the next tick loses the open
// window, which is what the heartbeat and shutdown records are for.
func (l *Ledger) writeGaps() {
	pending := l.takeGaps()
	if pending == nil {
		return
	}
	to := time.Now().UTC()
	for part, g := range pending {
		err := l.write(part, Record{
			Kind: KindCoverage, Reason: ReasonGap,
			TS:         to.Format(time.RFC3339Nano),
			WindowFrom: l.gapTS.Format(time.RFC3339Nano),
			WindowTo:   to.Format(time.RFC3339Nano),
			Dropped:    g.dropped, WriteErrors: g.writeErrors, IdentityFail: g.identityFail,
		})
		if err != nil {
			// The finding outlived its record. Put the counts back rather than
			// let a failed write erase the evidence of an earlier failure —
			// otherwise the only trace left is the write_errors that this very
			// failure just incremented, and the drops it was reporting vanish.
			l.gapMu.Lock()
			back, ok := l.gaps[part]
			if !ok {
				back = &gapCounts{}
				l.gaps[part] = back
			}
			back.dropped += g.dropped
			back.writeErrors += g.writeErrors
			back.identityFail += g.identityFail
			l.gapMu.Unlock()
		}
	}
	l.gapTS = to
}

// writeHeartbeat closes the current liveness window once it has run long
// enough, writing one record for the whole span. An idle proxy costs one line
// per window instead of one per tick, and the bound is declared in the header
// so a reader can judge a gap between windows without a clock of their own
// (§7: a heartbeat whose absence the reporter flags).
func (l *Ledger) writeHeartbeat(now time.Time, max time.Duration) {
	if now.Sub(l.hbTS) < max {
		return
	}
	l.write(ProxyPartition, Record{
		Kind: KindCoverage, Reason: ReasonHeartbeat,
		TS:         now.Format(time.RFC3339Nano),
		WindowFrom: l.hbTS.Format(time.RFC3339Nano),
		WindowTo:   now.Format(time.RFC3339Nano),
	})
	l.hbTS = now
}

func (l *Ledger) write(part string, rec Record) error {
	p, err := l.part(part)
	if err != nil {
		l.countGap(part, &l.WriteErrors, func(g *gapCounts) { g.writeErrors++ })
		return err
	}
	rec.Seq = p.seq + 1
	rec.PrevHash = p.headHash
	if err := l.appendLine(p, &rec); err != nil {
		l.countGap(part, &l.WriteErrors, func(g *gapCounts) { g.writeErrors++ })
		return err
	}
	if p.unsigned == 1 {
		p.firstUnsig = rec.Seq
	}
	if p.unsigned >= batchMaxRecords {
		l.signBatch(p)
	}
	if p.bytes >= l.maxSegment {
		if err := l.roll(part, p); err != nil {
			// A failed roll is a write error like any other: the record above
			// landed, so nothing is lost, and the partition keeps writing to
			// the segment it already has. An oversized file beats a silent
			// stop, because monitor mode may not drop traffic to protect its
			// own tidiness (NFR-3).
			l.countGap(part, &l.WriteErrors, func(g *gapCounts) { g.writeErrors++ })
		}
	}
	return nil
}

// roll seals this segment and continues the chain in the next file (D14).
//
// Sealing first is not tidiness. A segment closed with unsigned records at its
// tail is one nobody will ever sign: the next process to open this partition
// resumes the *latest* segment, so those lines would sit forever outside every
// signature — and anyone with file access could append to them. The resumed
// path exists for a crash, which is unavoidable; a roll is not, so it must not
// manufacture the same condition deliberately.
func (l *Ledger) roll(name string, p *partition) error {
	if p.unsigned > 0 {
		if err := l.signBatch(p); err != nil {
			return err
		}
	}
	if err := p.w.Flush(); err != nil {
		return err
	}
	if err := p.f.Sync(); err != nil {
		return err
	}
	if err := p.f.Close(); err != nil {
		return err
	}
	p.f, p.w = nil, nil
	l.open--

	// The seam: the new header's prev_hash is the sealed segment's last line,
	// exactly like any other record's, and its seq continues rather than
	// restarts. Both are carried in p, which is why the chain state survives
	// the file change.
	p.segment++
	p.bytes = 0
	if err := l.openFile(name, p); err != nil {
		return err
	}
	workload := ""
	if _, w, ok := strings.Cut(name, "/"); ok {
		workload = w
	}
	hdr := Record{Kind: KindHeader, TS: time.Now().UTC().Format(time.RFC3339Nano),
		Seq: p.seq + 1, SchemaVersion: SchemaVersion, Producer: l.id.Producer,
		Tenant: l.id.Tenant, Workload: workload,
		InstanceID: l.id.Instance, HeartbeatS: int(heartbeatMax / time.Second),
		Kid: l.kid, PubKey: l.pubB64, Segment: p.segment,
		PrevHash: p.headHash}
	return l.appendLine(p, &hdr)
}

// signBatch appends a batchsig covering [firstUnsig, seq]. Its prev_hash is
// the chain head, so the signature transitively covers every prior record.
func (l *Ledger) signBatch(p *partition) error {
	rec := Record{
		Kind:     KindBatchSig,
		TS:       time.Now().UTC().Format(time.RFC3339Nano),
		Kid:      l.kid, // which key signed this batch (NFR-5 rotation seam)
		FirstSeq: p.firstUnsig,
		Seq:      p.seq + 1,
		PrevHash: p.headHash,
	}
	unsigned, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(unsigned)
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		return err
	}
	rec.Sig = base64.StdEncoding.EncodeToString(sig)
	if err := l.appendLine(p, &rec); err != nil {
		return err
	}
	p.unsigned = 0
	return p.w.Flush()
}

func (l *Ledger) appendLine(p *partition, rec *Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	n, err := p.w.Write(append(line, '\n'))
	if err != nil {
		return err
	}
	p.bytes += int64(n)
	h := sha256.Sum256(line)
	p.headHash = fmt.Sprintf("%x", h)
	p.seq = rec.Seq
	// Header and batchsig excluded: the header is written before any batch is
	// open (counting it would leave firstUnsig pointing at it), and a batchsig
	// is the thing that closes a batch. Everything else is evidence and must
	// pull the signature window forward — a response record left outside every
	// batch would be the only unsigned line in the file. A coverage record
	// especially: "we lost N records" and "this chain ended cleanly" are the
	// claims most worth forging.
	if rec.Kind == KindDecision || rec.Kind == KindResponse || rec.Kind == KindCoverage {
		p.unsigned++
	}
	return nil
}

// segmentSeed is where a continuation segment picks up: the segment number it
// claims, and the seq/hash of the last line of the segment before it.
type segmentSeed struct {
	segment int
	seq     uint64
	head    string
}

// seedSegment prepares this partition's next file to continue an earlier
// segment rather than begin a chain (D14).
//
// Nothing in the proxy calls it yet — the roller that will is the other half
// of D14, and the reader had to ship first: a verifier that rejects segment 2
// as "gap or splice" strands every export the moment rotation lands. It is not
// a test hook. It is the writer-side seam, landed early and exercised by the
// tests that prove the verifier accepts a segment a *real* writer produced,
// signatures and all, rather than a fixture shaped to pass.
func (l *Ledger) seedSegment(name string, segment int, afterSeq uint64, afterHash string) {
	if l.seeds == nil {
		l.seeds = map[string]segmentSeed{}
	}
	l.seeds[name] = segmentSeed{segment: segment, seq: afterSeq, head: afterHash}
}

// part returns the open partition, creating, resuming, or re-opening its file.
func (l *Ledger) part(name string) (*partition, error) {
	l.clock++
	if p, ok := l.parts[name]; ok {
		if p.f == nil {
			if err := l.openFile(name, p); err != nil {
				return nil, err
			}
		}
		p.used = l.clock
		return p, nil
	}
	// Resume continues the *last* segment. Appending to segment 1 of a rolled
	// chain would fork it into two files both claiming the same successor, and
	// nothing downstream could say which was the real chain.
	latest := l.latestSegment(name)
	if latest == 0 {
		latest = 1
	}
	// ponytail: resume scans the whole segment to find the tail; index the head
	// out-of-band if segments ever get big enough to hurt startup. Bounded by
	// maxSegmentBytes now, which is the point of rolling.
	seq, head, count, inherited, err := scanTail(l.segPath(name, latest))
	if err != nil {
		return nil, err
	}
	// A seeded partition continues a previous segment: its first record is not
	// seq 1 and links to a line in another file. Only applied to a genuinely
	// empty file — seeding over an existing chain would rewrite its start.
	segment := latest
	if sd, ok := l.seeds[name]; ok && count == 0 {
		seq, head, segment = sd.seq, sd.head, sd.segment
		delete(l.seeds, name)
	}
	p := &partition{seq: seq, headHash: head, used: l.clock, segment: segment}
	if fi, err := os.Stat(l.segPath(name, segment)); err == nil {
		p.bytes = fi.Size() // a resumed segment rolls on its total size, not this run's
	}
	if err := l.openFile(name, p); err != nil {
		return nil, err
	}
	l.parts[name] = p
	if inherited > 0 {
		// Mark the boundary before writing anything else, so the record sits
		// between the inherited tail and everything this process signs.
		now := time.Now().UTC().Format(time.RFC3339Nano)
		rec := Record{Kind: KindCoverage, Reason: ReasonResumed,
			TS: now, WindowFrom: now, WindowTo: now,
			InheritedUnsigned: uint64(inherited),
		}
		rec.Seq = p.seq + 1
		rec.PrevHash = p.headHash
		l.appendLine(p, &rec)
	}
	if count == 0 {
		// heartbeat_s is declared per chain so a reader can judge a liveness
		// gap from the export alone, rather than against a constant compiled
		// into whichever verifier build they happen to run (§5.5 v0.8.3).
		// workload comes from the partition key the gateway chose
		// ("tenant/workload"); the lifecycle chain has no workload of its own.
		workload := ""
		if _, w, ok := strings.Cut(name, "/"); ok {
			workload = w
		}
		hdr := Record{Kind: KindHeader, TS: time.Now().UTC().Format(time.RFC3339Nano),
			Seq: p.seq + 1, SchemaVersion: SchemaVersion, Producer: l.id.Producer,
			Tenant: l.id.Tenant, Workload: workload,
			InstanceID: l.id.Instance, HeartbeatS: int(heartbeatMax / time.Second),
			Kid: l.kid, PubKey: l.pubB64,
			// Written explicitly rather than left to omitempty's default, so a
			// reader can tell "segment 1 of a segmenting writer" from "a chain
			// predating segments". Nothing rolls files yet (D14); this is the
			// reader arriving before the writer, deliberately.
			Segment: segment}
		hdr.PrevHash = p.headHash // "" for a first segment, the seam otherwise
		if err := l.appendLine(p, &hdr); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// openFile attaches a file handle to p, first releasing the least-recently-
// used one if the fd budget is full.
func (l *Ledger) openFile(name string, p *partition) error {
	if l.open >= maxOpenParts {
		l.evictLRU(name)
	}
	f, err := os.OpenFile(l.segPath(name, p.segment), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	p.f, p.w = f, bufio.NewWriter(f)
	l.open++
	return nil
}

// evictLRU releases the file handle of the least-recently-used partition,
// keeping its chain state so the next write continues the same chain.
//
// An open batch is signed before the fd goes, which both closes the evidence
// window on a partition about to go cold and leaves every other batchsig path
// (the tick, Close) able to skip evicted partitions on a simple nil check.
// Signing here needs no re-open: a partition with unsigned > 0 is by
// definition still holding its writer.
func (l *Ledger) evictLRU(except string) {
	var victim *partition
	var vname string
	for name, p := range l.parts {
		if name == except || p.f == nil {
			continue
		}
		if victim == nil || p.used < victim.used {
			victim, vname = p, name
		}
	}
	if victim == nil {
		return
	}
	var err error
	if victim.unsigned > 0 {
		err = l.signBatch(victim)
	}
	if ferr := victim.w.Flush(); err == nil {
		err = ferr
	}
	if cerr := victim.f.Close(); err == nil {
		err = cerr
	}
	victim.f, victim.w = nil, nil
	l.open--
	// A failed sign/flush/close leaves the in-memory chain head possibly ahead
	// of what is durable, and resuming from it would splice the chain. Forget
	// the partition instead of trusting it: the next write re-scans the file
	// and continues from the real on-disk head. The lost tail is counted, not
	// silently spliced (§7 — coverage gaps are surfaced, never invisible).
	if err != nil {
		l.countGap(vname, &l.WriteErrors, func(g *gapCounts) { g.writeErrors++ })
		delete(l.parts, vname)
	}
}

// path maps a partition name to its export file. The name is a (tenant,
// workload) key (ADR-6) and carries whatever the environment produced —
// "stdio:<bin>", IPv6 literals, "/" — so it needs a real filename encoding,
// not url.PathEscape: PathEscape leaves ":" (illegal on Windows) and
// preserves case, and on a case-insensitive filesystem two workloads
// differing only in case would then silently write to ONE chain. Merged
// chains misattribute evidence, which is the failure this ledger exists to
// prevent, so uniqueness rests on the hash of the original name; the
// lowercased readable prefix is only so humans can browse the directory.
func (l *Ledger) path(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	readable := b.String()
	if len(readable) > 64 { // every byte is ASCII by construction
		readable = readable[:64]
	}
	// 64 bits, not 32: partition names accumulate in a directory over the whole
	// life of a deployment (client addresses churn), and a birthday collision
	// merges two workloads' chains silently — the failure this encoding exists
	// to prevent. Names are environment-derived, so this is a birthday bound,
	// not a preimage one.
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(l.dir, fmt.Sprintf("%s-%x.jsonl", readable, sum[:8]))
}

// segPath is path() for segment n. Segment 1 keeps the original name, so an
// export written before rotation existed needs no migration and every existing
// reader still finds it.
//
// The suffix is a convenience for humans and for finding the tail on resume.
// It carries no evidentiary weight and no reader may order segments by it: a
// filename is unsigned, and `segment` inside the header is not (§5.5 v0.8.5).
func (l *Ledger) segPath(name string, n int) string {
	if n <= 1 {
		return l.path(name)
	}
	return strings.TrimSuffix(l.path(name), ".jsonl") + fmt.Sprintf(".s%04d.jsonl", n)
}

// latestSegment returns the highest segment number on disk for a partition,
// and 0 when the chain does not exist yet. Resume has to continue the *last*
// segment; appending to segment 1 of a rolled chain would fork it.
func (l *Ledger) latestSegment(name string) int {
	if _, err := os.Stat(l.path(name)); err != nil {
		return 0
	}
	n := 1
	for {
		if _, err := os.Stat(l.segPath(name, n+1)); err != nil {
			return n
		}
		n++
	}
}

// keyOutsideExport enforces what Open's doc comment promises. A comment is not
// a control: -state-dir and -ledger-dir are separate flags, so pointing them at
// one directory would quietly reinstate the leak of shipping the signing key
// with the evidence it signs.
func keyOutsideExport(dir, keyPath string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	absKey, err := filepath.Abs(keyPath)
	if err != nil {
		return err
	}
	if strings.HasPrefix(absKey, absDir+string(filepath.Separator)) {
		return fmt.Errorf("ledger: signing key %s is inside the export directory %s — "+
			"the export is handed to third-party verifiers, so it must carry no private key", keyPath, dir)
	}
	return nil
}

// scanTail finds the resume point, and how much of the tail no signature
// covers. unsigned matters for evidence, not for resuming: a crash leaves an
// unsigned tail legitimately, so this cannot refuse to continue — but anyone
// with file access can append to that tail, and the next batch this process
// signs would sign their records too. Recording the inherited count is what
// keeps that boundary visible (a forged "clean shutdown" appended after a
// crash sits inside it).
func scanTail(path string) (seq uint64, headHash string, count, unsigned int, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, "", 0, 0, nil
	}
	if err != nil {
		return 0, "", 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	var last []byte
	for sc.Scan() {
		last = append(last[:0], sc.Bytes()...)
		count++
		var rec Record
		if json.Unmarshal(last, &rec) == nil && rec.Kind == KindBatchSig {
			unsigned = 0
		} else {
			unsigned++
		}
	}
	if err := sc.Err(); err != nil {
		return 0, "", 0, 0, err
	}
	if count == 0 {
		return 0, "", 0, 0, nil
	}
	var rec Record
	if err := json.Unmarshal(last, &rec); err != nil {
		return 0, "", 0, 0, fmt.Errorf("ledger %s: corrupt tail: %w", path, err)
	}
	h := sha256.Sum256(last)
	return rec.Seq, fmt.Sprintf("%x", h), count, unsigned, nil
}

// keyID names a key in a way both sides can compute from the public half
// alone: the first 8 bytes of SHA-256 over the PKIX encoding. Rotation with a
// 2-key overlap (NFR-5) needs signatures to say which key made them, and a
// field added after evidence exists is a migration.
func keyID(pkix []byte) string {
	sum := sha256.Sum256(pkix)
	return fmt.Sprintf("%x", sum[:8])
}

// HashBody returns the req_hash for a request body (NFR-7: hashes, not payloads).
func HashBody(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h)
}

// PruneResult is what a prune actually did, per partition.
type PruneResult struct {
	Partition   string `json:"partition"`
	Removed     []int  `json:"removed_segments"`
	ThroughSeq  uint64 `json:"pruned_through_seq"`
	ThroughHash string `json:"pruned_through_hash"`
}

// Prune removes whole segments from every partition, keeping the most recent
// `keep` of each, and declares the removal in the chain first (D14, §5.5
// v0.8.7).
//
// **Operator-invoked only** (author decision 2026-08-10). Nothing calls this on
// a timer, and nothing should: an evidence product that quietly deletes its own
// records on a schedule is a different proposition from one an operator asks,
// and the retention record makes either auditable without making both wise.
//
// The ordering is the safety property, and it is the same one §5.5 requires of
// an enforced decision: **record before effect.** The declaration is appended,
// signed and synced *before* a single file is unlinked. Crash in between and
// the record over-claims — it names a prune that did not happen, the files are
// still there, and verification passes with a complete chain. Crash the other
// way round and the export has an undeclared hole, which fails verification and
// is indistinguishable from tampering. Only one of those asymmetries is
// survivable, so the code takes it deliberately.
//
// Whole segments only. Pruning *within* a segment would mean rewriting a hash
// chain around the hole, which is precisely the operation the chain exists to
// make impossible.
func (l *Ledger) Prune(keep int) ([]PruneResult, error) {
	if keep < 1 {
		// Keeping zero segments would delete the chain being written, including
		// the record declaring the deletion.
		return nil, fmt.Errorf("ledger: keep must be at least 1, got %d", keep)
	}
	var out []PruneResult
	done := make(chan error, 1)
	l.closeMu.RLock()
	if l.closed {
		l.closeMu.RUnlock()
		return nil, fmt.Errorf("ledger: closed")
	}
	l.queue <- queued{done: done, ctl: func() error {
		var err error
		out, err = l.pruneAll(keep)
		return err
	}}
	l.closeMu.RUnlock()
	return out, <-done
}

// pruneAll runs on the writer goroutine, where partition state is not shared.
func (l *Ledger) pruneAll(keep int) ([]PruneResult, error) {
	names := make([]string, 0, len(l.parts))
	for name := range l.parts {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic across runs; a prune that reorders its own report is hard to audit
	var out []PruneResult
	for _, name := range names {
		res, err := l.prunePartition(name, keep)
		if err != nil {
			return out, err
		}
		if len(res.Removed) > 0 {
			out = append(out, res)
		}
	}
	return out, nil
}

func (l *Ledger) prunePartition(name string, keep int) (PruneResult, error) {
	res := PruneResult{Partition: name}
	p, err := l.part(name)
	if err != nil {
		return res, err
	}
	last := p.segment - keep // remove segments 1..last
	if last < 1 {
		return res, nil
	}
	// The terminal line of the last segment being removed is what makes the
	// declaration checkable rather than merely stated: anyone who still holds
	// those segments — an archive, a replica — can confirm this names their
	// real last line instead of an invented one.
	seq, head, _, _, err := scanTail(l.segPath(name, last))
	if err != nil {
		return res, err
	}
	if head == "" {
		return res, fmt.Errorf("ledger: segment %d of %s is missing or empty; refusing to declare a prune it cannot describe", last, name)
	}

	rec := Record{Kind: KindRetention, TS: time.Now().UTC().Format(time.RFC3339Nano),
		PrunedThroughSeq: seq, PrunedThroughHash: head,
		RetentionPolicy: fmt.Sprintf("operator: keep %d segments", keep)}
	rec.Seq = p.seq + 1
	rec.PrevHash = p.headHash
	if err := l.appendLine(p, &rec); err != nil {
		return res, err
	}
	// Signed and on disk before anything is unlinked. An unsigned declaration
	// is forgeable by anyone with file access, and "these records were removed
	// on purpose" is among the most useful things to forge.
	if err := l.signBatch(p); err != nil {
		return res, err
	}
	if err := p.w.Flush(); err != nil {
		return res, err
	}
	if err := p.f.Sync(); err != nil {
		return res, err
	}

	for n := 1; n <= last; n++ {
		if err := os.Remove(l.segPath(name, n)); err != nil && !os.IsNotExist(err) {
			// Partial removal is safe in the direction it fails: the
			// declaration is already on disk, so what remains is a chain that
			// over-declares rather than one with an unexplained hole.
			return res, err
		}
		res.Removed = append(res.Removed, n)
	}
	res.ThroughSeq, res.ThroughHash = seq, head
	return res, nil
}
