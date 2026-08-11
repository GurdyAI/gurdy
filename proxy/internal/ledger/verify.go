package ledger

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// VerifyResult summarizes one partition export. LastSeq and HeadHash are the
// chain-head checkpoint: published/recorded out-of-band, they defeat
// truncation-to-a-batch-boundary, which chain+signature alone cannot (§5.5).
type VerifyResult struct {
	Records   int `json:"records"`
	Decisions int `json:"decisions"`
	// Answered/Unmatched are the call_id join (§5.5), not a row count: a
	// response whose decision was dropped, or a second response for one call,
	// would otherwise inflate "answered" and hide the coverage gap it is there
	// to expose. Unanswered decisions are normal (in-flight, stream, crash) —
	// reported, never an error.
	Answered  int `json:"answered"`
	Unmatched int `json:"unmatched"`
	Batches   int `json:"batches"`
	// Coverage findings the chain admits to (§5.5 v0.8.3). These are what the
	// writer knew it lost; traffic that never reached the proxy is outside all
	// of it by construction.
	Dropped      uint64 `json:"dropped"`
	WriteErrors  uint64 `json:"write_errors"`
	IdentityFail uint64 `json:"identity_failed"`
	// CleanEnd is false when a lifecycle chain has no shutdown record — the
	// proxy stopped without saying so. Nil for a workload chain, which carries
	// no lifecycle records and must not be read as having ended badly.
	CleanEnd *bool `json:"clean_end"`
	// LivenessGaps counts intervals between consecutive lifecycle windows
	// longer than the header's declared heartbeat_s: time in which the writer
	// produced no evidence and no explanation.
	LivenessGaps int `json:"liveness_gaps"`
	// UncleanRestarts counts start records that follow anything but a
	// shutdown. CleanEnd only speaks for the tail, so without this a crash
	// stops being reported the moment the proxy is restarted — the evidence
	// would decay exactly as the operator recovers.
	UncleanRestarts int `json:"unclean_restarts"`
	// Identity is what the header says this chain is evidence of (§5.5
	// v0.8.5) — read from inside the signature, never from the filename.
	SchemaVersion int `json:"schema_version"`
	// Producer is the build that wrote the chain, per the header. Empty for an
	// export written before this field existed, which is a fact worth showing
	// rather than papering over with a guess.
	Producer   string `json:"producer"`
	Tenant     string `json:"tenant"`
	Workload   string `json:"workload"`
	InstanceID string `json:"instance_id"`
	Kid        string `json:"kid"`
	// UnknownKinds counts records this verifier does not understand. Counted,
	// never fatal: the chain and signature still cover them, so an export from
	// a newer proxy stays verifiable by an older verifier instead of being
	// rejected wholesale — and it is reported, so nobody reads "I could not
	// parse these" as "these do not exist".
	UnknownKinds int    `json:"unknown_kinds"`
	Uncovered    int    `json:"uncovered"` // decisions after the last valid batchsig
	KeySource    string `json:"key_source"`
	LastSeq      uint64 `json:"last_seq"`
	HeadHash     string `json:"head_hash"`

	// Segment is this file's position in its chain (D14); 1, or a chain
	// written before segments existed. FirstSeq is where this file picks up.
	Segment  int    `json:"segment"`
	FirstSeq uint64 `json:"first_seq"`
	// ContinuesFrom is the hash a continuation segment claims to follow. It is
	// non-empty exactly when this file is *not* the start of its chain, and
	// that is a statement a caller must act on rather than a detail: a segment
	// verifies perfectly on its own while everything before it is missing.
	// Whoever holds the export has to supply the predecessor and check that
	// its HeadHash matches this — VerifyFile cannot, it was handed one file.
	ContinuesFrom string `json:"continues_from,omitempty"`
	// Pruned counts retention records: evidence the chain says was removed on
	// purpose. Reported separately from Dropped because they are opposite
	// claims — one is loss the writer regrets, the other is deletion someone
	// authorised — and a reader who conflates them learns nothing from either.
	Pruned           int    `json:"pruned"`
	PrunedThroughSeq uint64 `json:"pruned_through_seq,omitempty"`
}

// VerifyFile re-walks one partition export: hash chain, sequence continuity,
// batch signatures, and coverage. pinned, when non-nil, overrides the pubkey
// embedded in the header — third-party verification should always pin
// (an attacker who rewrites the file can embed their own key).
func VerifyFile(path string, pinned *ecdsa.PublicKey) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := &VerifyResult{KeySource: "pinned"}
	var (
		pub       = pinned
		prevHash  string
		prevSeq   uint64
		lastSigAt uint64
		awaiting  = map[string]struct{}{} // decision call_ids not yet answered

		heartbeatS   int    // declared by the header; 0 = chain predates heartbeats
		lastWindowTo string // end of the previous lifecycle window
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		res.Records++
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return res, fmt.Errorf("record %d: not valid JSON: %w", res.Records, err)
		}
		// A continuation segment picks up where the previous file stopped, so
		// its first record is legitimately not seq 1 and legitimately links to
		// a line this file does not contain (D14). Seeding from the header's
		// own declaration is safe because the file's batch signatures cover
		// that header: a forger without the key cannot claim an arbitrary
		// starting point and still produce a chain that verifies. What they
		// *can* do is hand over segment 5 alone and stay silent about 1–4 —
		// which is why ContinuesFrom is reported rather than resolved here.
		if res.Records == 1 && rec.Kind == KindHeader && rec.Segment > 1 {
			if rec.PrevHash == "" {
				return res, fmt.Errorf("header: segment %d declares no predecessor — a continuation that links to nothing", rec.Segment)
			}
			prevHash, prevSeq = rec.PrevHash, rec.Seq-1
			res.ContinuesFrom = rec.PrevHash
		}
		if rec.Seq != prevSeq+1 {
			return res, fmt.Errorf("record %d: seq %d after %d (gap or splice)", res.Records, rec.Seq, prevSeq)
		}
		if rec.PrevHash != prevHash {
			return res, fmt.Errorf("record %d (seq %d): prev_hash mismatch — chain broken", res.Records, rec.Seq)
		}
		switch rec.Kind {
		case KindHeader:
			if res.Records != 1 {
				return res, fmt.Errorf("record %d: header not first", res.Records)
			}
			heartbeatS = rec.HeartbeatS
			// Absent means 1: chains written before segmenting existed are the
			// first and only segment by construction, and reporting 0 would
			// invite a reader to wonder what came before.
			res.Segment = rec.Segment
			if res.Segment == 0 {
				res.Segment = 1
			}
			res.FirstSeq = rec.Seq
			res.SchemaVersion, res.Tenant = rec.SchemaVersion, rec.Tenant
			res.Producer = rec.Producer
			res.Workload, res.InstanceID, res.Kid = rec.Workload, rec.InstanceID, rec.Kid
			if pub == nil {
				pub, err = parsePubKey(rec.PubKey)
				if err != nil {
					return res, fmt.Errorf("header: %w", err)
				}
				res.KeySource = "embedded (unpinned — pin the key for third-party verification)"
			}
		case KindDecision:
			res.Decisions++
			if rec.CallID != "" {
				awaiting[rec.CallID] = struct{}{}
			}
		case KindResponse:
			// ponytail: one map entry per unanswered call, dropped on match, so
			// this is bounded by concurrency in a healthy export and by the
			// decision count in a pathological one. Stream it out-of-core if
			// exports ever outgrow that.
			if _, ok := awaiting[rec.CallID]; ok {
				delete(awaiting, rec.CallID)
				res.Answered++
			} else {
				res.Unmatched++
			}
		case KindCoverage:
			res.Dropped += rec.Dropped
			res.WriteErrors += rec.WriteErrors
			res.IdentityFail += rec.IdentityFail
			// A liveness gap is dead time *between* windows, so it needs the
			// previous window's end — and only a lifecycle chain has the
			// regular cadence that makes the comparison meaningful.
			if rec.Reason == ReasonStart || rec.Reason == ReasonHeartbeat || rec.Reason == ReasonShutdown {
				// A start following a clean shutdown is a restart, not a gap:
				// the proxy was not running, and it said so. Comparing across
				// that boundary would report every planned downtime as missing
				// evidence, which trains a reader to ignore the finding.
				if rec.Reason == ReasonStart && res.CleanEnd != nil && !*res.CleanEnd {
					res.UncleanRestarts++
				}
				if !(rec.Reason == ReasonStart && res.CleanEnd != nil && *res.CleanEnd) {
					if gapBetween(lastWindowTo, rec.WindowFrom, heartbeatS) {
						res.LivenessGaps++
					}
					// An overlong window hides the same dead time *inside* a
					// record instead of between two: a heartbeat claiming to
					// cover half an hour has not been heartbeating.
					if gapBetween(rec.WindowFrom, rec.WindowTo, heartbeatS) {
						res.LivenessGaps++
					}
				}
				lastWindowTo = rec.WindowTo
				clean := rec.Reason == ReasonShutdown
				res.CleanEnd = &clean // the last lifecycle record wins
			}
		case KindRetention:
			// Counted and surfaced, never fatal. The record is a *claim* that
			// evidence was removed deliberately; this verifier can confirm it
			// is chained and signed, which is all that makes it a claim rather
			// than a rumour. Whether the deletion was authorised is a question
			// about a policy, not about a file.
			res.Pruned++
			if rec.PrunedThroughSeq > res.PrunedThroughSeq {
				res.PrunedThroughSeq = rec.PrunedThroughSeq
			}
		case KindBatchSig:
			if pub == nil {
				return res, fmt.Errorf("record %d: batchsig before any key", res.Records)
			}
			if res.Kid != "" && rec.Kid != "" && rec.Kid != res.Kid {
				// One header names one key for the whole file. A batch signed
				// by another is exactly what rotation has to handle explicitly
				// (NFR-5), not something to wave through.
				return res, fmt.Errorf("record %d (seq %d): signed by key %q, header declares %q",
					res.Records, rec.Seq, rec.Kid, res.Kid)
			}
			if err := verifyBatchSig(rec, pub); err != nil {
				return res, fmt.Errorf("record %d (seq %d): %w", res.Records, rec.Seq, err)
			}
			res.Batches++
			lastSigAt = rec.Seq
		default:
			// Counted, not fatal. Rejecting unknown kinds would mean the first
			// record type a future proxy adds strands every deployed verifier,
			// and the integrity claim never depended on understanding a
			// record — only on it being chained and signed.
			res.UnknownKinds++
		}
		h := sha256.Sum256(line)
		prevHash = fmt.Sprintf("%x", h)
		prevSeq = rec.Seq
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	if res.Records == 0 {
		return res, fmt.Errorf("empty export")
	}
	// Decisions after the last batchsig are chain-linked but not yet signed
	// (open signature window) — reported, not failed.
	res.Uncovered = int(prevSeq - lastSigAt)
	res.LastSeq, res.HeadHash = prevSeq, prevHash
	if lastSigAt == 0 && res.Decisions > 0 {
		return res, fmt.Errorf("no batch signature covers any of %d decisions", res.Decisions)
	}
	return res, nil
}

// gapBetween reports whether two lifecycle windows sit further apart than the
// declared heartbeat interval. Unparseable or undeclared timestamps report no
// gap: this is a claim about the proxy, and a claim the file cannot
// substantiate should not be made from it.
func gapBetween(prevTo, nextFrom string, heartbeatS int) bool {
	if prevTo == "" || heartbeatS == 0 {
		return false
	}
	a, err1 := time.Parse(time.RFC3339Nano, prevTo)
	b, err2 := time.Parse(time.RFC3339Nano, nextFrom)
	if err1 != nil || err2 != nil {
		return false
	}
	// One interval of slack: a window closes on a tick and the next opens a
	// tick later by construction, which is not a gap.
	return b.Sub(a) > 2*time.Duration(heartbeatS)*time.Second
}

// verifyBatchSig checks the ES256 signature over the record's canonical
// unsigned form. Because prev_hash is the chain head at signing time, a valid
// signature transitively covers every prior record.
func verifyBatchSig(rec Record, pub *ecdsa.PublicKey) error {
	// Strict(): reject non-canonical base64. Without it the unused trailing
	// bits of a padded encoding are ignored, so several distinct sig strings
	// decode to one signature — a mutated byte in the final batchsig line has
	// no later record's prev_hash committing to it, leaving the signature as
	// the only check, and a lenient decoder waves it through.
	sig, err := base64.StdEncoding.Strict().DecodeString(rec.Sig)
	if err != nil {
		return fmt.Errorf("batchsig sig not base64: %w", err)
	}
	rec.Sig = ""
	unsigned, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(unsigned)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("batch signature invalid")
	}
	return nil
}

func parsePubKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("pubkey not base64: %w", err)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("pubkey not PKIX: %w", err)
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pubkey not ECDSA")
	}
	return ec, nil
}
