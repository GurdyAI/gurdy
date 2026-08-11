// gurdy-verify: offline third-party verification of ledger exports (NFR-4,
// BR-5). Needs nothing but this binary and the export files — the Stage D
// independence test.
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GurdyAI/gurdy/proxy/internal/ledger"
	"github.com/GurdyAI/gurdy/proxy/internal/version"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is main's body, parameterized so the CLI contract can be tested. That
// contract is the whole product claim (NFR-4, BR-5): a third party runs this
// and believes the exit code. 0 = every export verified, 1 = at least one did
// not, 2 = the verifier could not run (bad usage or unreadable pinned key) —
// 2 must never be confused with 0, or a broken invocation reads as a pass.
func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("gurdy-verify", flag.ContinueOnError)
	fs.SetOutput(errOut)
	pubPath := fs.String("pubkey", "", "PEM public key to pin (recommended; otherwise the export's embedded key is trusted)")
	allowTail := fs.Bool("allow-unsigned-tail", false,
		"accept trailing records no batch signature covers (live ledger being inspected mid-window; NEVER for a delivered export)")
	asJSON := fs.Bool("json", false,
		"emit one JSON object per export instead of prose, for a reporter or GRC tooling to consume")
	// A verifier's own version is part of a verdict: an auditor repeating this
	// check months later needs to know which build reached it, and NFR-9's
	// reproducibility claim is only executable if the binary names its commit.
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(out, version.String("gurdy-verify"))
		return 0
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(errOut, "usage: gurdy-verify [-pubkey key.pem] <export.jsonl | ledger-dir> ...")
		return 2
	}

	var pinned *ecdsa.PublicKey
	if *pubPath != "" {
		var err error
		if pinned, err = readPubKey(*pubPath); err != nil {
			fmt.Fprintf(errOut, "gurdy-verify: %v\n", err)
			return 2
		}
	}

	// The reporter consumes this rather than reimplementing chain verification:
	// §3.3's single-implementation rule means the Go core is the only verifier,
	// and a Python copy of a signature check is a second security-critical
	// implementation that would drift from this one.
	type jsonResult struct {
		File string `json:"file"`
		OK   bool   `json:"ok"`
		// Error is the reason verification failed. Present *and* OK=false, so a
		// consumer cannot mistake a failure for a pass by reading only one field.
		Error string `json:"error,omitempty"`
		*ledger.VerifyResult
	}
	var results []jsonResult
	// Segments verified so far, for the cross-file seam check. Collected
	// unconditionally rather than through emit(), which only accumulates for
	// -json: the seam is a correctness check, not an output format.
	var verified []segRef
	var seamProbs []string
	emit := func(r jsonResult) {
		if *asJSON {
			results = append(results, r)
		}
	}
	defer func() {
		if !*asJSON {
			return
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{
			"tool":    "gurdy-verify",
			"pinned":  pinned != nil,
			"exports": results,
			"seams":   seamProbs,
		})
	}()

	failed := false
	for _, arg := range fs.Args() {
		files := expand(arg)
		if len(files) == 0 {
			failed = true
			emit(jsonResult{File: arg, Error: "no ledger files found"})
			if !*asJSON {
				fmt.Fprintf(out, "FAIL  %s: no ledger files found\n", arg)
			}
			continue
		}
		for _, path := range files {
			res, err := ledger.VerifyFile(path, pinned)
			if err != nil {
				failed = true
				emit(jsonResult{File: path, Error: err.Error()})
				if !*asJSON {
					fmt.Fprintf(out, "FAIL  %s: %v\n", path, err)
				}
				continue
			}
			// Records past the last batch signature are chain-linked but NOT
			// signed, and the chain link alone is recomputable by anyone: an
			// attacker can append fabricated decisions with a correct seq and
			// prev_hash and they verify. Unsigned means unverified, so this
			// fails by default — BR-5 is "every decision signed", and a
			// verifier that prints OK over forged records is worse than no
			// verifier. -allow-unsigned-tail exists for inspecting a *live*
			// ledger mid-signature-window, never for a delivered export.
			if res.Uncovered > 0 && !*allowTail {
				failed = true
				emit(jsonResult{File: path, VerifyResult: res, Error: fmt.Sprintf(
					"%d trailing records covered by no batch signature (forged tail, or a live ledger)", res.Uncovered)})
				if !*asJSON {
					fmt.Fprintf(out, "FAIL  %s: %d trailing records covered by no batch signature "+
						"(forged tail, or a live ledger — re-export after close, or pass -allow-unsigned-tail)\n",
						path, res.Uncovered)
				}
				continue
			}
			verified = append(verified, segRef{path, res})
			emit(jsonResult{File: path, OK: true, VerifyResult: res})
			if *asJSON {
				continue // prose below is for humans only
			}
			// "answered" is the call_id join, not a response-record count: a
			// decision with no response is unanswered evidence, and folding the
			// two counts together would hide how much of it there is.
			fmt.Fprintf(out, "OK    %s: %d records, %d decisions (%d answered), %d batch signatures, key: %s\n",
				path, res.Records, res.Decisions, res.Answered, res.Batches, res.KeySource)
			if res.Unmatched > 0 {
				fmt.Fprintf(out, "      note: %d response records match no decision in this partition "+
					"(dropped decision, or a chain that starts mid-call)\n", res.Unmatched)
			}
			// The chain's own admission of what it lost (§5.5) — a floor, not a
			// total: a crash takes the open window with it.
			if res.Dropped+res.WriteErrors+res.IdentityFail > 0 {
				fmt.Fprintf(out, "      coverage: %d records dropped, %d write errors, %d identity failures "+
					"— self-reported, so a lower bound\n", res.Dropped, res.WriteErrors, res.IdentityFail)
			}
			if res.LivenessGaps > 0 {
				fmt.Fprintf(out, "      coverage: %d intervals with no heartbeat — the proxy was not writing "+
					"evidence, and any traffic in them is unrecorded\n", res.LivenessGaps)
			}
			// Only a lifecycle chain carries this: a workload chain has no
			// shutdown record to miss, and reporting one would cry wolf.
			if res.UncleanRestarts > 0 {
				fmt.Fprintf(out, "      lifecycle: %d restart(s) with no preceding shutdown — the proxy died "+
					"and came back; traffic between those points is unrecorded\n", res.UncleanRestarts)
			}
			if res.CleanEnd != nil {
				if *res.CleanEnd {
					fmt.Fprintf(out, "      lifecycle: ended cleanly\n")
				} else {
					fmt.Fprintf(out, "      lifecycle: NO shutdown record — the proxy stopped without closing "+
						"this chain (crash, kill, or truncation); treat the tail as incomplete\n")
				}
			}
			// What this chain is evidence *of*, read from inside the signature.
			// Printing it is the point of putting it there: an auditor holding
			// two exports must be able to tell whose is whose without trusting
			// a filename anyone can change.
			fmt.Fprintf(out, "      chain: tenant=%s workload=%s instance=%s schema=v%d key=%s\n",
				orNone(res.Tenant), orNone(res.Workload), orNone(res.InstanceID), res.SchemaVersion, orNone(res.Kid))
			// Which build wrote it. "none" is the honest answer for an export
			// predating the field, and is not the same claim as "built by an
			// unknown binary" — so it is shown rather than defaulted.
			fmt.Fprintf(out, "      producer: %s\n", orNone(res.Producer))
			if res.UnknownKinds > 0 {
				fmt.Fprintf(out, "      note: %d records of a kind this verifier does not know — chained and "+
					"signed, but not interpreted; this export may come from a newer proxy\n", res.UnknownKinds)
			}
			// The chain head is the truncation defense: record it out-of-band
			// and compare on the next verify (§5.5 checkpoint anchoring).
			fmt.Fprintf(out, "      head: seq %d hash %s\n", res.LastSeq, res.HeadHash)
			if res.Uncovered > 0 {
				fmt.Fprintf(out, "      note: %d trailing records accepted unsigned (-allow-unsigned-tail)\n", res.Uncovered)
			}
		}
	}
	// The seam check, which no single-file verify can do: a segment verifies
	// perfectly while everything before it is missing, so the only place the
	// chain-across-files claim can be tested is here, by whoever holds them
	// all (§5.5 v0.8.7).
	seamProbs = seamProblems(verified)
	for _, p := range seamProbs {
		failed = true
		if !*asJSON {
			fmt.Fprintf(out, "FAIL  %s\n", p)
		}
	}
	if failed {
		return 1
	}
	return 0
}

// seamProblems groups verified segments into chains and checks that each one
// continues the last.
//
// Chains are grouped by what the *headers* say — tenant, workload, instance —
// and ordered by the header's segment number, never by filename. A filename is
// unsigned and renameable; ordering evidence by one would let a rename
// reorder a chain (§5.5 v0.8.5).
type segRef struct {
	path string
	res  *ledger.VerifyResult
}

func seamProblems(segs []segRef) []string {
	chains := map[string][]segRef{}
	for _, s := range segs {
		k := s.res.Tenant + "\x00" + s.res.Workload + "\x00" + s.res.InstanceID
		chains[k] = append(chains[k], s)
	}
	keys := make([]string, 0, len(chains))
	for k := range chains {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic output; a verifier that reorders its own findings is hard to diff

	var probs []string
	for _, k := range keys {
		segs := chains[k]
		sort.Slice(segs, func(i, j int) bool { return segs[i].res.Segment < segs[j].res.Segment })

		// A chain that does not start at segment 1 is missing its beginning.
		// Reported as a failure unless the chain declares the removal — the
		// entire difference between authorised retention and someone handing
		// over only the part that suits them, and a difference a third party
		// must be able to see (§5.5 v0.8.7).
		//
		// Any segment may carry the declaration, not just the first surviving
		// one: the pruner appends it to the chain's *current* segment, because
		// that is the only file being written. And it has to actually cover
		// the hole — a record pruning through seq 40 does not excuse a chain
		// that starts at seq 900. An under-reaching declaration is how a
		// partial handover would otherwise dress itself up as retention.
		var prunedThrough uint64
		for _, s := range segs {
			if s.res.PrunedThroughSeq > prunedThrough {
				prunedThrough = s.res.PrunedThroughSeq
			}
		}
		if first := segs[0].res; first.Segment > 1 && prunedThrough < first.FirstSeq-1 {
			why := "nothing in this export says they were removed on purpose"
			if prunedThrough > 0 {
				why = fmt.Sprintf("the retention record only covers through seq %d, and this chain starts at seq %d",
					prunedThrough, first.FirstSeq)
			}
			probs = append(probs, fmt.Sprintf(
				"%s: chain begins at segment %d — segments 1-%d were not supplied, and %s",
				segs[0].path, first.Segment, first.Segment-1, why))
		}
		for i := 1; i < len(segs); i++ {
			prev, cur := segs[i-1].res, segs[i].res
			if cur.Segment == prev.Segment {
				probs = append(probs, fmt.Sprintf(
					"%s and %s both claim segment %d of the same chain — a fork, not a continuation",
					segs[i-1].path, segs[i].path, cur.Segment))
				continue
			}
			if cur.Segment != prev.Segment+1 {
				probs = append(probs, fmt.Sprintf(
					"%s: segment %d follows segment %d — %d segment(s) missing from this export",
					segs[i].path, cur.Segment, prev.Segment, cur.Segment-prev.Segment-1))
				continue
			}
			if cur.ContinuesFrom != prev.HeadHash {
				probs = append(probs, fmt.Sprintf(
					"%s: continues from %s, but %s ends at %s — these are not the same chain",
					segs[i].path, short(cur.ContinuesFrom), segs[i-1].path, short(prev.HeadHash)))
			}
			if cur.FirstSeq != prev.LastSeq+1 {
				probs = append(probs, fmt.Sprintf(
					"%s: starts at seq %d, but %s ends at seq %d",
					segs[i].path, cur.FirstSeq, segs[i-1].path, prev.LastSeq))
			}
		}
	}
	return probs
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func expand(arg string) []string {
	info, err := os.Stat(arg)
	if err != nil || !info.IsDir() {
		return []string{arg}
	}
	entries, err := os.ReadDir(arg)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			files = append(files, filepath.Join(arg, e.Name()))
		}
	}
	return files
}

func readPubKey(path string) (*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return ec, nil
}
