// gurdy-conform runs the shared SDK conformance suite (§5.9): the
// language-agnostic fixtures both SDKs must pass, so parity is a property of
// one corpus rather than of two test suites that drift apart.
//
// The contract it checks is deliberately the *evidence*, not the API. A case
// says what an SDK must cause to appear in the ledger — asserted identity,
// lineage, degrade behavior — and never how the SDK spells it. That is what
// lets one corpus judge Python, TypeScript and the raw wire protocol, and it
// is why the suite can exist before either SDK does: the reference driver
// below speaks the wire contract directly, which proves every expectation is
// satisfiable by something.
//
// A driver is any executable. It receives the case on stdin and the endpoints
// in the environment, performs the steps, and reports what failed on stdout;
// see conformance/README.md.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/GurdyAI/gurdy/proxy/internal/ledger"
)

// Case is one conformance scenario. Steps describe what the SDK must do;
// Expect describes what must then be true of the evidence.
type Case struct {
	Name string `json:"name"`
	Why  string `json:"why"` // the requirement this pins, in the author's words
	// Kind is who executes the case (§5.9 boundary):
	//
	//   "sdk"  (default) — the driver runs it through the SDK's public surface.
	//   "wire" — the *runner* runs it, always, whatever -driver says. These pin
	//            proxy behavior an SDK cannot produce: a forged credential
	//            needs a signing key, and §5.9 is explicit that the SDK never
	//            holds one.
	//
	// The split exists so an SDK cannot appear to pass a case it never ran.
	// Handing a wire case to a driver would have every driver execute the same
	// bypass code and report a pass that says nothing about the SDK.
	Kind string `json:"kind"`
	// Attack is the adversarial-corpus narrative (§8.2): what the attacker is
	// trying, in their terms. Separate from Why, which says what the trace pins.
	Attack string `json:"attack,omitempty"`
	// KnownGap marks a trace whose expectations describe what the pack does
	// *today* rather than what it should do — an attack that currently succeeds.
	//
	// The mechanism that stops this becoming a graveyard is in the runner: a
	// known gap that no longer reproduces is a FAILURE, not a quiet pass. If the
	// pack improves, the corpus must be told, because a trace still claiming a
	// weakness that has been fixed is the corpus lying about the product in the
	// other direction.
	KnownGap *KnownGap `json:"known_gap,omitempty"`
	Steps    []Step    `json:"steps"`
	Expect   Expect    `json:"expect"`
}

type KnownGap struct {
	Why        string `json:"why"`
	ClosesWith string `json:"closes_with"`
}

const (
	kindSDK  = "sdk"
	kindWire = "wire"
)

// execContexts are the legal CallStep.In values; "" is inline.
var execContexts = []string{"", "thread", "async", "process"}

func (c Case) kind() string {
	if c.Kind == "" {
		return kindSDK
	}
	return c.Kind
}

// validate refuses a corpus that cannot mean what it says. A forged credential
// in an SDK case is the specific mistake worth catching: it would silently
// become "every SDK driver hand-rolls a bypass", which tests nothing.
func (c Case) validate() error {
	if k := c.kind(); k != kindSDK && k != kindWire {
		return fmt.Errorf("unknown kind %q", k)
	}
	if g := c.KnownGap; g != nil && (g.Why == "" || g.ClosesWith == "") {
		return fmt.Errorf("known_gap must say why the attack succeeds and what closes it — " +
			"an unexplained gap is an excuse, not a finding")
	}
	for i, s := range c.Steps {
		// Checked for every kind: an unknown value would otherwise be silently
		// ignored by both drivers, and the case would pass while testing
		// nothing — the specific way a propagation case fails open.
		if s.Call != nil && !slices.Contains(execContexts, s.Call.In) {
			return fmt.Errorf("step %d: unknown execution context %q, want one of %v",
				i, s.Call.In, execContexts[1:])
		}
	}
	if c.kind() == kindWire {
		return nil
	}
	for i, s := range c.Steps {
		if s.Call != nil && s.Call.Txn == "forged" {
			return fmt.Errorf(`step %d uses txn "forged", which no SDK can produce (§5.9: the SDK `+
				`never holds signing keys) — mark the case "kind": "wire"`, i)
		}
	}
	return nil
}

type Step struct {
	Mint   *MintStep   `json:"mint,omitempty"`
	Derive *DeriveStep `json:"derive,omitempty"`
	Call   *CallStep   `json:"call,omitempty"`
}

type MintStep struct {
	As         string         `json:"as"` // name this token for later steps
	Agent      string         `json:"agent"`
	HumanActor string         `json:"human_actor"`
	Scope      map[string]any `json:"scope"`
}

type DeriveStep struct {
	From          string         `json:"from"`
	As            string         `json:"as"`
	Agent         string         `json:"agent"`
	Scope         map[string]any `json:"scope"`
	ExpectRefused bool           `json:"expect_refused"`
}

// CallStep issues one governed call. Txn names a token from an earlier step,
// or the two degrade cases the SDK must also get right: "none" (no SDK
// context at all) and "forged" (a credential that does not verify).
type CallStep struct {
	Txn  string         `json:"txn"`
	Tool string         `json:"tool"`
	Args map[string]any `json:"args"`
	Body string         `json:"body"` // raw body instead of an MCP tools/call
	Path string         `json:"path"`
	// In is the execution context the call must be made from: "" (inline),
	// "thread", "async", or "process". It exists because §5.9 requires
	// lineage to survive those boundaries and a language runtime is exactly
	// where it silently does not — a Python ContextVar does not cross into a
	// worker thread, and nothing at all crosses into a subprocess.
	//
	// The reference driver honours it by crossing a real goroutine boundary,
	// which proves the expectation is satisfiable from the wire contract and
	// nothing more: it holds tokens explicitly, so no execution context can
	// lose one. The claim only bites on an SDK driver, which is the point —
	// this is the class of bug that produces a record attributing a
	// sub-agent's action to nobody, or worse, to the wrong agent.
	In string `json:"in"`
}

// Expect matches the exported ledger. Record fields left empty are not
// asserted, so a case pins the property it is about and nothing else — a
// fixture that over-specifies fails on unrelated changes and gets deleted.
type Expect struct {
	Records                []RecordMatch `json:"records"`
	UpstreamNeverSawHeader []string      `json:"upstream_never_saw_header"`
	DriverErrorContains    []string      `json:"driver_error_contains"`
	// UpstreamCalls pins that the traffic actually reached the tool. Without
	// it a case like "a forged credential is recorded, not dropped" asserts
	// only the first half of its own name: a proxy that recorded the record
	// and swallowed the call would pass.
	UpstreamCalls *int `json:"upstream_calls"`
	// CleanExport requires the whole directory to verify as a closed export:
	// the lifecycle chain ended cleanly and no workload record is left outside
	// a signature. Defaults on; a case must opt out deliberately.
	AllowOpenExport bool `json:"allow_open_export"`
}

type RecordMatch struct {
	Action             string   `json:"action"`
	Tool               string   `json:"tool"`
	Decision           string   `json:"decision"`
	AssertionStatus    string   `json:"assertion_status"`
	AssertedPrincipal  string   `json:"asserted_principal"`
	AssertedHumanActor string   `json:"asserted_human_actor"`
	PrincipalTier      string   `json:"principal_tier"`
	ActionApplied      string   `json:"action_applied"`
	PolicyMode         string   `json:"policy_mode"`
	Lineage            []string `json:"lineage"`
	PrincipalPrefix    string   `json:"principal_prefix"`
	// Policy is the policy_id that must appear in policy_effects. A corpus trace
	// asserting only `decision` would pass when the *wrong* rule fired, which
	// for a pack that gates on named controls is a pass for the wrong reason.
	Policy           string `json:"policy"`
	NoAssertedFields bool   `json:"no_asserted_fields"`
	// SameTxnAs names an earlier record index that this one must share a
	// transaction with. "In the same chain" is a claim about a relationship,
	// so a per-record matcher cannot express it: an SDK that minted a second
	// transaction with the same agent name would satisfy every field above
	// while producing exactly the split provenance the case exists to forbid.
	SameTxnAs *int `json:"same_txn_as"`
	Answered  bool `json:"answered"` // a response record joins this call
}

func main() {
	cases := flag.String("cases", "../conformance/cases", "directory of case files")
	driver := flag.String("driver", "direct",
		`driver to exercise: "direct" (built-in wire-contract reference) or a path to an executable`)
	proxyBin := flag.String("proxy", "gurdy-proxy", "gurdy-proxy binary to run the cases against")
	flag.Parse()

	files, err := filepath.Glob(filepath.Join(*cases, "*.json"))
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no cases in %s\n", *cases)
		os.Exit(2)
	}
	sort.Strings(files)

	failed, wire, gaps := 0, 0, 0
	for _, f := range files {
		var c Case
		raw, err := os.ReadFile(f)
		if err == nil {
			err = json.Unmarshal(raw, &c)
		}
		if err == nil {
			err = c.validate()
		}
		if err != nil {
			fmt.Printf("FAIL  %s: %v\n", filepath.Base(f), err)
			failed++
			continue
		}
		// A wire case runs on the built-in driver whatever -driver says, and
		// the output labels it, so "7 passed" can never be read as "the SDK
		// passed 7".
		useDriver, label := *driver, "sdk "
		if c.kind() == kindWire {
			useDriver, label = "direct", "wire"
			wire++
		}
		if problems := runCase(c, useDriver, *proxyBin); len(problems) > 0 {
			if c.KnownGap != nil {
				// A documented gap that no longer reproduces is the good news
				// case, and it still fails: the corpus is now claiming a
				// weakness the pack does not have, which is the same defect as
				// claiming a defence it does not have. Update the trace.
				failed++
				fmt.Printf("FAIL  [gap ] %s — this known gap NO LONGER REPRODUCES\n", c.Name)
				fmt.Printf("        if the pack improved, delete the known_gap marker and assert the "+
					"behaviour you now want (%s)\n", c.KnownGap.ClosesWith)
				for _, p := range problems {
					fmt.Printf("        %s\n", p)
				}
				continue
			}
			failed++
			fmt.Printf("FAIL  [%s] %s\n", label, c.Name)
			for _, p := range problems {
				fmt.Printf("        %s\n", p)
			}
			continue
		}
		if c.KnownGap != nil {
			// Not a pass. The attack succeeded and the trace proves it still
			// does; printing PASS would let a reader skim a green run and
			// conclude the pack defends against something it does not.
			gaps++
			fmt.Printf("GAP   [gap ] %s\n", c.Name)
			fmt.Printf("        %s\n", c.KnownGap.Why)
			fmt.Printf("        closes with: %s\n", c.KnownGap.ClosesWith)
			continue
		}
		fmt.Printf("PASS  [%s] %s\n", label, c.Name)
	}
	if gaps > 0 {
		fmt.Printf("\n%d cases (%d exercised %s, %d wire-contract), %d failed, "+
			"%d documented gaps — attacks this pack does NOT stop\n",
			len(files), len(files)-wire, *driver, wire, failed, gaps)
	} else {
		fmt.Printf("\n%d cases (%d exercised %s, %d wire-contract), %d failed\n",
			len(files), len(files)-wire, *driver, wire, failed)
	}
	if failed > 0 {
		os.Exit(1)
	}
}

// runCase stands up a proxy and an upstream, runs the driver against them, and
// judges the export. Each case gets its own proxy and its own ledger: a suite
// where one case can see another's evidence cannot tell a leak from a pass.
func runCase(c Case, driver, proxyBin string) (problems []string) {
	dir, err := os.MkdirTemp("", "gc") // short: unix socket paths cap at ~104 bytes
	if err != nil {
		return []string{err.Error()}
	}
	defer os.RemoveAll(dir)

	var sawHeaders []http.Header
	// The stub answers tools/list with real declarations, because the tool the
	// corpus most needs to exercise — signature binding (§7) — only works once
	// an upstream has said what it offers. Without this the registry is always
	// empty and no trace can reach the control.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sawHeaders = append(sawHeaders, r.Header.Clone())
		w.Header().Set("Content-Type", "application/json")
		if bytes.Contains(body, []byte("tools/list")) {
			w.Write([]byte(toolsListResult))
			return
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`))
	}))
	defer upstream.Close()

	listen, admin := freePort(), freePort()
	ledgerDir, stateDir := filepath.Join(dir, "l"), filepath.Join(dir, "s")
	proxy := exec.Command(proxyBin,
		"-upstream", upstream.URL, "-listen", listen, "-admin", admin,
		"-ledger-dir", ledgerDir, "-state-dir", stateDir)
	var proxyLog bytes.Buffer
	proxy.Stdout, proxy.Stderr = &proxyLog, &proxyLog
	if err := proxy.Start(); err != nil {
		return []string{fmt.Sprintf("start proxy: %v", err)}
	}
	// Both listeners, not just the socket: a proxy whose HTTP port lost a race
	// to another process would otherwise be "ready" and every call would fail
	// with a connection error that looks like an SDK bug.
	defer func() {
		if proxy.ProcessState == nil {
			proxy.Process.Kill()
			proxy.Wait()
		}
	}()
	sock := filepath.Join(stateDir, "tis.sock")
	ready := func() bool {
		if _, err := os.Stat(sock); err != nil {
			return false
		}
		resp, err := http.Get("http://" + admin + "/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		c, err := net.DialTimeout("tcp", listen, 200*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	if err := waitFor(ready); err != nil {
		return []string{fmt.Sprintf("proxy never came up: %v\n%s", err, proxyLog.String())}
	}

	env := map[string]string{
		"GURDY_PROXY_URL":  "http://" + listen,
		"GURDY_TIS_SOCKET": sock,
	}
	tr, err := runDriver(driver, c, env)
	if err != nil {
		problems = append(problems, fmt.Sprintf("driver: %v", err))
	}

	// SIGTERM, not Kill: the proxy signs its final batch and writes its
	// shutdown record on the way out, and the suite asserts on a *closed*
	// export because that is what an auditor is handed.
	proxy.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { proxy.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		// A proxy that will not close leaves an unsigned tail, which the
		// export check below reports rather than papering over.
		proxy.Process.Kill()
		<-done
		problems = append(problems, "proxy did not shut down within 15s")
	}

	problems = append(problems, judge(c, ledgerDir, sawHeaders, tr)...)
	// A failing case without the proxy's own account of what it decided sends
	// you debugging the SDK for something the proxy already explained on
	// stderr. Only on failure, and only then, because the decision log is
	// per-call and would bury a passing run.
	if len(problems) > 0 && proxyLog.Len() > 0 {
		problems = append(problems, "proxy log:\n        "+
			strings.ReplaceAll(strings.TrimSpace(proxyLog.String()), "\n", "\n        "))
	}
	return problems
}

// Transcript is what a driver reports: one entry per step it executed. A
// structured transcript rather than free-form output, because a case whose
// only evidence is a printed word can be satisfied by printing that word — a
// driver could "pass" the narrow-only case without ever calling derive.
type Transcript struct {
	Steps []StepResult `json:"steps"`
}

type StepResult struct {
	Index   int    `json:"index"`
	Refused bool   `json:"refused"`
	Reason  string `json:"reason"`
}

// runDriver executes the case. The built-in reference driver is in-process;
// anything else is a subprocess speaking the documented protocol, bounded by a
// timeout so a hung SDK driver fails its case instead of the whole CI run.
func runDriver(driver string, c Case, env map[string]string) (Transcript, error) {
	if driver == "direct" {
		return directDriver(c, env["GURDY_PROXY_URL"], env["GURDY_TIS_SOCKET"])
	}
	ctx, cancel := context.WithTimeout(context.Background(), driverTimeout)
	defer cancel()
	body, _ := json.Marshal(c)
	cmd := exec.CommandContext(ctx, driver)
	cmd.Stdin = bytes.NewReader(body)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return Transcript{}, fmt.Errorf("driver did not finish within %s", driverTimeout)
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return Transcript{}, fmt.Errorf("exit %d: %s", ee.ExitCode(), ee.Stderr)
		}
		return Transcript{}, err
	}
	var tr Transcript
	if err := json.Unmarshal(out, &tr); err != nil {
		return Transcript{}, fmt.Errorf("driver output is not a transcript: %v (got %q)", err, out)
	}
	return tr, nil
}

const driverTimeout = 60 * time.Second

// toolsListResult is what the stub upstream declares about itself. The argument
// names are deliberately ones the extractor's name heuristic does NOT know
// ("victim", "loc"), so a trace that resolves them proves the role came from the
// declaration rather than from a lucky guess.
const toolsListResult = `{"jsonrpc":"2.0","id":1,"result":{"tools":[
  {"name":"read_file","description":"Read a file",
   "inputSchema":{"type":"object","properties":{"victim":{"type":"string","description":"absolute file path to read"}}}},
  {"name":"purge_file","description":"Delete a file permanently",
   "inputSchema":{"type":"object","properties":{"victim":{"type":"string","description":"absolute file path to remove"}}}},
  {"name":"delete_file","description":"Delete a file",
   "inputSchema":{"type":"object","properties":{"victim":{"type":"string","description":"absolute file path to remove"}}}}
]}}`

// judge compares the export against the case's expectations.
func judge(c Case, ledgerDir string, sawHeaders []http.Header, tr Transcript) (problems []string) {
	// Every step the case marks expect_refused must appear in the transcript
	// as a refusal *of that step*. This is what stops a driver from claiming a
	// refusal it never attempted.
	byIndex := map[int]StepResult{}
	for _, r := range tr.Steps {
		byIndex[r.Index] = r
	}
	for i, st := range c.Steps {
		if st.Derive == nil || !st.Derive.ExpectRefused {
			continue
		}
		got, ok := byIndex[i]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"step %d expected a refusal but the driver never reported executing it", i))
			continue
		}
		if !got.Refused {
			problems = append(problems, fmt.Sprintf("step %d: derive succeeded, want refused", i))
			continue
		}
		for _, want := range c.Expect.DriverErrorContains {
			if !strings.Contains(got.Reason, want) {
				problems = append(problems, fmt.Sprintf(
					"step %d: refusal reason %q does not mention %q", i, got.Reason, want))
			}
		}
	}
	for _, h := range c.Expect.UpstreamNeverSawHeader {
		for i, hdr := range sawHeaders {
			if hdr.Get(h) != "" {
				problems = append(problems, fmt.Sprintf(
					"upstream request %d carried %s — it is hop-by-hop and must be consumed", i, h))
			}
		}
	}

	if c.Expect.UpstreamCalls != nil && len(sawHeaders) != *c.Expect.UpstreamCalls {
		problems = append(problems, fmt.Sprintf(
			"upstream saw %d requests, want %d — monitor mode forwards every call it records (ADR-3)",
			len(sawHeaders), *c.Expect.UpstreamCalls))
	}
	decisions, answered, err := decisionRecords(ledgerDir, c.Expect.AllowOpenExport)
	if err != nil {
		return append(problems, err.Error())
	}
	if len(decisions) != len(c.Expect.Records) {
		return append(problems, fmt.Sprintf("want %d decision records, got %d: %s",
			len(c.Expect.Records), len(decisions), summarize(decisions)))
	}
	for i, want := range c.Expect.Records {
		problems = append(problems, matchRecord(i, want, decisions[i], decisions, answered)...)
	}
	return problems
}

func matchRecord(i int, want RecordMatch, got map[string]any, all []map[string]any, answered map[string]bool) (problems []string) {
	check := func(field, wantV string) {
		if wantV == "" {
			return
		}
		if gotV, _ := got[field].(string); gotV != wantV {
			problems = append(problems, fmt.Sprintf("record %d: %s = %q, want %q", i, field, gotV, wantV))
		}
	}
	check("action", want.Action)
	check("tool", want.Tool)
	check("decision", want.Decision)
	check("assertion_status", want.AssertionStatus)
	check("asserted_principal", want.AssertedPrincipal)
	check("asserted_human_actor", want.AssertedHumanActor)
	check("principal_tier", want.PrincipalTier)
	check("action_applied", want.ActionApplied)
	check("policy_mode", want.PolicyMode)

	if want.Policy != "" {
		var fired []string
		if raw, ok := got["policy_effects"].([]any); ok {
			for _, e := range raw {
				if m, ok := e.(map[string]any); ok {
					if id, _ := m["policy_id"].(string); id != "" {
						fired = append(fired, id)
					}
				}
			}
		}
		if !slices.Contains(fired, want.Policy) {
			problems = append(problems, fmt.Sprintf(
				"record %d: policy %q did not fire (fired: %v) — the decision may be right for the wrong reason",
				i, want.Policy, fired))
		}
	}
	if want.PrincipalPrefix != "" {
		p, _ := got["principal"].(string)
		if !strings.HasPrefix(p, want.PrincipalPrefix) {
			problems = append(problems, fmt.Sprintf(
				"record %d: observed principal %q does not start with %q — the SDK's claim displaced it",
				i, p, want.PrincipalPrefix))
		}
	}
	if want.Lineage != nil {
		var lineage []string
		if raw, ok := got["lineage"].([]any); ok {
			for _, v := range raw {
				s, _ := v.(string)
				lineage = append(lineage, s)
			}
		}
		if strings.Join(lineage, ">") != strings.Join(want.Lineage, ">") {
			problems = append(problems, fmt.Sprintf("record %d: lineage %v, want %v", i, lineage, want.Lineage))
		}
	}
	if want.SameTxnAs != nil {
		j := *want.SameTxnAs
		mine, _ := got["txn_id"].(string)
		if j < 0 || j >= len(all) {
			problems = append(problems, fmt.Sprintf("record %d: same_txn_as %d is out of range", i, j))
		} else if theirs, _ := all[j]["txn_id"].(string); mine == "" || mine != theirs {
			problems = append(problems, fmt.Sprintf(
				"record %d: txn_id %q does not match record %d's %q — the calls are not in one transaction",
				i, mine, j, theirs))
		}
	}
	if want.Answered {
		id, _ := got["call_id"].(string)
		if !answered[id] {
			problems = append(problems, fmt.Sprintf(
				"record %d: no response record joins call_id %q — the call was recorded but never answered", i, id))
		}
	}
	if want.NoAssertedFields {
		// §5.5: asserted fields are written only when the assertion verified.
		// An SDK that cannot produce a valid credential must produce *no*
		// claim, not an unverified one.
		for _, f := range []string{"asserted_principal", "asserted_human_actor", "asserted_scope", "lineage"} {
			if got[f] != nil {
				problems = append(problems, fmt.Sprintf(
					"record %d: %s present without a valid assertion — an unverified claim was recorded as one", i, f))
			}
		}
	}
	return problems
}

// decisionRecords returns the workload chain's decisions, and fails the case if
// the export does not verify: evidence that does not survive gurdy-verify is
// not evidence, whatever it says.
func decisionRecords(dir string, allowOpen bool) ([]map[string]any, map[string]bool, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("no export was written at all")
	}
	var out []map[string]any
	answered := map[string]bool{}
	for _, f := range files {
		res, err := ledger.VerifyFile(f, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("export does not verify: %s: %v", filepath.Base(f), err)
		}
		// The README promises a *closed* export, so check it rather than
		// asserting it in prose: an unsigned tail or a missing shutdown record
		// means the proxy did not finish, and every field read after that is
		// read from evidence nobody signed.
		if !allowOpen {
			if res.Uncovered > 0 {
				return nil, nil, fmt.Errorf("%s: %d records covered by no signature", filepath.Base(f), res.Uncovered)
			}
			if strings.HasPrefix(filepath.Base(f), ledger.ProxyPartition) &&
				(res.CleanEnd == nil || !*res.CleanEnd) {
				return nil, nil, fmt.Errorf("the proxy did not shut down cleanly; the export is truncated")
			}
		}
		if strings.HasPrefix(filepath.Base(f), ledger.ProxyPartition) {
			continue // lifecycle chain, not workload evidence
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			switch rec["kind"] {
			case "decision":
				out = append(out, rec)
			case "response":
				if id, _ := rec["call_id"].(string); id != "" {
					answered[id] = true
				}
			}
		}
	}
	return out, answered, nil
}

func summarize(records []map[string]any) string {
	var parts []string
	for _, r := range records {
		parts = append(parts, fmt.Sprintf("%v/%v", r["action"], r["tool"]))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func freePort() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "127.0.0.1:0"
	}
	defer l.Close()
	return l.Addr().String()
}

func waitFor(ok func() bool) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out")
}

// directDriver is the reference implementation of the driver contract: it does
// what an SDK must do, using nothing but the wire contract. Its job is to keep
// the corpus honest — an expectation no driver can satisfy is a bug in the
// case, and this is what proves the difference.
func directDriver(c Case, proxyURL, sock string) (Transcript, error) {
	tis := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	tokens := map[string]string{}
	var tr Transcript

	post := func(c *http.Client, url, body string) (int, map[string]string) {
		resp, err := c.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			return 0, map[string]string{"error": err.Error()}
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]string
		json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}

	for i, s := range c.Steps {
		switch {
		case s.Mint != nil:
			body, _ := json.Marshal(map[string]any{
				"agent": s.Mint.Agent, "human_actor": s.Mint.HumanActor, "scope": s.Mint.Scope})
			code, out := post(tis, "http://tis/mint", string(body))
			if code != http.StatusOK {
				tr.Steps = append(tr.Steps, StepResult{Index: i, Refused: true, Reason: out["error"]})
				continue
			}
			tokens[s.Mint.As] = out["txn"]
			tr.Steps = append(tr.Steps, StepResult{Index: i})

		case s.Derive != nil:
			body, _ := json.Marshal(map[string]any{
				"parent": tokens[s.Derive.From], "agent": s.Derive.Agent, "scope": s.Derive.Scope})
			code, out := post(tis, "http://tis/derive", string(body))
			if code != http.StatusOK {
				tr.Steps = append(tr.Steps, StepResult{Index: i, Refused: true, Reason: out["error"]})
				continue
			}
			tokens[s.Derive.As] = out["txn"]
			tr.Steps = append(tr.Steps, StepResult{Index: i})

		case s.Call != nil:
			body := s.Call.Body
			if body == "" {
				args, _ := json.Marshal(s.Call.Args)
				body = fmt.Sprintf(
					`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`,
					s.Call.Tool, args)
			}
			req, _ := http.NewRequest(http.MethodPost, proxyURL+s.Call.Path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			switch s.Call.Txn {
			case "", "none":
			case "forged":
				req.Header.Set("Gurdy-Txn", "eyJhbGciOiJFUzI1NiJ9.forged.signature")
			default:
				req.Header.Set("Gurdy-Txn", tokens[s.Call.Txn])
			}
			// A real boundary even here: the case says the call is made from
			// another execution context, and a reference driver that quietly
			// ran it inline would be asserting satisfiability it never
			// demonstrated. Waited on, so record order stays deterministic.
			send := func() error {
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return fmt.Errorf("call: %w", err)
				}
				io.Copy(io.Discard, resp.Body)
				return resp.Body.Close()
			}
			sendErr := send
			if s.Call.In != "" {
				sendErr = func() error {
					done := make(chan error, 1)
					go func() { done <- send() }()
					return <-done
				}
			}
			if err := sendErr(); err != nil {
				return tr, err
			}
			tr.Steps = append(tr.Steps, StepResult{Index: i})
		}
	}
	return tr, nil
}
