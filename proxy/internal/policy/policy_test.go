package policy

import (
	"slices"
	"testing"
)

func mustLoad(t testing.TB) *Evaluator {
	t.Helper()
	e, err := Load("starter-v0", Starter)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return e
}

func TestAllowBenignCall(t *testing.T) {
	e := mustLoad(t)
	r := e.Evaluate(Input{
		Principal: "agent-local",
		Tool:      "read_file",
		Action:    "mcp/tools_call",
		Resource:  "/workspace/notes.txt",
		Context:   map[string]string{"resource_path": "/workspace/notes.txt"},
	})
	if r.Decision != Allow {
		t.Fatalf("want allow, got %s (policies %v)", r.Decision, r.IDs())
	}
}

func TestFlagCredentialRead(t *testing.T) {
	e := mustLoad(t)
	r := e.Evaluate(Input{
		Principal: "agent-local",
		Tool:      "read_file",
		Action:    "mcp/tools_call",
		Resource:  "/Users/x/.ssh/id_ed25519",
		Context:   map[string]string{"resource_path": "/Users/x/.ssh/id_ed25519"},
	})
	if r.Decision != Flag {
		t.Fatalf("want flag, got %s", r.Decision)
	}
	if len(r.IDs()) == 0 {
		t.Fatal("flag decision must carry determining policy IDs")
	}
}

func TestFlagDestructiveOp(t *testing.T) {
	e := mustLoad(t)
	for tool, want := range map[string]Decision{
		"delete_file":      Flag,
		"remove_directory": Flag,
		"rm":               Flag,
		"DeleteFile":       Flag, // case tricks must not dodge matching
		"unlink_file":      Flag,
		"read_file":        Allow, // negative case: benign tool untouched
	} {
		r := e.Evaluate(Input{
			Principal: "agent-local", Tool: tool, Action: "mcp/tools_call",
			Resource: "/workspace/x",
			Context:  map[string]string{"resource_path": "/workspace/x"},
		})
		if r.Decision != want {
			t.Errorf("%s: got %s, want %s", tool, r.Decision, want)
		}
	}
}

func TestNoResourcePathIsAllowNotIndeterminate(t *testing.T) {
	e := mustLoad(t)
	r := e.Evaluate(Input{
		Principal: "agent-local",
		Tool:      "get_time",
		Action:    "mcp/tools_call",
		Resource:  "get_time",
	})
	if r.Decision != Allow {
		t.Fatalf("missing optional attr must not poison eval: want allow, got %s", r.Decision)
	}
}

func TestBadPolicyRejectedAtLoad(t *testing.T) {
	if _, err := Load("bad", []byte("permit (nonsense")); err == nil {
		t.Fatal("want parse error")
	}
	// Re-keying by @id means a duplicate silently drops a rule from the set —
	// a control missing from a pack that still lists it, and a policy_ids entry
	// that no longer says which rule fired.
	dup := []byte(`
@id("same") forbid (principal, action, resource) when { context.tool == "rm" };
@id("same") forbid (principal, action, resource) when { context.tool == "cp" };`)
	if _, err := Load("dup", dup); err == nil {
		t.Fatal("duplicate @id must fail the load, not overwrite a policy")
	}
}

// enforce_action is the graduation knob (ADR-14): the same forbid reads as
// "flagged" or "would have blocked" depending only on what its author declared,
// and both are recorded under policy_mode=monitor with the traffic forwarded.
// A typo in either annotation must fail the pack at load, not degrade silently
// to the permissive default — that is the whole reason to validate a value
// nothing consumes yet.
func TestEnforceMetadata(t *testing.T) {
	const forbidRm = `forbid (principal, action, resource) when { context.tool == "rm" };`
	in := Input{Principal: "a", Tool: "rm", Action: "mcp/tools_call", Resource: "/x"}

	for _, tc := range []struct {
		name, ann string
		want      Decision
	}{
		{"default is flag", `@id("p")`, Flag},
		{"explicit flag", `@id("p") @enforce_action("flag") @on_error("open")`, Flag},
		{"block is a conclusion, not an effect", `@id("p") @enforce_action("block")`, Block},
	} {
		e, err := Load("v", []byte(tc.ann+"\n"+forbidRm))
		if err != nil {
			t.Fatalf("%s: load: %v", tc.name, err)
		}
		if got := e.Evaluate(in).Decision; got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}

	for _, ann := range []string{`@enforce_action("blcok")`, `@on_error("clsoed")`, `@enforce_action("warn")`} {
		if _, err := Load("v", []byte(ann+"\n"+forbidRm)); err == nil {
			t.Errorf("%s: want load error, got none", ann)
		}
	}
}

// Most-restrictive-wins across the policies that produced one deny: if any
// matching forbid would have blocked, the call would have been blocked.
func TestBlockWinsOverFlag(t *testing.T) {
	e, err := Load("v", []byte(`
@id("flagger") @enforce_action("flag")
forbid (principal, action, resource) when { context.tool == "rm" };
@id("blocker") @enforce_action("block")
forbid (principal, action, resource) when { context has resource_path };`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := e.Evaluate(Input{Principal: "a", Tool: "rm", Action: "mcp/tools_call",
		Resource: "/x", Context: map[string]string{"resource_path": "/x"}})
	if r.Decision != Block {
		t.Fatalf("got %s, want block (policies %v)", r.Decision, r.IDs())
	}
	if len(r.IDs()) != 2 {
		t.Fatalf("both determining policies must be recorded, got %v", r.IDs())
	}
}

// BenchmarkEvaluate is the week-1 go/no-go gate (OQ #4): sub-ms eval or Cedar is out.
func BenchmarkEvaluate(b *testing.B) {
	e := mustLoad(b)
	in := Input{
		Principal: "agent-local",
		Tool:      "read_file",
		Action:    "mcp/tools_call",
		Resource:  "/Users/x/.ssh/id_ed25519",
		Context:   map[string]string{"resource_path": "/Users/x/.ssh/id_ed25519"},
	}
	b.ReportAllocs()
	for b.Loop() {
		e.Evaluate(in)
	}
}

// An extracted attribute must never shadow a reserved context key. Tool names
// are lowercased into context.tool precisely so name-matching policies cannot
// be dodged; letting an extractor overwrite that key would hand the dodge back
// through the tool's own arguments (§7 aliasing). The same applies to the
// identity keys: a forged asserted_principal is most dangerous exactly when
// there is no real one to overwrite it.
func TestExtractedAttrsCannotShadowReservedKeys(t *testing.T) {
	e, err := Load("test", []byte(`
@id("allow-all") permit (principal, action, resource);

@id("flag-destructive")
forbid (principal, action, resource) when { context.tool like "delete*" };

@id("trust-asserted")
forbid (principal, action, resource) when {
    context has asserted_principal &&
    context.asserted_principal == "quarantined-agent" &&
    context.assertion_status == "valid"
};`))
	if err != nil {
		t.Fatal(err)
	}
	// No assertion at all — every identity value below is attacker-supplied.
	r := e.Evaluate(Input{
		Principal:       "svc:host:127.0.0.1",
		AssertionStatus: "absent",
		Tool:            "delete_everything",
		Action:          "mcp/tools_call",
		Resource:        "/workspace/x",
		Context: map[string]string{
			"tool":               "read_file",     // dodge the name match
			"assertion_status":   "valid",         // self-certify
			"asserted_principal": "trusted-agent", // and pick an identity
		},
	})
	if !slices.Contains(r.IDs(), "flag-destructive") {
		t.Fatalf("shadowed context.tool dodged the destructive-op policy: %s %v", r.Decision, r.IDs())
	}

	// Same injection, but now the pack rule keys on the identity the caller
	// tried to forge. It must not be visible to Cedar at all.
	r = e.Evaluate(Input{
		Principal:       "svc:host:127.0.0.1",
		AssertionStatus: "absent",
		Tool:            "read_file",
		Action:          "mcp/tools_call",
		Resource:        "/workspace/x",
		Context: map[string]string{
			"asserted_principal": "quarantined-agent",
			"assertion_status":   "valid",
		},
	})
	if slices.Contains(r.IDs(), "trust-asserted") {
		t.Fatalf("extractor-supplied identity reached policy: %v", r.IDs())
	}
}

// Asserted identity reaches policy as context, never as the request principal
// (§5.5) — so a pack that trusts an agent-side claim does it on an explicit
// line, and gating on assertion_status actually works.
func TestAssertedIdentityIsContextNotPrincipal(t *testing.T) {
	e, err := Load("test", []byte(`
@id("allow-all")
permit (principal, action, resource);

@id("observed-principal-is-proxy-derived")
forbid (principal == Agent::"svc:host:10.0.0.9", action, resource);

@id("trust-asserted-only-when-valid")
forbid (principal, action, resource) when {
    context has asserted_principal &&
    context.asserted_principal == "quarantined-agent" &&
    context.assertion_status == "valid"
};`))
	if err != nil {
		t.Fatal(err)
	}
	base := Input{Tool: "read_file", Action: "mcp/tools_call", Resource: "/tmp/x"}

	in := base
	in.Principal, in.AssertionStatus = "svc:host:10.0.0.9", "absent"
	in.AssertedPrincipal = "friendly-name" // the claim must not become the principal
	if r := e.Evaluate(in); r.Decision != Flag || !slices.Contains(r.IDs(), "observed-principal-is-proxy-derived") {
		t.Fatalf("policy did not evaluate on the observed principal: %s %v", r.Decision, r.IDs())
	}

	in = base
	in.Principal, in.AssertedPrincipal, in.AssertionStatus = "svc:host:10.0.0.1", "quarantined-agent", "valid"
	if r := e.Evaluate(in); r.Decision != Flag {
		t.Fatalf("valid asserted claim unreachable from policy: %s", r.Decision)
	}

	// Same claim, unverified: the gate holds, which is the whole point of
	// exposing assertion_status alongside it (§5.9).
	in.AssertionStatus = "invalid"
	if r := e.Evaluate(in); r.Decision != Allow {
		t.Fatalf("unverified claim was trusted: %s %v", r.Decision, r.IDs())
	}
}

// Staged graduation puts policies with different declared behavior on the same
// call. A flat list of IDs cannot say which of them would have blocked and
// which was only flagging, and that is unreconstructable once the evidence is
// written (§5.5 v0.8.5).
func TestPerPolicyEffectsRecorded(t *testing.T) {
	e, err := Load("v", []byte(`
@id("flagger") @enforce_action("flag") @on_error("open")
forbid (principal, action, resource) when { context.tool == "rm" };
@id("blocker") @enforce_action("block") @on_error("closed")
forbid (principal, action, resource) when { context has resource_path };`))
	if err != nil {
		t.Fatal(err)
	}
	r := e.Evaluate(Input{Principal: "a", Tool: "rm", Action: "mcp/tools_call",
		Resource: "/x", Context: map[string]string{"resource_path": "/x"}})

	if r.Decision != Block {
		t.Fatalf("aggregate decision %s, want block (most restrictive wins)", r.Decision)
	}
	got := map[string]Effect{}
	for _, e := range r.Effects {
		got[e.PolicyID] = e
	}
	if len(got) != 2 {
		t.Fatalf("want an effect per determining policy, got %v", r.Effects)
	}
	if f := got["flagger"]; f.Decision != Flag || f.EnforceAction != EnforceFlag || f.OnError != OnErrorOpen {
		t.Errorf("flagger effect wrong: %+v", f)
	}
	if b := got["blocker"]; b.Decision != Block || b.EnforceAction != EnforceBlock || b.OnError != OnErrorClosed {
		t.Errorf("blocker effect wrong: %+v", b)
	}
	// Every policy is monitor until the actuator exists: a build that cannot
	// enforce must not let a pack claim in the evidence that it was enforcing.
	for _, e := range r.Effects {
		if e.Mode != ModeMonitor {
			t.Errorf("%s: mode %q in a build with no actuator", e.PolicyID, e.Mode)
		}
	}
}

// Case-folding is a property of matching, not of one field. It began as
// `context.tool` only, and adversarial corpus trace 05 found the same dodge one
// field over: the credential rule matches resource_path, and /home/u/.SSH/id_rsa
// is the same file on macOS and Windows. A one-line bypass of the flagship
// BR-11 control.
//
// The table is the point — a fix that lowercased only the field the corpus
// happened to name would pass one row and fail the rest.
func TestEveryMatchedStringIsCaseFolded(t *testing.T) {
	e, err := Load("v", []byte(`
@id("allow-all") permit (principal, action, resource);
@id("cred") forbid (principal, action, resource)
  when { context has resource_path && context.resource_path like "*/.ssh/*" };
@id("tool") forbid (principal, action, resource) when { context.tool like "delete*" };
@id("agent") forbid (principal, action, resource)
  when { context has asserted_principal && context.asserted_principal == "quarantined" };
@id("res") forbid (principal, action, resource == Resource::"/etc/shadow");`))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		in     Input
		policy string
	}{
		{"path segment", Input{Tool: "read_file", Action: "a",
			Context: map[string]string{"resource_path": "/home/u/.SSH/id_rsa"}}, "cred"},
		{"whole path", Input{Tool: "read_file", Action: "a",
			Context: map[string]string{"resource_path": "/HOME/U/.Ssh/ID_RSA"}}, "cred"},
		// Folding lowercases; it does not re-punctuate. "DeleteFile" becomes
		// "deletefile", which is why the shipped rule is a prefix match rather
		// than an equality — the first version of this test asserted equality
		// against "delete_file" and failed for that reason, not a code defect.
		{"tool name", Input{Tool: "DeleteFile", Action: "a"}, "tool"},
		{"asserted agent", Input{Tool: "x", Action: "a", AssertedPrincipal: "QuarantinEd",
			AssertionStatus: "valid"}, "agent"},
		{"resource uid", Input{Tool: "x", Action: "a", Resource: "/ETC/Shadow"}, "res"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Evaluate(tc.in)
			if !slices.Contains(got.IDs(), tc.policy) {
				t.Errorf("case variation dodged %q: decision %s, policies %v",
					tc.policy, got.Decision, got.IDs())
			}
		})
	}
}

// The cost of the fix, asserted so it is a known trade rather than a surprise:
// where case genuinely distinguishes two files, both now match. A spurious flag
// is noise in a monitor; a missed credential read is a bypass.
func TestCaseFoldingCanOverMatchAndThatIsTheSaferDirection(t *testing.T) {
	e, err := Load("v", []byte(`
@id("allow-all") permit (principal, action, resource);
@id("cred") forbid (principal, action, resource)
  when { context has resource_path && context.resource_path like "*/.ssh/*" };`))
	if err != nil {
		t.Fatal(err)
	}
	// On Linux this is a different directory from .ssh, and it flags anyway.
	got := e.Evaluate(Input{Tool: "read_file", Action: "a",
		Context: map[string]string{"resource_path": "/home/u/.SSH/notes.txt"}})
	if got.Decision != Flag {
		t.Errorf("expected the deliberate over-match, got %s", got.Decision)
	}
}
