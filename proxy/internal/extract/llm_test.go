package extract

import "testing"

const anthropicBody = `{"model":"claude-opus-4-6","max_tokens":1024,"stream":true,
  "messages":[{"role":"user","content":"summarize this"},{"role":"assistant","content":"ok"}]}`

// A model call is an action in the same taxonomy as a tool call (§5.3,
// v0.8.4), and what it records is metadata: which model, which provider, how
// big a ceiling — never what was in the payload (NFR-7, ADR-7).
func TestModelCallClassified(t *testing.T) {
	res, ok := Default.Classify(Call{
		Host: "api.anthropic.com", Path: "/v1/messages",
		Body: []byte(anthropicBody),
	})
	if !ok {
		t.Fatal("a model call went ungoverned")
	}
	want := map[string]string{
		"provider": "anthropic", "model": "claude-opus-4-6", "endpoint": "/v1/messages",
		"stream": "true", "max_tokens": "1024", "messages": "2", "resource_host": "api.anthropic.com",
	}
	for k, v := range want {
		if res.Attrs[k] != v {
			t.Errorf("attr %s = %q, want %q", k, res.Attrs[k], v)
		}
	}
	if res.Action != "llm/completion" || res.Tool != "claude-opus-4-6" ||
		res.Resource != "anthropic/claude-opus-4-6" {
		t.Errorf("classification wrong: %+v", res)
	}
	for k, v := range res.Attrs {
		if len(v) > 200 || k == "messages_content" {
			t.Errorf("attr %s looks like payload content, which may never reach the ledger", k)
		}
	}
}

// An agent must not be able to relabel its own traffic. A tool call carrying a
// "model" argument is still a tool call — otherwise adding one word to a
// filesystem call would move it out of the reach of every fs policy.
func TestToolCallCannotPoseAsModelCall(t *testing.T) {
	res, ok := Default.Classify(Call{
		Tool:      "read_file",
		Arguments: map[string]any{"path": "/home/u/.ssh/id_rsa", "model": "claude-opus-4-6"},
		Host:      "api.anthropic.com", Path: "/v1/messages",
		Body: []byte(anthropicBody),
	})
	if !ok {
		t.Fatal("tool call not classified")
	}
	if res.Action != "mcp/tools_call" || res.Tool != "read_file" {
		t.Fatalf("a tool call relabelled itself as a model call: %+v", res)
	}
	if res.Attrs["resource_path"] != "/home/u/.ssh/id_rsa" {
		t.Errorf("fs attributes lost: %+v", res.Attrs)
	}
}

// The reverse: only a request that actually looks like a completion counts.
// Recording ordinary JSON as a model call would put junk in the evidence, and
// a reader who cannot trust the action taxonomy cannot trust the record.
func TestNonCompletionBodiesAreNotModelCalls(t *testing.T) {
	for _, c := range []struct {
		name, path, body string
	}{
		{"model list", "/v1/models", `{"model":"claude-opus-4-6"}`},
		{"config blob", "/settings", `{"model":"x","temperature":0.5}`},
		{"embeddings", "/v1/embeddings", `{"model":"text-embed-3","input":"some text"}`},
		{"image generation", "/v1/images/generations", `{"model":"dall-e","prompt":"a cat"}`},
		{"health check", "/healthz", `{"ok":true}`},
		{"junk on an unknown path", "/whatever", `not json at all`},
	} {
		if res, ok := Default.Classify(Call{Host: "h", Path: c.path, Body: []byte(c.body)}); ok {
			t.Errorf("%s was classified as %s", c.name, res.Action)
		}
	}
}

// A malformed body on a *recognized* endpoint is not "not mine" — it is the
// malformed-payload evasion (§8.4). The call must come back recognized and
// undecodable so the gateway records it as indeterminate; classifying it away
// is exactly the silence a broken payload is buying.
func TestMalformedBodyOnKnownEndpointIsRecognized(t *testing.T) {
	for _, body := range []string{`not json at all`, ``, `{"messages": "wrong type"}`, `{`} {
		res, ok := Default.Classify(Call{
			Host: "api.anthropic.com", Path: "/v1/messages", Body: []byte(body),
		})
		if !ok || !res.Undecodable {
			t.Errorf("body %q on /v1/messages went unrecorded (ok=%v, undecodable=%v)", body, ok, res.Undecodable)
		}
		if res.Action != "llm/completion" {
			t.Errorf("body %q: action %q", body, res.Action)
		}
	}
}

// Model identifiers that live in the path, not the body. Without them a policy
// about which model may be called cannot see the model on the two providers
// that put it in the URL.
func TestModelFromPath(t *testing.T) {
	for _, c := range []struct{ host, path, wantModel, wantProvider string }{
		{"my-co.openai.azure.com", "/openai/deployments/gpt-4o-prod/chat/completions", "gpt-4o-prod", "azure-openai"},
		{"bedrock-runtime.us-east-1.amazonaws.com", "/model/anthropic.claude-v2/converse", "anthropic.claude-v2", "bedrock"},
		{"generativelanguage.googleapis.com", "/v1beta/models/gemini-2.0-pro:generateContent", "gemini-2.0-pro", "google"},
	} {
		res, ok := Default.Classify(Call{Host: c.host, Path: c.path,
			Body: []byte(`{"messages":[{"role":"user","content":"hi"}]}`)})
		if !ok || res.Tool != c.wantModel || res.Attrs["provider"] != c.wantProvider {
			t.Errorf("%s%s: got model=%q provider=%q, want %q/%q",
				c.host, c.path, res.Tool, res.Attrs["provider"], c.wantModel, c.wantProvider)
		}
	}
}

// An extractor that panics on adversarial input must not take the request with
// it: monitor mode may never break traffic (NFR-3). The call surfaces as
// recognized-but-undecodable, which the gateway records as indeterminate.
func TestPanickingExtractorIsContained(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic escaped the registry: %v", r)
		}
	}()
	res, ok := Registry{panicExtractor{}}.Classify(Call{Tool: "x"})
	if !ok || !res.Undecodable {
		t.Fatalf("a panicking extractor produced no record: %+v", res)
	}
}

type panicExtractor struct{}

func (panicExtractor) Name() string { return "boom" }
func (panicExtractor) Extract(Call) (Result, bool) {
	var m map[string]string
	m["write to nil map"] = "panics"
	return Result{}, true
}

// Provider naming is a control, not a convenience: a lookalike endpoint
// harvesting an agent's prompts must be reported as unlisted rather than
// inheriting the name it claims, since "unlisted" is what a pack flags on.
func TestProviderNaming(t *testing.T) {
	for host, want := range map[string]string{
		"api.anthropic.com":                       "anthropic",
		"api.anthropic.com:443":                   "anthropic",
		"API.ANTHROPIC.COM":                       "anthropic",
		"api.openai.com":                          "openai",
		"generativelanguage.googleapis.com":       "google",
		"bedrock-runtime.us-east-1.amazonaws.com": "bedrock",
		"localhost:11434":                         "local",
		"api-anthropic.com.evil.example":          "unlisted",
		"anthropic.com.attacker.test":             "unlisted",
		// A bucket named to look like the model service is the exfil case the
		// unlisted-host rule exists for; substring matching would wave it past.
		"bedrock-dump.s3.amazonaws.com":                    "unlisted",
		"my-openai.azure.com.evil.test":                    "unlisted",
		"[::1]:11434":                                      "local",
		"bedrock-runtime-fips.us-gov-west-1.amazonaws.com": "bedrock",
		"": "unknown",
	} {
		if got := provider(host); got != want {
			t.Errorf("provider(%q) = %q, want %q", host, got, want)
		}
	}
}

// A gateway can mount a completion endpoint anywhere, so body shape carries
// the match when the path is unfamiliar — otherwise routing model traffic
// through a proxy path of your choosing would make it invisible.
func TestUnfamiliarPathStillClassifiedByBodyShape(t *testing.T) {
	res, ok := Default.Classify(Call{
		Host: "llm-gw.internal", Path: "/proxy/generate/v3",
		Body: []byte(`{"model":"llama-3","messages":[{"role":"user","content":"hi"}]}`),
	})
	if !ok || res.Action != "llm/completion" {
		t.Fatalf("model call through an unfamiliar path went ungoverned: %+v", res)
	}
	if res.Attrs["provider"] != "unlisted" {
		t.Errorf("provider = %q, want unlisted", res.Attrs["provider"])
	}
}
