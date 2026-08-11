package extract

import (
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// llmExtractor recognizes the agent's call to a model and classifies it as
// `llm/completion` (§5.3, v0.8.4). A model is a tool the agent calls, so this
// is an extractor and a policy family — not a second subsystem — and the
// resulting record sits in the same provenance chain as the agent's tool
// calls, under the same identity.
//
// What it extracts is metadata only: provider, model, endpoint, streaming, the
// declared token ceiling and the message count. Nothing about *what was in* the
// payload — that is a classifier's job, it is probabilistic, and it arrives
// afterwards as an advisory finding, never on the decision path (ADR-7,
// permanent).
type llmExtractor struct{}

func (llmExtractor) Name() string { return "llm" }

// completionPaths are the well-known completion endpoints. A path match alone
// makes a request *recognized* — enough to demand a record even if the body is
// unreadable — while an unfamiliar path has to earn classification from the
// body's shape, because a gateway can mount a model API anywhere.
var completionPaths = []string{
	"/v1/messages",                 // Anthropic
	"/v1/chat/completions",         // OpenAI, Azure OpenAI, compatible gateways
	"/v1/completions",              // OpenAI legacy
	"/v1/responses",                // OpenAI Responses
	"/api/chat",                    // Ollama
	"/api/generate",                // Ollama
	":generatecontent",             // Gemini
	":streamgeneratecontent",       // Gemini streaming
	"/converse",                    // Bedrock Converse
	"/converse-stream",             // Bedrock Converse streaming
	"/invoke",                      // Bedrock InvokeModel
	"/invoke-with-response-stream", // Bedrock InvokeModel streaming
}

// Model identifiers that live in the path rather than the body. Without these
// an Azure deployment call or a Bedrock invoke records as "unnamed", and a
// policy about *which model* may be called cannot see the one thing it needs.
var pathModel = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/openai/deployments/([^/]+)/`),                // Azure OpenAI
	regexp.MustCompile(`(?i)/model/([^/]+)/(?:converse|invoke)`),          // Bedrock
	regexp.MustCompile(`(?i)/models/([^/:]+):(?:stream)?generatecontent`), // Gemini
}

// completionBody is the shape shared by every provider's request: a model name
// plus somewhere to put the conversation.
type completionBody struct {
	Model     string            `json:"model"`
	Stream    bool              `json:"stream"`
	MaxTokens int               `json:"max_tokens"`
	Messages  []json.RawMessage `json:"messages"` // Anthropic, OpenAI, Ollama, Bedrock Converse
	Contents  []json.RawMessage `json:"contents"` // Gemini
	Prompt    *json.RawMessage  `json:"prompt"`   // legacy completions
	Input     *json.RawMessage  `json:"input"`    // OpenAI Responses
}

func (llmExtractor) Extract(c Call) (Result, bool) {
	// A named MCP tool is a tool call even if its arguments mention a model:
	// the tool extractor owns it, and claiming it here would let an agent
	// relabel its own filesystem traffic by adding a "model" argument.
	if c.Tool != "" {
		return Result{}, false
	}
	known := knownPath(c.Path)
	host := hostname(c.Host)

	var b completionBody
	decoded := len(c.Body) > 0 && json.Unmarshal(c.Body, &b) == nil
	if !decoded {
		if !known {
			return Result{}, false
		}
		// Recognized by endpoint, unreadable as a request. Forwarded either
		// way, but it must not vanish: an undecodable body on a governed
		// endpoint is the malformed-payload evasion (§8.4), and silence is
		// exactly what it is buying.
		return Result{Action: "llm/completion", Undecodable: true,
			Attrs: map[string]string{"provider": provider(host), "endpoint": c.Path}}, true
	}

	model := b.Model
	if model == "" {
		model = modelFromPath(c.Path)
	}
	// prompt/input are shared with embeddings and image APIs, so they only
	// count as a conversation on a path that is known to be a completion.
	// Otherwise an embeddings call would enter the ledger as a model
	// completion, and an action taxonomy a reader cannot trust is worse than
	// a coarse one.
	conversation := len(b.Messages) > 0 || len(b.Contents) > 0
	if known {
		conversation = conversation || b.Prompt != nil || b.Input != nil
	}
	if !conversation {
		return Result{}, false
	}
	if model == "" && !known {
		return Result{}, false
	}

	attrs := map[string]string{
		"provider": provider(host),
		"endpoint": c.Path,
		"stream":   strconv.FormatBool(b.Stream),
	}
	if host != "" {
		// Same key and same normalization the tool extractor uses, so one
		// policy about where data may go covers tool calls and model calls
		// alike rather than needing a port-aware copy of itself.
		attrs["resource_host"] = host
	}
	if model != "" {
		attrs["model"] = model
	}
	if b.MaxTokens > 0 {
		// The *declared* ceiling, not the spend: a spend-limit policy needs a
		// number that exists before the response does (§8.4 corpus).
		attrs["max_tokens"] = strconv.Itoa(b.MaxTokens)
	}
	if n := len(b.Messages) + len(b.Contents); n > 0 {
		attrs["messages"] = strconv.Itoa(n)
	}

	if model == "" {
		model = "unnamed"
	}
	// Tool is the model, so `context.tool` — lowercased by the engine — lets a
	// pack name models the way it names tools. Resource is provider/model,
	// which is how a rule about *which model may be called* reads.
	return Result{
		Action:   "llm/completion",
		Tool:     model,
		Resource: attrs["provider"] + "/" + model,
		Attrs:    attrs,
	}, true
}

func knownPath(p string) bool {
	p = strings.ToLower(p)
	for _, s := range completionPaths {
		if strings.HasSuffix(p, s) || strings.Contains(p, s+"?") {
			return true
		}
	}
	return false
}

func modelFromPath(p string) string {
	for _, re := range pathModel {
		if m := re.FindStringSubmatch(p); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

// hostname strips the port (and IPv6 brackets) so provider matching and
// resource_host see the same shape the tool extractor produces.
func hostname(h string) string {
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}

// bedrockHost matches the model-serving endpoints only. Substring matching
// would let bedrock-dump.s3.amazonaws.com present itself as Bedrock, which is
// precisely the exfiltration destination the unlisted-host rule exists to
// flag — a name check that an attacker can satisfy by naming their bucket is
// not a check.
var bedrockHost = regexp.MustCompile(`^bedrock(-runtime)?(-fips)?\.[a-z0-9-]+\.amazonaws\.com$`)

// provider names the destination from its host. Unknown hosts are reported as
// "unlisted" rather than guessed: a lookalike endpoint collecting an agent's
// prompts is exactly what a pack wants to flag, and calling it by the name it
// claims would defeat that.
func provider(host string) string {
	h := strings.ToLower(hostname(host))
	switch {
	case h == "":
		return "unknown"
	case h == "api.anthropic.com":
		return "anthropic"
	case h == "api.openai.com":
		return "openai"
	case strings.HasSuffix(h, ".openai.azure.com"):
		return "azure-openai"
	case h == "generativelanguage.googleapis.com" || strings.HasSuffix(h, "-aiplatform.googleapis.com") ||
		h == "aiplatform.googleapis.com":
		return "google"
	case bedrockHost.MatchString(h):
		return "bedrock"
	case h == "localhost" || h == "127.0.0.1" || h == "::1":
		return "local"
	}
	return "unlisted"
}
