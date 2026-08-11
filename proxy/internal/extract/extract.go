// Package extract resolves policy-relevant attributes from intercepted calls
// (FR-6): a registry of per-domain extractors, each recognizing the traffic it
// understands and naming the §5.3 action-taxonomy entry it belongs to.
//
// The action is the extractor's answer, not the call site's. That is what lets
// a model call (`llm/completion`) and an MCP tool call (`mcp/tools_call`) share
// one decision path and one provenance chain without either being special-cased
// in the gateway (v0.8.4).
package extract

// Call is the transport-neutral view of one intercepted call. Both halves are
// optional: MCP traffic fills Tool/Arguments, a reverse-proxied HTTP request
// fills Method/Host/Path/Body, and an extractor reads whichever it needs.
//
// Body is here so an extractor can read the *shape* of a request — never so it
// can record one. Deriving a count or a hash from it is fine; putting payload
// content into Attrs would put it in the ledger, which NFR-7 forbids.
type Call struct {
	Tool      string
	Arguments map[string]any
	Host      string
	Path      string
	Body      []byte
	// Signature is the upstream's own declaration for this tool, when one was
	// observed. Extractors prefer it over guessing argument roles from names:
	// the agent chooses the name it sends, and it does not choose the schema
	// the server published.
	Signature *Signature
}

// Result is what one extractor concluded about a call.
type Result struct {
	Action   string            // §5.3 taxonomy entry, e.g. "mcp/tools_call", "llm/completion"
	Tool     string            // the thing being called: MCP tool name, or the model
	Resource string            // primary resource identifier ("" when none is derivable)
	Attrs    map[string]string // policy-relevant attributes; never payload content
	// Undecodable marks traffic an extractor *recognized* but could not read —
	// a governed endpoint carrying a malformed body. It is not "no match": the
	// call must still be recorded, as indeterminate, or a deliberately broken
	// payload buys silence on an endpoint the proxy is supposed to be watching
	// (§5.1, the malformed-payload evasion of §8.4).
	Undecodable bool
}

// An Extractor recognizes one domain of traffic. Extract reports false when
// the call is not its business and the registry moves on.
type Extractor interface {
	Name() string
	Extract(Call) (Result, bool)
}

// Registry is an ordered set of extractors: first match wins. The ordering is
// the contract — merging several extractors' results would make the recorded
// action depend on iteration order, and hand an attacker a way to make two
// extractors disagree about what a call was.
type Registry []Extractor

// Default is the built-in registry. The specific extractor runs before the
// general one: an MCP tool call carrying a model-shaped argument is still an
// MCP tool call, and a model call is not a filesystem call.
//
// ponytail: a slice, not a plugin loader. Pack-supplied extractors (DB, cloud
// API, FHIR) arrive as further entries; a dynamic loader waits until a pack
// actually ships one, because the boundary such a loader needs is this
// interface, and it exists now.
var Default = Registry{llmExtractor{}, toolExtractor{}}

// Classify returns the first extractor's verdict, and false when nothing
// recognized the call — traffic the proxy forwards without governing.
func (r Registry) Classify(c Call) (Result, bool) {
	for _, e := range r {
		res, ok := safeExtract(e, c)
		if !ok {
			continue
		}
		if res.Attrs == nil {
			res.Attrs = map[string]string{}
		}
		return res, true
	}
	return Result{}, false
}

// safeExtract contains a panicking extractor. Extractors parse adversary-
// controlled bodies, and they will eventually arrive from packs rather than
// from this repo; a panic on the decision path would take down the request
// that triggered it, which is monitor mode breaking traffic (NFR-3). A
// crashing extractor yields recognized-but-undecodable instead, so the call is
// recorded as indeterminate rather than lost — or fatal.
func safeExtract(e Extractor, c Call) (res Result, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			res = Result{Action: e.Name() + "/panic", Undecodable: true,
				Attrs: map[string]string{"reason": "extractor panicked"}}
			ok = true
		}
	}()
	return e.Extract(c)
}

// Signature is what the upstream declared about the tool being called, when it
// declared anything (internal/toolsig). Present means this endpoint published
// the tool through tools/list; absent means it did not, which is what a renamed
// tool looks like from here and is itself policy-visible as tool_declared.
type Signature struct {
	Hash     string
	PathArgs []string
	URLArgs  []string
}
