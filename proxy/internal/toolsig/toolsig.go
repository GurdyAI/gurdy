// Package toolsig binds policy to what a tool *is* rather than to what it is
// called (§7: "policy binds to upstream endpoint + tool signature, not display
// name").
//
// The attack it answers is in the adversarial corpus. Every control in the
// starter pack matches a string the governed party chooses — the tool name, the
// argument name — so renaming `delete_file` to `purge_file`, or passing a path
// as `src` instead of `path`, walks straight past it. Five of the corpus's seven
// remaining gaps share that root cause.
//
// What makes a signature trustworthy is *who declares it*. An MCP server
// advertises its tools through `tools/list`, including a JSON Schema for each
// one's arguments. The agent picks which tool to call; it does not get to write
// that declaration. So the proxy learns signatures by watching `tools/list`
// responses and keys them by the **upstream endpoint**, which is also not the
// agent's to choose — it is where the proxy forwards.
//
// Three things this buys, and one it does not:
//
//   - **A stable identity.** (endpoint, name, schema hash) survives a display
//     name change, because a renamed tool has a different name and therefore a
//     different key — which makes it *undeclared*, and that is itself a fact
//     policy can act on.
//   - **Argument roles instead of argument names.** The schema says which
//     property is a filesystem path; the extractor no longer has to guess from a
//     fixed list of names it hopes someone thought of.
//   - **A key for pack authors.** A capability declaration ("this signature is
//     destructive") needs something stable to attach to, and a display name is
//     not it.
//
// What it does not buy: **capability inference.** A schema says `fs_write` takes
// a path and a mode; it does not say that `mode: "truncate"` destroys the file.
// Deriving intent from a description would need a model in the decision path,
// which ADR-7 forbids permanently. Capability therefore comes from a pack
// declaration keyed by signature, and that is the pack registry's job (§5.4).
//
// The honest limit: a server that lies in `tools/list` is trusted here, because
// the agent-versus-server distinction is what the whole mechanism rests on. An
// agent that also controls its MCP server controls its declarations, and no
// amount of signature binding changes that — it is a different threat model,
// and the deployment answer is which servers you let an agent reach.
package toolsig

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Signature is what an upstream declared about one tool.
type Signature struct {
	// Hash identifies the declared argument schema. Content-addressed so two
	// tools with identical schemas share it — a rename is then visibly the same
	// shape under a new name, which is exactly the aliasing case.
	Hash string
	// PathArgs and URLArgs are argument names the *schema* marks as filesystem
	// paths or URLs, so a control can find the path without knowing what the
	// tool chose to call it.
	PathArgs []string
	URLArgs  []string
}

// Registry maps (upstream endpoint, tool name) to what that endpoint declared.
//
// Keyed by endpoint because the same display name means different things on
// different servers, and because the endpoint is the half of the identity the
// agent cannot influence.
type Registry struct {
	mu   sync.RWMutex
	sigs map[string]Signature
	// maxTools bounds memory: a hostile or broken server could advertise an
	// unbounded tool list, and a monitor that exhausts memory stops governing
	// (NFR-3).
	maxTools int
}

const defaultMaxTools = 4096

func New() *Registry {
	return &Registry{sigs: map[string]Signature{}, maxTools: defaultMaxTools}
}

func key(endpoint, tool string) string {
	// Lowercased for the same reason policy matching is (see policy.Evaluate):
	// case is not an identity distinction anyone should be able to exploit.
	return strings.ToLower(endpoint) + "\x00" + strings.ToLower(tool)
}

// Observe records the declarations in one tools/list response.
func (r *Registry) Observe(endpoint string, decls []Declaration) int {
	if len(decls) == 0 {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, d := range decls {
		if d.Name == "" {
			continue
		}
		if len(r.sigs) >= r.maxTools {
			// Stop recording rather than evict: an eviction policy here would
			// let a flood of junk declarations push out the real ones, turning
			// known tools into unknown ones and inverting what the registry is
			// for.
			break
		}
		r.sigs[key(endpoint, d.Name)] = d.signature()
		n++
	}
	return n
}

// Lookup returns the declared signature, and whether this endpoint ever
// declared this tool at all.
//
// The boolean is the interesting half. An undeclared tool is not an error — a
// client may call before listing, and some servers do not implement tools/list
// — but it is a *fact*: this deployment has no record of the upstream offering
// it. That is what a rename looks like from here.
func (r *Registry) Lookup(endpoint, tool string) (Signature, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sigs[key(endpoint, tool)]
	return s, ok
}

// Len is the number of declarations held, for /health and tests.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sigs)
}

// Declaration is one entry of a tools/list result.
type Declaration struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// signature derives the stable identity and the argument roles.
func (d Declaration) signature() Signature {
	sig := Signature{Hash: schemaHash(d.InputSchema)}
	sig.PathArgs, sig.URLArgs = argRoles(d.InputSchema)
	return sig
}

// schemaHash is content-addressed over the *canonical* form of the schema, so
// two servers that declare the same shape with different key ordering or
// whitespace produce the same signature. Without canonicalisation the hash
// would identify a serialisation rather than a schema.
func schemaHash(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Undecodable schema: hash the bytes. Still stable, still distinguishes
		// this declaration from another, and never silently equal to a schema
		// that *did* parse.
		return "raw:" + fmt.Sprintf("%x", sha256.Sum256(raw))[:32]
	}
	canon, err := json.Marshal(canonical(v))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(canon))[:32]
}

// canonical rebuilds a decoded value with maps in sorted key order. Go's
// encoding/json already emits map keys sorted, so this is really about
// recursing through the structure so that ordering holds at every depth.
func canonical(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out[k] = canonical(t[k])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = canonical(e)
		}
		return out
	default:
		return v
	}
}

// argRoles reads a JSON Schema object and reports which properties are
// filesystem paths and which are URLs.
//
// Deliberately shallow, and the shallowness is the honest part. JSON Schema has
// no "this is a filesystem path" type, so this reads the two signals a real MCP
// server actually emits: the standard `format` keyword (`uri`, `iri`), and a
// name that reads like a path. The name heuristic is the same guess the
// extractor makes today — but it is applied to the *server's declaration*
// rather than to the agent's call, which is the whole difference: the agent can
// rename its argument, and it cannot rename the schema the server published.
func argRoles(raw json.RawMessage) (paths, urls []string) {
	var schema struct {
		Properties map[string]struct {
			Type        string `json:"type"`
			Format      string `json:"format"`
			Description string `json:"description"`
		} `json:"properties"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &schema) != nil {
		return nil, nil
	}
	for name, p := range schema.Properties {
		if p.Type != "" && p.Type != "string" {
			continue
		}
		switch {
		case p.Format == "uri" || p.Format == "iri" || p.Format == "url":
			urls = append(urls, name)
		case looksLikePath(name) || looksLikePath(p.Description):
			paths = append(paths, name)
		case looksLikeURL(name):
			urls = append(urls, name)
		}
	}
	// Sorted so a signature is deterministic and two runs agree.
	sort.Strings(paths)
	sort.Strings(urls)
	return paths, urls
}

var pathWords = []string{"path", "file", "filename", "directory", "dir", "target", "src", "source", "destination", "dest", "location"}
var urlWords = []string{"url", "uri", "endpoint", "href", "link"}

func looksLikePath(s string) bool { return containsWord(s, pathWords) }
func looksLikeURL(s string) bool  { return containsWord(s, urlWords) }

func containsWord(s string, words []string) bool {
	l := strings.ToLower(s)
	for _, w := range words {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}
