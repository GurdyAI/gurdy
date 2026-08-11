// Package mcp parses MCP JSON-RPC frames far enough to classify tool calls (FR-1).
package mcp

import "encoding/json"

// ToolCall is one MCP tools/call request. Name is "" when the frame is a
// tools/call whose params were undecodable — the caller must record that as
// indeterminate (§5.1), not skip it (malformed-MCP evasion, §8.2 corpus).
type ToolCall struct {
	Name      string
	Arguments map[string]any
	// ID is the JSON-RPC id exactly as the client wrote it, "" for a
	// notification. It is the only thing that can join this call to the frame
	// that answers it on a stdio transport, where there is no request/response
	// pairing below the protocol (D4).
	ID string
}

// Response is one JSON-RPC response frame from the server: a frame carrying an
// id and no method. A server-to-client *request* also carries an id, hence the
// method test — attributing one of those to a pending call would answer a call
// with someone else's frame.
type Response struct {
	ID string
	// Raw is this element's own bytes. A batch response shares one line, so
	// hashing the element rather than the envelope is what makes a batched
	// call's resp_hash mean the same thing as an unbatched one's.
	//
	// For an unbatched frame this *aliases* the caller's buffer, which on the
	// shim is bufio's and is invalidated by the next read. Callers hash it
	// before returning; anything that wants to keep it must copy. Named here
	// because the failure mode is a resp_hash over someone else's frame —
	// misattributed evidence, silent, and the one thing this ledger may not do.
	Raw []byte
}

// frame is the envelope common to every JSON-RPC message. Method is a pointer
// so an *absent* method is distinguishable from `"method": ""` — the two look
// identical through a string field, and "has no method" is exactly the test
// that separates a response from a request.
type frame struct {
	Method *string         `json:"method"`
	ID     json.RawMessage `json:"id"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// elements splits a body into the frames it carries — a single request or a
// JSON-RPC batch array (removed in newer MCP revisions but still on the wire
// from older clients; a batched call must not dodge logging). Decoded
// independently so one malformed frame can't hide the rest.
func elements(body []byte) []json.RawMessage {
	var raws []json.RawMessage
	if err := json.Unmarshal(body, &raws); err != nil {
		return []json.RawMessage{body}
	}
	return raws
}

// ParseToolsCalls returns every tools/call in body. Empty slice for any other
// traffic, which is forwarded uninspected (§5.1).
func ParseToolsCalls(body []byte) []ToolCall {
	var calls []ToolCall
	for _, raw := range elements(body) {
		var f frame
		if err := json.Unmarshal(raw, &f); err != nil || f.Method == nil || *f.Method != "tools/call" {
			continue
		}
		var p callParams
		if err := json.Unmarshal(f.Params, &p); err != nil || p.Name == "" {
			calls = append(calls, ToolCall{ID: id(f)}) // undecodable tools/call
			continue
		}
		calls = append(calls, ToolCall{Name: p.Name, Arguments: p.Arguments, ID: id(f)})
	}
	return calls
}

// ParseResponses returns every response frame in line, with the bytes of each.
//
// A response is a frame with an id, no method, and a result or an error. All
// three tests are load-bearing: without the method test a server's own request
// to the client (sampling, elicitation) would be claimed as an answer, and
// without the result/error test a malformed frame that happens to carry a
// pending id would consume that call's pending entry and record *its* hash —
// the real response then arriving unrecorded.
func ParseResponses(line []byte) []Response {
	var out []Response
	for _, raw := range elements(line) {
		var f frame
		if err := json.Unmarshal(raw, &f); err != nil || f.Method != nil {
			continue
		}
		if f.Result == nil && f.Error == nil {
			continue
		}
		if k := id(f); k != "" {
			out = append(out, Response{ID: k, Raw: raw})
		}
	}
	return out
}

// id is the correlation key: the id's raw JSON bytes, not a decoded value, and
// "" for anything that must not correlate.
//
// Raw because the only thing that has to hold is that a request and the
// response echoing it produce the same key, and JSON-RPC says the response
// carries the request's id — so the bytes match whenever the peer echoes
// rather than re-serializes.
//
// `null` is excluded. It is the id a peer uses when it could not read the
// request well enough to know one, so it names no particular call; treating it
// as a key would join a parse-error frame to whichever malformed call happened
// to carry a null id.
//
// ponytail: a peer that re-serializes 1 as 1.0, or reorders a (non-conformant)
// object id, produces a key that does not match and the call stays *unanswered*
// — a visible missing half, never a response joined to the wrong call. Upgrade
// path is canonicalizing scalars here; not worth it until a real server is seen
// doing it.
func id(f frame) string {
	if k := string(f.ID); k != "null" {
		return k
	}
	return ""
}

// IsToolsList reports whether a request body asks the upstream to enumerate its
// tools. The proxy watches for it so it can read the *answer*: a tools/list
// response is where an upstream declares what it offers, and those declarations
// are what lets policy bind to a tool's signature rather than its display name
// (§7, internal/toolsig).
func IsToolsList(body []byte) bool {
	for _, raw := range elements(body) {
		var f frame
		if err := json.Unmarshal(raw, &f); err != nil || f.Method == nil {
			continue
		}
		if *f.Method == "tools/list" {
			return true
		}
	}
	return false
}

// ToolDeclaration is one entry of a tools/list result: what the upstream says a
// tool is called and what arguments it takes.
type ToolDeclaration struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ParseToolDeclarations reads the tools out of a tools/list response.
//
// Metadata only, and that is what keeps it inside NFR-7: a tool's name and
// argument schema are the upstream's published interface, not the payload of
// anyone's call. Nothing here is written to the ledger — the declarations feed
// policy attributes, and the record carries the derived signature rather than
// the schema.
func ParseToolDeclarations(body []byte) []ToolDeclaration {
	var out []ToolDeclaration
	for _, raw := range elements(body) {
		var resp struct {
			Result struct {
				Tools []ToolDeclaration `json:"tools"`
			} `json:"result"`
		}
		if json.Unmarshal(raw, &resp) != nil {
			continue
		}
		for _, t := range resp.Result.Tools {
			if t.Name != "" {
				out = append(out, t)
			}
		}
	}
	return out
}
