package extract

import (
	"net/url"
	"strings"
)

// toolExtractor handles MCP tool calls: the filesystem and host attributes a
// tool's arguments carry. It is the general case and therefore last in the
// registry — it claims any call that names a tool.
type toolExtractor struct{}

func (toolExtractor) Name() string { return "mcp-tool" }

// pathKeys and urlKeys are the argument names common MCP tools use.
// ponytail: flat key match, no schema introspection; extend per OQ #1 against
// real agent traffic at the wk-5 checkpoint.
var (
	pathKeys = []string{"path", "file_path", "filepath", "filename", "target", "directory"}
	urlKeys  = []string{"url", "uri", "endpoint"}
)

func (toolExtractor) Extract(c Call) (Result, bool) {
	if c.Tool == "" {
		return Result{}, false
	}
	res := Result{Action: "mcp/tools_call", Tool: c.Tool, Attrs: map[string]string{}}

	// What the upstream declared about this tool. Recorded whether or not the
	// schema helps, because "this endpoint never declared this tool" is the
	// fact a renamed tool produces, and a pack needs to be able to see it
	// (§7: bind to endpoint + signature, not display name).
	if c.Signature != nil {
		res.Attrs["tool_declared"] = "true"
		if c.Signature.Hash != "" {
			res.Attrs["tool_signature"] = c.Signature.Hash
		}
	} else {
		res.Attrs["tool_declared"] = "false"
	}
	if c.Host != "" {
		res.Attrs["tool_endpoint"] = c.Host
	}

	// Argument roles from the declaration, before the name guesses below. This
	// is the half of the aliasing control that actually closes: the agent picks
	// what to call its arguments, the server picks what its schema says they
	// are, and only one of those is trustworthy.
	if c.Signature != nil {
		for _, k := range c.Signature.PathArgs {
			if v, ok := c.Arguments[k].(string); ok && v != "" {
				res.Attrs["resource_path"] = v
				res.Resource = v
				break
			}
		}
		for _, k := range c.Signature.URLArgs {
			if v, ok := c.Arguments[k].(string); ok && v != "" {
				if host := hostOf(v); host != "" {
					res.Attrs["resource_host"] = host
					if res.Resource == "" {
						res.Resource = v
					}
					break
				}
			}
		}
	}

	for _, k := range pathKeys {
		if _, done := res.Attrs["resource_path"]; done {
			break
		}
		if v, ok := c.Arguments[k].(string); ok && v != "" {
			res.Attrs["resource_path"] = v
			res.Resource = v
			break
		}
	}
	for _, k := range urlKeys {
		if _, done := res.Attrs["resource_host"]; done {
			break
		}
		v, ok := c.Arguments[k].(string)
		if !ok || v == "" {
			continue
		}
		if host := hostOf(v); host != "" {
			res.Attrs["resource_host"] = host
			if res.Resource == "" {
				res.Resource = v
			}
			break
		}
		// unparseable value: keep trying the remaining keys — a dead "url"
		// arg must not shadow a live "endpoint" arg
	}
	return res, true
}

// hostOf extracts the host from full URLs and scheme-less forms like
// "exfil.example/drop" — a bare endpoint string must not silently evade
// host-based policies. Plain paths ("/local") yield "".
func hostOf(v string) string {
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if strings.HasPrefix(v, "/") {
		return ""
	}
	if u, err := url.Parse("//" + v); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return ""
}
