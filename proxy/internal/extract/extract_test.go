package extract

import "testing"

func TestHostExtraction(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		host string
	}{
		{"full url", map[string]any{"url": "https://exfil.example/drop"}, "exfil.example"},
		{"scheme-less", map[string]any{"url": "exfil.example/drop"}, "exfil.example"},
		{"with port and userinfo", map[string]any{"url": "https://u:p@exfil.example:8443/x"}, "exfil.example"},
		{"plain path is not a host", map[string]any{"url": "/local/file"}, ""},
		{"dead url must not shadow live endpoint", map[string]any{"url": "/local", "endpoint": "https://exfil.example/drop"}, "exfil.example"},
	}
	for _, c := range cases {
		res, ok := Default.Classify(Call{Tool: "http_get", Arguments: c.args})
		if !ok {
			t.Fatalf("%s: a named tool call must always be classified", c.name)
		}
		if res.Action != "mcp/tools_call" {
			t.Errorf("%s: action %q, want mcp/tools_call", c.name, res.Action)
		}
		if res.Attrs["resource_host"] != c.host {
			t.Errorf("%s: got %q, want %q", c.name, res.Attrs["resource_host"], c.host)
		}
	}
}
