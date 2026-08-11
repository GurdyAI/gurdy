package mcp

import "testing"

func TestParseToolsCalls(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int // total calls returned
		bad  int // of which undecodable (Name == "")
	}{
		{"single", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"f","arguments":{}}}`, 1, 0},
		{"batch", `[{"method":"tools/call","params":{"name":"a"}},{"method":"tools/call","params":{"name":"b"}}]`, 2, 0},
		{"batch with non-call", `[{"method":"tools/list"},{"method":"tools/call","params":{"name":"a"}}]`, 1, 0},
		{"malformed element cannot hide the rest", `[{"method":"tools/call","params":[]},{"method":"tools/call","params":{"name":"a"}}]`, 2, 1},
		{"undecodable params surfaced", `{"method":"tools/call","params":[1,2]}`, 1, 1},
		{"missing name surfaced", `{"method":"tools/call","params":{}}`, 1, 1},
		{"not a call", `{"method":"initialize"}`, 0, 0},
		{"not json", `garbage`, 0, 0},
	}
	for _, c := range cases {
		got := ParseToolsCalls([]byte(c.body))
		bad := 0
		for _, tc := range got {
			if tc.Name == "" {
				bad++
			}
		}
		if len(got) != c.want || bad != c.bad {
			t.Errorf("%s: got %d calls (%d undecodable), want %d (%d)", c.name, len(got), bad, c.want, c.bad)
		}
	}
}
