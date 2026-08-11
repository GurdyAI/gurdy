package toolsig

import (
	"encoding/json"
	"slices"
	"sync"
	"testing"
)

func decl(name, schema string) Declaration {
	return Declaration{Name: name, InputSchema: json.RawMessage(schema)}
}

const pathSchema = `{"type":"object","properties":{"victim":{"type":"string","description":"absolute file path"}}}`

func TestSignatureIdentifiesTheShapeNotTheName(t *testing.T) {
	// The aliasing case, stated as an identity property: rename the tool and the
	// declared shape is unchanged, so a pack rule bound to the signature follows
	// the capability rather than the label.
	r := New()
	r.Observe("srv:1", []Declaration{decl("delete_file", pathSchema), decl("purge_file", pathSchema)})

	a, okA := r.Lookup("srv:1", "delete_file")
	b, okB := r.Lookup("srv:1", "purge_file")
	if !okA || !okB {
		t.Fatal("both declarations should be recorded")
	}
	if a.Hash == "" || a.Hash != b.Hash {
		t.Errorf("a rename changed the signature: %q vs %q", a.Hash, b.Hash)
	}
}

func TestSignatureIsStableAcrossKeyOrderAndWhitespace(t *testing.T) {
	// Content-addressed over the canonical form. Without that the hash would
	// identify a serialisation, and two servers publishing the same schema with
	// different key order would look like different tools.
	r := New()
	r.Observe("a", []Declaration{decl("t", `{"type":"object","properties":{"p":{"type":"string"}}}`)})
	r.Observe("b", []Declaration{decl("t", "{\n  \"properties\": {\"p\": {\"type\":\"string\"}},\n  \"type\": \"object\"\n}")})
	x, _ := r.Lookup("a", "t")
	y, _ := r.Lookup("b", "t")
	if x.Hash != y.Hash {
		t.Errorf("formatting changed the signature: %q vs %q", x.Hash, y.Hash)
	}
}

func TestDifferentSchemasGetDifferentSignatures(t *testing.T) {
	r := New()
	r.Observe("a", []Declaration{
		decl("t1", `{"type":"object","properties":{"p":{"type":"string"}}}`),
		decl("t2", `{"type":"object","properties":{"p":{"type":"number"}}}`)})
	x, _ := r.Lookup("a", "t1")
	y, _ := r.Lookup("a", "t2")
	if x.Hash == y.Hash {
		t.Error("two different schemas collided")
	}
}

func TestTheEndpointIsPartOfTheIdentity(t *testing.T) {
	// §7 binds to "upstream endpoint + tool signature". The same display name on
	// a different server is a different tool, and the endpoint is the half the
	// agent cannot choose — it is where the proxy forwards.
	r := New()
	r.Observe("prod", []Declaration{decl("delete_file", pathSchema)})
	if _, ok := r.Lookup("scratch", "delete_file"); ok {
		t.Error("a declaration on one endpoint answered for another")
	}
	if _, ok := r.Lookup("prod", "delete_file"); !ok {
		t.Error("the endpoint that declared it should resolve")
	}
}

func TestArgumentRolesComeFromTheDeclarationNotTheCallersNaming(t *testing.T) {
	// The half of the aliasing control that actually closes. The agent picks
	// what to call its argument; the server picks what its schema says it is.
	r := New()
	r.Observe("a", []Declaration{decl("read_file", pathSchema)})
	sig, _ := r.Lookup("a", "read_file")
	if !slices.Contains(sig.PathArgs, "victim") {
		t.Errorf("schema-declared path argument not found: %v", sig.PathArgs)
	}
}

func TestURLArgumentsAreRecognisedByFormatAndByName(t *testing.T) {
	r := New()
	r.Observe("a", []Declaration{
		decl("fetch", `{"type":"object","properties":{"loc":{"type":"string","format":"uri"}}}`),
		decl("post", `{"type":"object","properties":{"endpoint":{"type":"string"}}}`)})
	f, _ := r.Lookup("a", "fetch")
	if !slices.Contains(f.URLArgs, "loc") {
		t.Errorf("format:uri not recognised: %v", f.URLArgs)
	}
	p, _ := r.Lookup("a", "post")
	if !slices.Contains(p.URLArgs, "endpoint") {
		t.Errorf("url-ish name not recognised: %v", p.URLArgs)
	}
}

func TestAnUndeclaredToolIsReportedAsSuch(t *testing.T) {
	// Not an error — a client may call before listing, and some servers do not
	// implement tools/list. But it is a fact, and it is what a rename looks like
	// from here.
	r := New()
	r.Observe("a", []Declaration{decl("read_file", pathSchema)})
	if _, ok := r.Lookup("a", "purge_file"); ok {
		t.Error("a tool nobody declared resolved")
	}
}

func TestCaseIsNotAnIdentityDistinction(t *testing.T) {
	r := New()
	r.Observe("Srv:1", []Declaration{decl("Delete_File", pathSchema)})
	if _, ok := r.Lookup("srv:1", "delete_file"); !ok {
		t.Error("case variation defeated the lookup — the same dodge policy folding exists to stop")
	}
}

func TestAnUndecodableSchemaStillGetsADistinctSignature(t *testing.T) {
	// It must never hash equal to a schema that parsed, and it must not be
	// empty: an unparseable declaration is still a declaration, and treating it
	// as "no signature" would make it indistinguishable from an undeclared tool.
	r := New()
	r.Observe("a", []Declaration{decl("t", `{not json`), decl("u", pathSchema)})
	bad, _ := r.Lookup("a", "t")
	good, _ := r.Lookup("a", "u")
	if bad.Hash == "" || bad.Hash == good.Hash {
		t.Errorf("undecodable schema signature %q vs %q", bad.Hash, good.Hash)
	}
}

func TestTheRegistryIsBounded(t *testing.T) {
	// A hostile or broken upstream could advertise an unbounded catalogue, and a
	// monitor that exhausts memory stops governing (NFR-3). It stops recording
	// rather than evicting: eviction would let junk declarations push out real
	// ones, turning known tools into unknown ones and inverting the point.
	r := New()
	r.maxTools = 4
	many := make([]Declaration, 100)
	for i := range many {
		many[i] = decl(string(rune('a'+i%26))+string(rune('0'+i/26)), pathSchema)
	}
	r.Observe("a", many)
	if r.Len() > 4 {
		t.Errorf("registry grew to %d past its bound", r.Len())
	}
}

func TestConcurrentObserveAndLookup(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Observe("a", []Declaration{decl("t", pathSchema)})
				r.Lookup("a", "t")
			}
		}(i)
	}
	wg.Wait()
	if _, ok := r.Lookup("a", "t"); !ok {
		t.Error("declaration lost under concurrency")
	}
}
