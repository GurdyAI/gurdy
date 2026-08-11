package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const permitAll = "@id(\"p1\")\npermit (principal, action, resource);\n"

// writeTarball builds a .tar.gz bundle from name->content pairs.
func writeTarball(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	path := filepath.Join(t.TempDir(), "pack.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBareCedarFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.cedar")
	os.WriteFile(path, []byte(permitAll), 0o644)
	ev, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Version) != len("file:")+12 || ev.Version[:5] != "file:" {
		t.Fatalf("bare-file version shape: %q", ev.Version)
	}
}

// Same label, different content -> different bundle_ver (FR-10: a version
// string must pin content, or ledger attribution is ambiguous).
func TestVersionPinsContent(t *testing.T) {
	a := writeTarball(t, map[string]string{
		"manifest.json": `{"pack_id":"p","version":"1.0.0"}`,
		"p.cedar":       permitAll,
	})
	b := writeTarball(t, map[string]string{
		"manifest.json": `{"pack_id":"p","version":"1.0.0"}`,
		"p.cedar":       "@id(\"other\")\npermit (principal, action, resource);\n",
	})
	evA, err := Load(a)
	if err != nil {
		t.Fatal(err)
	}
	evB, err := Load(b)
	if err != nil {
		t.Fatal(err)
	}
	if evA.Version == evB.Version {
		t.Fatalf("distinct content shares bundle_ver %q", evA.Version)
	}
	if !strings.HasPrefix(evA.Version, "p@1.0.0+") {
		t.Fatalf("version shape: %q", evA.Version)
	}
}

// A small gzip that inflates past the content cap must be rejected, not OOM.
func TestDecompressionBombRejected(t *testing.T) {
	path := writeTarball(t, map[string]string{
		"manifest.json": `{"pack_id":"p","version":"1"}`,
		"bomb.cedar":    strings.Repeat("\x00", 65<<20),
	})
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("bomb accepted (err=%v)", err)
	}
}

func TestOversizeBundleFileRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.tar.gz")
	if err := os.WriteFile(path, make([]byte, 17<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversize bundle accepted (err=%v)", err)
	}
}

func TestLoadTarball(t *testing.T) {
	path := writeTarball(t, map[string]string{
		"manifest.json": `{"pack_id":"agent-security","version":"1.2.0"}`,
		"secrets.cedar": permitAll,
		"README.md":     "ignored",
	})
	ev, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ev.Version, "agent-security@1.2.0+") {
		t.Fatalf("version: %q", ev.Version)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"missing manifest":   {"p.cedar": permitAll},
		"manifest no fields": {"manifest.json": `{}`, "p.cedar": permitAll},
		"no policies":        {"manifest.json": `{"pack_id":"x","version":"1"}`},
		"bad cedar":          {"manifest.json": `{"pack_id":"x","version":"1"}`, "p.cedar": "permit(nonsense"},
	}
	for name, files := range cases {
		if _, err := Load(writeTarball(t, files)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nope.tar.gz")); err == nil {
		t.Error("missing file accepted")
	}
}
