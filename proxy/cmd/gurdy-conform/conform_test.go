package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The suite is only a parity mechanism if it actually runs in CI — a corpus
// nobody executes is documentation with a .json extension. This builds the
// proxy and drives every case with the reference driver.
func TestConformanceSuitePassesWithReferenceDriver(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the proxy binary")
	}
	dir, err := os.MkdirTemp("", "gc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	proxyBin := filepath.Join(dir, "gurdy-proxy")
	if out, err := exec.Command("go", "build", "-o", proxyBin, "../gurdy-proxy").CombinedOutput(); err != nil {
		t.Fatalf("build proxy: %v\n%s", err, out)
	}

	cases, err := filepath.Abs("../../../conformance/cases")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cases); err != nil {
		t.Fatalf("case corpus missing at %s: %v", cases, err)
	}

	out, err := exec.Command("go", "run", ".", "-cases", cases, "-proxy", proxyBin).CombinedOutput()
	if err != nil {
		t.Fatalf("conformance suite failed:\n%s", out)
	}
	if !strings.Contains(string(out), "0 failed") {
		t.Fatalf("unexpected suite output:\n%s", out)
	}
	// A corpus that silently shrinks to nothing would also report "0 failed".
	if strings.Contains(string(out), "\n0 cases") {
		t.Fatalf("no cases ran:\n%s", out)
	}
	t.Logf("%s", out)
}
