// Package bundle loads policy bundles (§5.3): a .tar.gz containing
// manifest.json + *.cedar files, or a bare .cedar file for local authoring.
// Every bundle gets a version string and content hash recorded per decision
// (FR-10).
//
// ponytail: manifest is JSON and bundles are unsigned for now — YAML manifest,
// control_map, and ES256 pack signatures land with the pack registry, which
// owns the signer identity there is currently nothing to verify against.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/GurdyAI/gurdy/proxy/internal/policy"
)

// Manifest identifies a pack (§5.3 pack manifest, minimal cut).
type Manifest struct {
	PackID  string `json:"pack_id"`
	Version string `json:"version"`
}

const (
	maxBundleFile    = 16 << 20 // compressed / on-disk bundle cap
	maxBundleContent = 64 << 20 // total uncompressed cap (gzip-bomb guard)
)

// Load reads a bundle from path and compiles it. The version string always
// pins content — "<pack_id>@<version>+<hash12>" for tarballs, "file:<hash12>"
// for bare .cedar files — so a re-released pack with different policies can
// never share a bundle_ver with its predecessor in the ledger (FR-10).
func Load(path string) (*policy.Evaluator, error) {
	if info, err := os.Stat(path); err != nil {
		return nil, err
	} else if info.Size() > maxBundleFile {
		return nil, fmt.Errorf("bundle: %s exceeds %dMB limit", path, maxBundleFile>>20)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	hash12 := fmt.Sprintf("%x", sum[:6])
	if strings.HasSuffix(path, ".cedar") {
		return policy.Load("file:"+hash12, raw)
	}
	return loadTarball(raw, hash12)
}

// cappedReader errors (rather than EOF-ing) once n decompressed bytes have
// been read, so bomb rejection is distinguishable from a truncated tarball.
type cappedReader struct {
	r        io.Reader
	n        int64
	exceeded bool
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		c.exceeded = true
		return 0, fmt.Errorf("bundle content limit exceeded")
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	return n, err
}

func loadTarball(raw []byte, hash12 string) (*policy.Evaluator, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("bundle: not a gzip tarball: %w", err)
	}
	defer gz.Close()

	var manifest *Manifest
	policies := map[string][]byte{}
	// Meter the decompressed stream itself so tar headers and PAX/long-name
	// metadata count against the cap too, not just entry bodies.
	capped := &cappedReader{r: gz, n: maxBundleContent}
	tr := tar.NewReader(capped)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if capped.exceeded {
				return nil, fmt.Errorf("bundle: uncompressed content exceeds %dMB limit", maxBundleContent>>20)
			}
			return nil, fmt.Errorf("bundle: bad tar: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		body, err := io.ReadAll(tr)
		if err != nil {
			if capped.exceeded {
				return nil, fmt.Errorf("bundle: uncompressed content exceeds %dMB limit", maxBundleContent>>20)
			}
			return nil, err
		}
		switch {
		case name == "manifest.json":
			manifest = &Manifest{}
			if err := json.Unmarshal(body, manifest); err != nil {
				return nil, fmt.Errorf("bundle: bad manifest.json: %w", err)
			}
		case strings.HasSuffix(name, ".cedar"):
			policies[name] = body
		}
	}
	if manifest == nil || manifest.PackID == "" || manifest.Version == "" {
		return nil, fmt.Errorf("bundle: manifest.json with pack_id and version required")
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("bundle: no .cedar policies in %s", manifest.PackID)
	}
	// Deterministic concatenation so identical bundles compile identically.
	names := make([]string, 0, len(policies))
	for n := range policies {
		names = append(names, n)
	}
	sort.Strings(names)
	var src []byte
	for _, n := range names {
		src = append(src, policies[n]...)
		src = append(src, '\n')
	}
	return policy.Load(manifest.PackID+"@"+manifest.Version+"+"+hash12, src)
}
