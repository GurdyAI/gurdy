// Package keyfile loads (or creates on first use) a persistent ES256 private
// key from disk. Both the deployment identity key (§5.2) and the ledger
// signing key are install-time per-deployment secrets that must survive a
// restart, so they share one loader rather than two near-identical copies.
package keyfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadOrCreate returns the P-256 key at path, generating and persisting one
// (0600) if it does not exist yet. Parent directories are created 0700 — these
// files are private keys and must never sit in an exported ledger directory.
//
// Creation is write-then-link: two processes starting against one state
// directory must converge on a single key. A plain write would let each keep
// the key it generated while the file held the other's — replicas that cannot
// verify each other, and worse for the ledger, a chain whose header pubkey
// disagrees with the signatures written under it.
//
// ponytail: no ownership/symlink/mode check on an existing key file, so a
// state directory that is already world-writable stays a way in. Add the
// checks when the install path stops being "a directory the operator chose".
func LoadOrCreate(path string) (*ecdsa.PrivateKey, error) {
	key, err := load(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	// Write to a temp file, then link it into place — not O_EXCL-create then
	// write. O_EXCL makes the *creation* atomic but says nothing about the
	// contents: it publishes an empty file at path and fills it a moment later,
	// so a caller taking the ErrExist branch in that window reads nothing or
	// half a PEM block. It surfaces as "is not PEM", which reads like a corrupt
	// key rather than a race, and the two demand opposite responses. This is
	// the recurring shape in this repo — state that outlives its own proof —
	// here as a file that exists before it means anything.
	//
	// os.Link supplies the missing half: it fails with ErrExist if the
	// destination exists, so the key becomes visible at path already complete.
	// os.Rename would not do — it clobbers, so two racers would each install
	// their own key and each return the one the other overwrote, which is the
	// precise divergence this function exists to prevent.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".key-*.tmp") // 0600 by definition
	if err != nil {
		return nil, err
	}
	// Removes the temp *name* only. After a successful Link the key has two
	// names for one inode, so this drops the spare; on any failure path it is
	// the cleanup that stops a private key littering the state directory.
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(pemBytes); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return load(path) // another caller won the race; its key is the key
		}
		// Every other Link failure is reported with what it actually means,
		// because the interesting one is a filesystem that does not support
		// hard links at all (FAT/exFAT, some FUSE and container volume
		// drivers). That surfaces as a bare EPERM/ENOTSUP on a path the
		// operator chose, and "link: operation not permitted" tells them
		// nothing about which of their choices to change.
		//
		// Deliberately *not* falling back to O_EXCL-then-write on that error.
		// The fallback would reintroduce the torn-read window on precisely the
		// filesystems nobody tests, so the rare deployment would carry the bug
		// the common one no longer has — a refusal an operator can act on beats
		// a race they will never reproduce.
		//
		// ponytail: hard links are now a requirement on the state directory.
		// If a real deployment lands on a filesystem without them, the upgrade
		// path is O_EXCL + a lockfile, not a silent fallback.
		return nil, fmt.Errorf("keyfile: cannot create %s: %w (the state directory's "+
			"filesystem must support hard links)", path, err)
	}
	return key, nil
}

func load(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err // includes fs.ErrNotExist, which LoadOrCreate acts on
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("keyfile: %s is not PEM", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
