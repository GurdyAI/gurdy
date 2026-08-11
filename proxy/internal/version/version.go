// Package version reports which build of Gurdy is running.
//
// This exists for the ledger, not for the `--version` banner. An export is
// evidence a third party is asked to trust, and "which code produced it" is
// part of what they need in order to judge it: if a defect is found in some
// released build, every export written by that build is suspect, and a reader
// holding one currently has no way to tell whether theirs is affected. The
// chain header is the right home for that fact because the header is inside the
// signature (§5.5 v0.8.5) — an attacker who can rewrite the producer string can
// already rewrite everything else, so it is as trustworthy as the rest of the
// chain, which is the standard the whole export is held to.
//
// It is also what makes the reproducibility claim usable. NFR-9 asks for
// reproducible builds, and a reader can only rebuild the verifier that produced
// a verdict if the artifact says which commit to rebuild. `Producer()` names a
// commit precisely so that instruction is executable rather than aspirational.
//
// Values are injected at link time by GoReleaser (-X). They are deliberately
// *not* read from debug.ReadBuildInfo alone: a `go build` from a tarball has no
// VCS stamps at all, so a build that fell back to build info would silently
// report an empty commit rather than an obviously-unofficial one.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Injected via -ldflags -X. The defaults are what an unofficial build reports,
// and they are deliberately conspicuous: a ledger header reading "dev" is a
// true statement about a binary somebody built themselves, and it should not be
// mistakable for a release.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// Version is the release tag, or "dev" for a local build.
func Version() string { return version }

// Commit is the full git SHA the binary was built from, or "" if unknown.
//
// Falls back to the VCS stamp Go embeds for a `go build` inside a git checkout.
// That fallback is best-effort: it is absent for a tarball build, and it says
// nothing about whether the tree was clean unless Modified reports it.
func Commit() string {
	if commit != "" {
		return commit
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return ""
}

// Modified reports whether the working tree had uncommitted changes at build
// time, per Go's VCS stamp. A modified build is not reproducible by anyone
// else, which is exactly what a reader of the ledger needs to know.
func Modified() bool {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.modified" {
				return s.Value == "true"
			}
		}
	}
	return false
}

// Producer is the string stamped into the ledger chain header.
//
// Format: `gurdy/<version>+<short-commit>` — short because it goes in every
// chain header and the full SHA buys nothing a reader cannot get by asking for
// it, `+dirty` when the tree was not clean. Kept to one line and one field so
// it stays a schema addition rather than a nested object nobody agreed to.
func Producer() string {
	s := "gurdy/" + version
	if c := Commit(); c != "" {
		n := 12
		if len(c) < n {
			n = len(c)
		}
		s += "+" + c[:n]
	}
	if Modified() {
		s += "+dirty"
	}
	return s
}

// String is the human-facing `-version` output. It names the toolchain because
// a reproduction attempt with a different Go version will not produce matching
// bytes, and that is the first thing someone gets wrong.
func String(binary string) string {
	s := fmt.Sprintf("%s %s", binary, version)
	if c := Commit(); c != "" {
		s += " (" + c
		if Modified() {
			s += ", dirty"
		}
		s += ")"
	}
	if date != "" {
		s += " built " + date
	}
	return s + fmt.Sprintf("\n%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
