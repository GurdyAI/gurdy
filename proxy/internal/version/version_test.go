package version

import (
	"runtime"
	"strings"
	"testing"
)

// Producer() is written into every ledger chain header, inside the signature.
// A reader uses it to decide whether their export came from a build with a
// known defect, so its failure mode matters: it must never be empty, never
// silently drop the commit, and never call a dirty build clean.
func TestProducer(t *testing.T) {
	saved := [3]string{version, commit, date}
	t.Cleanup(func() { version, commit, date = saved[0], saved[1], saved[2] })

	cases := []struct {
		name          string
		version       string
		commit        string
		wantContains  []string
		wantNotSuffix string
	}{
		{
			name:         "release build",
			version:      "v1.2.3",
			commit:       "9a9bb2408937faffd15fd8e1e86ad84ff2b52665",
			wantContains: []string{"gurdy/v1.2.3", "9a9bb2408937"},
		},
		{
			// The default. A ledger header reading "dev" is a true statement
			// about a binary somebody built themselves, and it must not be
			// mistakable for a release.
			name:         "unofficial build",
			version:      "dev",
			commit:       "",
			wantContains: []string{"gurdy/dev"},
		},
		{
			// A short commit must not be sliced out of range.
			name:         "short commit",
			version:      "v0.1.0",
			commit:       "abc",
			wantContains: []string{"gurdy/v0.1.0", "abc"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version, commit = tc.version, tc.commit
			got := Producer()
			if got == "" {
				t.Fatal("Producer() is empty — the header would claim nothing")
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("Producer() = %q, missing %q", got, want)
				}
			}
		})
	}
}

func TestProducerTruncatesCommitButKeepsItIdentifying(t *testing.T) {
	saved := [2]string{version, commit}
	t.Cleanup(func() { version, commit = saved[0], saved[1] })
	version, commit = "v1.0.0", "0123456789abcdef0123456789abcdef01234567"

	got := Producer()
	if strings.Contains(got, commit) {
		t.Errorf("Producer() carries the full 40-char SHA (%q) — it goes in every chain header", got)
	}
	if !strings.Contains(got, "0123456789ab") {
		t.Errorf("Producer() = %q, expected the 12-char short commit", got)
	}
}

func TestCommitPrefersTheLinkedValue(t *testing.T) {
	// Deliberately not read from debug.ReadBuildInfo alone: a `go build` from a
	// tarball has no VCS stamps, so a build that fell back to build info would
	// report an empty commit rather than an obviously-unofficial one.
	saved := commit
	t.Cleanup(func() { commit = saved })
	commit = "deadbeefcafe1234"
	if Commit() != "deadbeefcafe1234" {
		t.Errorf("Commit() = %q, want the linker-injected value", Commit())
	}
}

func TestStringNamesTheToolchain(t *testing.T) {
	// A reproduction attempt with a different Go version will not produce
	// matching bytes, and that is the first thing people get wrong — so
	// -version has to say which toolchain built this.
	got := String("gurdy-verify")
	for _, want := range []string{"gurdy-verify", runtime.Version(), runtime.GOOS, runtime.GOARCH} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}

func TestStringCarriesTheBuildDateWhenSet(t *testing.T) {
	saved := date
	t.Cleanup(func() { date = saved })
	date = "2026-07-27T00:00:00Z"
	if !strings.Contains(String("gurdy-proxy"), date) {
		t.Errorf("String() dropped the build date")
	}
	date = ""
	if strings.Contains(String("gurdy-proxy"), "built ") {
		t.Errorf("String() invented a build date when none was linked in")
	}
}

func TestVersionReportsTheLinkedValue(t *testing.T) {
	saved := version
	t.Cleanup(func() { version = saved })
	version = "v9.9.9"
	if Version() != "v9.9.9" {
		t.Errorf("Version() = %q, want v9.9.9", Version())
	}
}

func TestStringIdentifiesTheCommitItCanBeRebuiltFrom(t *testing.T) {
	// docs/reproducible-builds.md tells a reader to check out the commit this
	// binary names and rebuild it. That instruction is only executable if
	// -version actually prints the commit.
	saved := commit
	t.Cleanup(func() { commit = saved })
	commit = "0123456789abcdef"

	got := String("gurdy-proxy")
	if !strings.Contains(got, "0123456789abcdef") {
		t.Errorf("String() = %q — a reader cannot tell which commit to rebuild", got)
	}
	if !strings.Contains(got, "(") {
		t.Errorf("String() = %q, expected the commit in parentheses", got)
	}
}

func TestProducerMarksADirtyTreeWhenTheBuildWasDirty(t *testing.T) {
	// A dirty build is one nobody else can reproduce, which is exactly what a
	// reader of the ledger needs to know. Modified() reads Go's VCS stamp, so
	// this asserts the two agree rather than forcing a value the test cannot
	// control.
	saved := [2]string{version, commit}
	t.Cleanup(func() { version, commit = saved[0], saved[1] })
	version, commit = "v1.0.0", "abcdef123456"

	got := Producer()
	if Modified() != strings.Contains(got, "+dirty") {
		t.Errorf("Producer() = %q but Modified() = %v — the marker disagrees with the build",
			got, Modified())
	}
}
