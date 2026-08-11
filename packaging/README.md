# Packaging

Four channels, one set of binaries. Everything here **repackages** what
GoReleaser built — nothing rebuilds. That is deliberate: if npm compiled its own
copy, the binary a user installs would not be the one the release signed, the
one `checksums.txt` covers, or the one the reproducibility job checked.

| Channel | Command | Built by |
|---|---|---|
| GitHub release | `curl … install.sh \| sh` | `.goreleaser.yaml` |
| Homebrew | `brew install gurdyai/tap/gurdy` | `.goreleaser.yaml` (`homebrew_casks`) |
| npm | `npm i -g @gurdy/cli` | `packaging/npm/build.sh` |
| PyPI | `pipx install gurdy` | `packaging/pypi/build_wheels.py` |

```bash
cd proxy && goreleaser build --snapshot --clean   # produces dist/
packaging/npm/build.sh 0.1.0                      # -> packaging/npm/out
python3 packaging/pypi/build_wheels.py 0.1.0      # -> packaging/pypi/out
```

Both output directories are gitignored — they hold ~70 MB of binaries.

## npm — `@gurdy/cli`

The esbuild pattern. The wrapper carries no binaries and declares an
`optionalDependency` on one `@gurdy/cli-<os>-<arch>` package per platform, each
gated by `os`/`cpu`, so npm installs exactly the matching one.

**Publish order is load-bearing**: platform packages first, wrapper last. Publish
the wrapper first and an install landing in the gap resolves optional
dependencies that do not exist yet, *succeeds* (they are optional), and leaves
the user a command that cannot find its binary.

### The publish is not atomic, and npm offers no way to make it one

Six packages go out across two steps and a loop. A failure partway — a 409, a
network blip, a provenance rejection — leaves some of them live at the new
version and the rest missing, with those version numbers burned. Ordering
protects the *install* (a wrapper never resolves against absent platform
packages) but nothing protects the *release*.

Three things narrow it, none of them close it. `npm test` for the SDK runs
**before** anything publishes, so the likeliest failure aborts while the
registry is still untouched. Platform packages precede the wrapper, so the
partial state a mid-loop failure leaves is the harmless direction. And the SDK
publishes last, so a failure there cannot strand the ordering-sensitive
sequence.

The mechanism that would actually make it atomic is **staged publishing**: stage
all six, promote together. That is a second, independent argument for the
stage-only trusted-publisher posture we deferred on security grounds — and it
turns an open question into one worth answering, since promotion has to be
atomic *across packages* for this to buy anything. Until then, recovery from a
partial publish is manual: bump the patch version and re-release. Do not attempt
to re-publish a burned version.

The JS shim resolves the platform package and `exec`s the binary with
`stdio: "inherit"` — that matters for `-stdio` mode, where the proxy relays an
MCP stream byte-for-byte and piping it through Node could re-chunk the very
bytes this project promises not to touch. Tested across four install shapes:
registry tarballs, symlinked local dirs, global install, and platform package
absent (which must exit 1 with a sentence, not a stack trace).

## PyPI — `gurdy`

**One package, two jobs**, because §3.3 says the wheel bundles the Go core
("ruff/esbuild pattern"):

- `pipx install gurdy` → `gurdy-proxy` / `gurdy-verify` on PATH (§5.8)
- `pip install gurdy` → `import gurdy` *plus* the bundled core for dev mode (§5.9)

Binaries ride in `gurdy-<ver>.data/scripts/`, which pip installs into the
environment's `bin/` and marks executable — the same mechanism ruff and maturin
use. No `console_scripts` shim: an entry point must be a Python callable, and
wrapping a binary in a Python process would put interpreter startup in front of
every proxy invocation.

**A pure-Python `py3-none-any` wheel is published too**, and it is not a
leftover. The SDK gets installed into someone else's agent process and must not
be why that install fails. On a platform we ship no binary for, pip falls back to
the pure wheel: `import gurdy` works, enrichment against a remote proxy works,
and only the bundled dev-mode core is missing. That is the SDK's standing rule —
degrade, never break — applied to packaging.

The wheel builder has no build dependencies. A wheel is a zip with three
metadata files, and pulling in `build`/`hatchling` to emit one would be more
moving parts than the format has. Output is byte-deterministic (fixed member
timestamps), so wheels inherit the reproducibility of the binaries inside them.

> `sdk/python/pyproject.toml` is for development only. `uv build` there produces
> a pure wheel with no core — installable, importable, and missing the half that
> dev mode needs.

## When each channel publishes

Tagging `v*` builds, signs and creates a **draft** GitHub release, then proves it
is reproducible. Nothing reaches a registry yet.

npm and PyPI publish only when a human **publishes that draft**. The draft exists
so someone reads the notes before anyone can install, and gating only the GitHub
release had that exactly backwards — a draft release can be deleted without
trace, npm can be unpublished for 72 hours under restrictions, and **a PyPI
version number is burned permanently the moment it is uploaded**. The reversible
channel had the gate; the irreversible ones did not.

It is an event gate (`release: published`) rather than an environment protection
rule, because the latter is a repo setting somebody has to remember to configure
— and a rule enforced by discipline decays.

At that point `packaging/from-release.sh` fetches the archives **attached to the
release**, verifies them against its `checksums.txt`, and lays them out for the
two packagers. Not a rebuild: a rebuild would be *equivalent* to what was signed,
and these are *identical* to it.

## Credentials

| Secret | Needed by | Notes |
|---|---|---|
| `HOMEBREW_TAP_TOKEN` | Homebrew cask | Write access to `GurdyAI/homebrew-tap`, which `GITHUB_TOKEN` cannot grant. The tap repo must exist first. |
| *(none)* | npm | **Trusted Publishing** — all six `@gurdy` packages trust `GurdyAI/gurdy` + workflow `release.yml`, no environment. Needs npm >= 11.5.1 and Node >= 22.14.0, hence Node 24 plus an explicit npm upgrade in the job. |
| *(none)* | PyPI | **Trusted Publishing** — PyPI verifies this workflow's GitHub OIDC identity instead of a token. Configure once at `pypi.org/manage/project/gurdy/settings/publishing/`. |

Neither registry needs a secret, which is worth preferring for the same reason
cosign keyless signing is: there is no long-lived credential to leak, rotate, or
be compelled to hand over. `HOMEBREW_TAP_TOKEN` is now the only long-lived
credential in the release path, and only because a git push to another repo has
no OIDC equivalent.

**npm cannot do a first-ever publish over OIDC** ([npm/cli#8544](https://github.com/npm/cli/issues/8544)) —
a trusted publisher can only be configured on a package that already exists. All
six were brought into existence as `0.0.0` stubs under the **`placeholder`
dist-tag, deliberately not `latest`**: a stub on `latest` means `npm i -g
@gurdy/cli` installs a do-nothing package and reports no error, whereas with no
`latest` tag the same command fails with "no matching version", which is the
truthful answer for something that has not shipped. The first real release
publishes to `latest` and takes over.

`--provenance` is passed explicitly even though npm's docs say trusted publishing
generates provenance automatically, because publishes have been reported to fail
without it. It is a no-op if the docs are right and load-bearing if they are not.

## macOS

We do not notarize (no Apple Developer account). `brew` is the supported macOS
path — the cask's post-install hook clears `com.apple.quarantine`, which
**formulae get for free and casks do not**. `install.sh` clears it too. A binary
pulled straight from a release archive by hand needs
`xattr -dr com.apple.quarantine` first.
