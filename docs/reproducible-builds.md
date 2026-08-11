# Reproducible builds

**Why this page exists.** Gurdy's claim is that a third party can check an
export without trusting whoever handed it to them. They run `gurdy-verify`,
it re-walks the hash chain, and it says yes or no.

That argument has a hole in it if the verifier itself is a binary we built,
signed with our key, and asked you to trust. Then "don't trust the operator" has
quietly become "trust us instead" — the same assurance, moved one level down.

Reproducible builds close it. Every released binary can be rebuilt from source
by anyone, producing **byte-identical** output. You do not have to trust our
build; you can reconstruct it and check.

This is NFR-9, and it is the reason `.goreleaser.yaml` is fussier than a normal
release config.

## Reproducing a release

You need the exact Go toolchain — a different Go version produces a different
binary, and it is the most common reason a reproduction attempt fails.

```bash
git clone https://github.com/GurdyAI/gurdy && cd gurdy
git checkout v0.1.0                      # the tag you are checking

grep '^go ' proxy/go.mod                 # use exactly this Go version

go run github.com/goreleaser/goreleaser/v2@latest build --clean --skip=validate
sha256sum dist/gurdy-verify_linux_amd64_v1/gurdy-verify
```

Compare against the published `checksums.txt` on the release (which is itself
cosign-signed — see below). The binary inside the published archive must have
the same hash as the one you just built.

**We check this ourselves on every release.** The `verify-reproducible` job in
`.github/workflows/release.yml` rebuilds the tag on a different runner in a
different directory and fails the release if any byte differs. A reproducibility
claim that nobody re-runs is precisely the sort of unverified assurance this
product exists to argue against, so it is a gate rather than a paragraph.

## What makes it reproducible, and what breaks it

Two defaults would silently break this, and both were measured rather than
assumed:

| Input | Effect if wrong |
|---|---|
| **`-trimpath`** | Without it the absolute build directory is baked into the binary. Same source at two paths → two different hashes. |
| **`.CommitDate`, not `.Date`** | GoReleaser's stock ldflags embed the wall-clock *build time*. Two builds of the same commit differ, so nobody can reproduce either — including us. |
| **Go toolchain version** | Different Go versions emit different code. Pinned by `proxy/go.mod`. |
| **`CGO_ENABLED=0`** | A cgo build depends on the local C toolchain and headers, which are not reproducible across machines. |
| **`mod_timestamp`** | Archive member mtimes would otherwise be build time, so the `.tar.gz` differs even when the binary inside does not. |
| **Dependency versions** | Pinned by `go.sum`; `scripts/check-licenses.sh` additionally gates what may enter the build. |

### The one thing that is not reproducible from a tarball

Go stamps VCS metadata (`vcs.revision`, `vcs.time`, `vcs.modified`) into
binaries built inside a git checkout. A build from a source **tarball** has no
`.git`, so those stamps are absent and the binary differs from one built from a
clone — even at the identical commit.

So: **reproduce from a git clone at the tag, not from a downloaded tarball.**
We keep the stamps rather than disabling them with `-buildvcs=false`, because
they are real provenance: they bind the binary to a commit, which is what makes
"rebuild the verifier that produced this verdict" an executable instruction.

## Which build produced an export

Every ledger chain header records the build that wrote it, inside the signature:

```
$ gurdy-verify ./gurdy-ledger
OK  ledger/…jsonl: 3 records, 1 decisions, 1 batch signatures
    chain: tenant=local workload=stdio:cat instance=… schema=v1 key=…
    producer: gurdy/v0.1.0+9a9bb2408937
```

That is deliberate, and it is the field you want if a defect is ever found in a
released build: it tells a reader whether *their* export came from an affected
one. It is inside the signature, so forging it breaks the chain — tested by
`TestProducerIsRecordedAndSigned`.

`producer: none` means the export predates the field or was written by a build
that set none. `+dirty` means the tree had uncommitted changes at build time,
which is a build **nobody else can reproduce** — a local build, never a release.

## Verifying signatures

Releases are signed with [cosign](https://docs.sigstore.dev/) keyless signing.
There is no long-lived private key: identity comes from the GitHub Actions OIDC
token, and every signature is recorded in the public Rekor transparency log. So
a signature we did not make is publicly discoverable, rather than something we
can only deny.

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/GurdyAI/gurdy/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum -c checksums.txt --ignore-missing
```

Pin `--certificate-identity-regexp` to this repository. Without it you are
checking that *somebody* signed the file, which is not a useful statement.

## macOS and Gatekeeper

We do not notarize (no Apple Developer account). Practically:

- **`brew install gurdyai/tap/gurdy` works** — the cask's post-install hook
  clears `com.apple.quarantine`. This is the supported macOS path.
- **A binary downloaded with `curl` is quarantined.** macOS will refuse to run
  it until you clear the attribute yourself:
  `xattr -dr com.apple.quarantine ./gurdy-proxy`.

Stated here rather than left as a surprise dialog. Notarization is a seam in the
release workflow, not a rewrite, if that changes.
