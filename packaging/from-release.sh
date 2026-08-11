#!/usr/bin/env bash
# Rebuild a dist/ layout from the artifacts attached to a published release.
#
#   packaging/from-release.sh v0.1.0 [dest]     # default dest: ./dist
#
# The npm and PyPI packagers take binaries from `dist/`. When they run at
# release time that directory is right there from the build. When they run
# *later* — after a human has published the draft, which is when publishing to
# an irreversible registry should happen — it is not, and rebuilding would give
# npm and PyPI a binary that is merely *equivalent* to the released one rather
# than identical to it.
#
# So this fetches the published archives and verifies them against the release's
# own checksums.txt before unpacking. Same reasoning as install.sh: this project
# argues that you check artifacts instead of trusting where they came from, and
# our own pipeline is the last place that should take an unverified byte.
set -euo pipefail

TAG="${1:?usage: from-release.sh <tag> [dest]}"
DEST="${2:-dist}"
REPO="${GITHUB_REPOSITORY:-GurdyAI/gurdy}"

command -v gh >/dev/null || { echo "error: gh is required" >&2; exit 1; }

tmp=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$tmp'" EXIT INT TERM

gh release download "$TAG" --repo "$REPO" --dir "$tmp" \
  --pattern 'gurdy_*.tar.gz' --pattern 'checksums.txt'

# Verify before unpacking, never after.
(cd "$tmp" && sha256sum --check --ignore-missing checksums.txt) \
  || { echo "error: checksum verification failed for $TAG — refusing to package" >&2; exit 1; }

mkdir -p "$DEST"
found=0
for archive in "$tmp"/gurdy_*.tar.gz; do
  base=$(basename "$archive" .tar.gz)          # gurdy_0.1.0_linux_amd64
  os=$(echo "$base" | cut -d_ -f3)
  arch=$(echo "$base" | cut -d_ -f4)
  work="$tmp/x_${os}_${arch}"; mkdir -p "$work"
  tar -xzf "$archive" -C "$work"
  for b in gurdy-proxy gurdy-verify; do
    [ -f "$work/$b" ] || { echo "error: $b missing from $base" >&2; exit 1; }
    # The layout the packagers glob for: <binary>_<goos>_<goarch>*/
    d="$DEST/${b}_${os}_${arch}"
    mkdir -p "$d"
    cp "$work/$b" "$d/$b"
    chmod 0755 "$d/$b"
    found=$((found + 1))
  done
done

[ "$found" -gt 0 ] || { echo "error: no archives found for $TAG" >&2; exit 1; }
echo "laid out $found binaries under $DEST from $TAG (checksums verified)"
