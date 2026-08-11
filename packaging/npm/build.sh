#!/usr/bin/env bash
# Build the npm packages from GoReleaser's dist/ output.
#
#   packaging/npm/build.sh <version>          # build into packaging/npm/out
#   NPM_PUBLISH=1 packaging/npm/build.sh 0.1.0 --otp=123456   # and publish
#
# Layout (the esbuild pattern):
#   @gurdy/cli                 wrapper, no binaries, optionalDependencies on ↓
#   @gurdy/cli-darwin-arm64    one binary pair each, gated by os/cpu
#   @gurdy/cli-darwin-amd64
#   @gurdy/cli-linux-amd64
#   @gurdy/cli-linux-arm64
#
# Publish order matters and is not cosmetic: the platform packages go first. If
# the wrapper were published first, an install in the gap between the two would
# resolve optionalDependencies that do not exist yet, silently succeed (they are
# *optional*), and leave the user with a command that cannot find its binary.
set -euo pipefail

VERSION="${1:?usage: build.sh <version> [npm publish args...]}"
VERSION="${VERSION#v}"
shift || true

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
dist="$root/dist"
# OUT_DIR lets a test build land outside the repo. Default is beside this
# script; it is gitignored, because it holds ~70MB of binaries.
out="${OUT_DIR:-$here/out}"

[ -d "$dist" ] || { echo "error: $dist not found — run 'goreleaser build --snapshot --clean' first" >&2; exit 1; }

# Tolerate an undeletable leftover (npm-created files can resist removal in
# some sandboxes) rather than aborting the whole build under `set -e`.
rm -rf "$out" 2>/dev/null || true
mkdir -p "$out"

# Go's naming on the left (what GoReleaser writes), npm's on the right.
# GoReleaser suffixes some targets with a microarchitecture level (amd64_v1,
# arm64_v8.0); matched by glob so a GoReleaser default change does not silently
# produce an empty package.
PLATFORMS="darwin-arm64:darwin:arm64 darwin-amd64:darwin:x64 linux-amd64:linux:x64 linux-arm64:linux:arm64"

optional_deps=""
for entry in $PLATFORMS; do
  slug=${entry%%:*}; rest=${entry#*:}; nodeos=${rest%%:*}; nodecpu=${rest##*:}
  goos=${slug%%-*}; goarch=${slug##*-}

  pkgdir="$out/cli-$slug"
  mkdir -p "$pkgdir/bin"

  for b in gurdy-proxy gurdy-verify; do
    src=$(find "$dist" -type d -name "${b}_${goos}_${goarch}*" -print -quit)
    [ -n "$src" ] || { echo "error: no dist dir for ${b} ${goos}/${goarch}" >&2; exit 1; }
    cp "$src/$b" "$pkgdir/bin/$b"
    chmod 0755 "$pkgdir/bin/$b"
  done

  cat > "$pkgdir/package.json" <<EOF
{
  "name": "@gurdy/cli-$slug",
  "version": "$VERSION",
  "description": "gurdy binaries for $nodeos $nodecpu. Installed automatically by @gurdy/cli — do not depend on this directly.",
  "license": "Apache-2.0",
  "repository": { "type": "git", "url": "git+https://github.com/GurdyAI/gurdy.git" },
  "os": ["$nodeos"],
  "cpu": ["$nodecpu"],
  "files": ["bin"],
  "preferUnplugged": true
}
EOF
  cp "$root/LICENSE" "$root/NOTICE" "$pkgdir/"
  optional_deps="$optional_deps    \"@gurdy/cli-$slug\": \"$VERSION\",\n"
done

# --- the wrapper ---
wrap="$out/cli"
mkdir -p "$wrap/bin"
cp "$here/bin/shared.js" "$here/bin/gurdy-proxy.js" "$here/bin/gurdy-verify.js" "$wrap/bin/"
cp "$root/LICENSE" "$root/NOTICE" "$wrap/"
cp "$here/README.md" "$wrap/README.md" 2>/dev/null || true

cat > "$wrap/package.json" <<EOF
{
  "name": "@gurdy/cli",
  "version": "$VERSION",
  "description": "A flight recorder for AI agents — governs agent tool calls and writes a verifiable decision ledger",
  "license": "Apache-2.0",
  "repository": { "type": "git", "url": "git+https://github.com/GurdyAI/gurdy.git" },
  "homepage": "https://github.com/GurdyAI/gurdy",
  "keywords": ["mcp", "ai-agents", "governance", "audit", "security"],
  "bin": {
    "gurdy-proxy": "bin/gurdy-proxy.js",
    "gurdy-verify": "bin/gurdy-verify.js"
  },
  "files": ["bin", "LICENSE", "NOTICE", "README.md"],
  "engines": { "node": ">=18" },
  "optionalDependencies": {
$(printf "%b" "$optional_deps" | sed '$ s/,$//')
  }
}
EOF

echo "built into $out:"
for d in "$out"/*/; do
  printf '  %-28s %s\n' "$(basename "$d")" "$(du -sh "$d" | cut -f1)"
done

if [ "${NPM_PUBLISH:-}" = "1" ]; then
  echo
  echo "publishing platform packages first (see the note at the top of this file)..."
  for d in "$out"/cli-*/; do
    (cd "$d" && npm publish --access public "$@")
  done
  echo "publishing the wrapper..."
  (cd "$wrap" && npm publish --access public "$@")
fi
