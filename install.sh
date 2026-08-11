#!/usr/bin/env sh
# Install gurdy-proxy and gurdy-verify.
#
#   curl -fsSL https://raw.githubusercontent.com/GurdyAI/gurdy/main/install.sh | sh
#
# It verifies the SHA-256 of what it downloaded before installing anything, and
# it verifies the cosign signature too when cosign is present. That is not
# ceremony: this tool's whole argument is that you should check evidence instead
# of trusting its source, and an installer for it that piped an unverified
# binary to your PATH would be the loudest possible counter-example.
#
# On macOS, prefer `brew install gurdyai/tap/gurdy` — see the Gatekeeper note at
# the end of this script.
set -eu

REPO="GurdyAI/gurdy"
BIN_DIR="${GURDY_BIN_DIR:-/usr/local/bin}"
VERSION="${GURDY_VERSION:-latest}"

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need curl
need tar

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os" in
  linux|darwin) ;;
  *) die "unsupported OS '$os'. Windows is Phase 2; WSL2 works today." ;;
esac
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture '$arch'" ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$VERSION" ] || die "could not determine the latest release — is one published yet?"
fi
num=${VERSION#v}

archive="gurdy_${num}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"
tmp=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$tmp'" EXIT INT TERM

say "gurdy $VERSION  ($os/$arch)"
curl -fsSL -o "$tmp/$archive"       "$base/$archive"      || die "download failed: $base/$archive"
curl -fsSL -o "$tmp/checksums.txt"  "$base/checksums.txt" || die "could not fetch checksums.txt"

# --- verify before unpacking, always ---------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  sum=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  sum=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
else
  die "no sha256sum or shasum available; refusing to install unverified binaries"
fi
want=$(grep " \{1,2\}$archive\$" "$tmp/checksums.txt" | cut -d' ' -f1)
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
[ "$sum" = "$want" ] || die "checksum mismatch for $archive
  expected $want
  got      $sum
Do not use this download."
say "  checksum OK"

# Signature check when cosign is available. Not required — most people will not
# have cosign — but when it is here, use it: it proves the checksums file came
# from this repository's release workflow rather than merely matching itself.
if command -v cosign >/dev/null 2>&1; then
  if curl -fsSL -o "$tmp/checksums.txt.sig" "$base/checksums.txt.sig" 2>/dev/null &&
     curl -fsSL -o "$tmp/checksums.txt.pem" "$base/checksums.txt.pem" 2>/dev/null; then
    if cosign verify-blob \
        --certificate "$tmp/checksums.txt.pem" \
        --signature "$tmp/checksums.txt.sig" \
        --certificate-identity-regexp "https://github.com/$REPO/.*" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$tmp/checksums.txt" >/dev/null 2>&1; then
      say "  cosign signature OK"
    else
      die "cosign signature verification FAILED — do not use this download"
    fi
  fi
else
  # Be precise about what was and was not established. The archive and
  # checksums.txt come from the same host, so a matching checksum shows the
  # download was not corrupted in transit — it does NOT show the artifact is
  # the one we built, because anyone able to replace the archive could replace
  # the checksum alongside it. Only the signature establishes origin.
  say "  note: checksum verified (integrity), but NOT origin — the checksum file"
  say "        comes from the same place as the archive. Install cosign and re-run"
  say "        to verify this was built by the GurdyAI release workflow."
fi

tar -xzf "$tmp/$archive" -C "$tmp"

install_one() {
  if [ -w "$BIN_DIR" ]; then
    install -m 0755 "$tmp/$1" "$BIN_DIR/$1"
  elif command -v sudo >/dev/null 2>&1; then
    sudo install -m 0755 "$tmp/$1" "$BIN_DIR/$1"
  else
    die "$BIN_DIR is not writable and sudo is unavailable. Set GURDY_BIN_DIR to a directory you own."
  fi
}
install_one gurdy-proxy
install_one gurdy-verify

# macOS quarantines anything downloaded by curl, and we do not notarize (no
# Apple Developer account). Clear it here rather than letting the user meet a
# "the developer cannot be verified" dialog on a security tool.
if [ "$os" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
  xattr -dr com.apple.quarantine "$BIN_DIR/gurdy-proxy" "$BIN_DIR/gurdy-verify" 2>/dev/null || true
fi

say ""
say "installed to $BIN_DIR:"
say "  gurdy-proxy   $("$BIN_DIR/gurdy-proxy" -version 2>/dev/null | head -1)"
say "  gurdy-verify  $("$BIN_DIR/gurdy-verify" -version 2>/dev/null | head -1)"
say ""
say "Next: govern something in one command —"
say "  echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/home/me/.ssh/id_rsa\"}}}' \\"
say "    | gurdy-proxy -stdio -ledger-dir ./ledger -state-dir ./state -- cat"
say "  gurdy-verify ./ledger"
