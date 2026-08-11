// Resolve the platform-specific binary and hand the process over to it.
//
// The esbuild/ruff pattern: `@gurdy/cli` carries no binaries, and declares an
// optionalDependency on one `@gurdy/cli-<os>-<arch>` package per platform. Each
// of those sets `os`/`cpu`, so npm installs exactly the one that matches and
// skips the rest — the user downloads one binary, not four.
//
// Why a JS shim rather than letting the platform package declare `bin`:
// npm's linking of binaries from *optional* dependencies is not dependable
// across npm/pnpm/yarn versions, and the failure mode is a missing command with
// no explanation. Resolving here means a missing platform package produces a
// sentence telling the user what happened.
"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// Node's arch/platform names are not Go's, and the archives are named with Go's.
const PLATFORMS = {
  "darwin arm64": "darwin-arm64",
  "darwin x64": "darwin-amd64",
  "linux arm64": "linux-arm64",
  "linux x64": "linux-amd64",
};

function binaryPath(name) {
  const key = `${process.platform} ${process.arch}`;
  const slug = PLATFORMS[key];
  if (!slug) {
    throw new Error(
      `gurdy: unsupported platform ${key}.\n` +
        `Supported: ${Object.keys(PLATFORMS).join(", ")}.\n` +
        `Windows is Phase 2; WSL2 works today. Build from source: https://github.com/GurdyAI/gurdy`
    );
  }
  const pkg = `@gurdy/cli-${slug}`;
  let dir = null;
  try {
    // Resolve the package's own manifest — resolving the bare package name
    // would need a main entry, and these packages deliberately ship nothing but
    // binaries.
    dir = path.dirname(require.resolve(`${pkg}/package.json`));
  } catch {
    // require.resolve walks up from this file's *real* path, so when the
    // wrapper is a symlink to a source checkout (`npm install ./dir`, `npm
    // link`) the walk starts in the checkout, which has no node_modules, and
    // reports "not installed" for a package sitting right there in the
    // consumer's tree. Retry the walk from the working directory and from the
    // invoked script's location, which are inside that tree.
    //
    // Found by hitting it in testing. The first fix attempted was a list of
    // guessed sibling directories, which was wrong for the very layout that
    // produced the bug — `paths:` re-runs the real resolution algorithm instead
    // of imitating it.
    const from = [process.cwd()];
    if (process.argv[1]) from.push(path.dirname(fs.realpathSync(process.argv[1])));
    try {
      dir = path.dirname(require.resolve(`${pkg}/package.json`, { paths: from }));
    } catch {
      /* fall through to the error below */
    }
  }
  if (!dir) {
    throw new Error(
      `gurdy: the platform package ${pkg} is not installed.\n` +
        `This usually means the install ran with --no-optional, or npm skipped\n` +
        `optional dependencies. Reinstall with:  npm install -g @gurdy/cli`
    );
  }
  const bin = path.join(dir, "bin", name);
  if (!fs.existsSync(bin)) {
    throw new Error(`gurdy: ${pkg} is installed but ${name} is missing from it.`);
  }
  return bin;
}

function run(name) {
  let bin;
  try {
    bin = binaryPath(name);
  } catch (err) {
    process.stderr.write(String(err.message) + "\n");
    process.exit(1);
  }
  // stdio: "inherit" is load-bearing for the stdio shim. gurdy-proxy -stdio
  // relays an MCP protocol stream on stdout byte-for-byte; piping it through
  // Node would risk re-encoding or re-chunking the very bytes this project
  // promises not to touch.
  const res = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
  if (res.error) {
    process.stderr.write(`gurdy: failed to execute ${bin}: ${res.error.message}\n`);
    process.exit(1);
  }
  // Propagate a signal death as a shell does (128 + signum) rather than
  // reporting success: a proxy killed mid-run has not exited cleanly, and the
  // ledger's shutdown record will be absent to prove it.
  if (res.signal) process.exit(128 + (require("os").constants.signals[res.signal] || 0));
  process.exit(res.status === null ? 1 : res.status);
}

module.exports = { run, binaryPath, PLATFORMS };
