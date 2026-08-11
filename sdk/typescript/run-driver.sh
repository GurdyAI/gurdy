#!/usr/bin/env sh
# Runs the conformance driver from the compiled output.
#
# The suite executes a driver as a plain executable and gives it no way to say
# "build first", so the indirection lives here rather than in the runner: the
# driver contract stays "any executable", which is what lets the Python driver
# plug into the identical socket.
#
# Deliberately does NOT build. A build triggered per case would run twelve times
# and could race itself; a missing build should say so once, clearly.
set -e
cd "$(dirname "$0")"
if [ ! -f dist/conformance-driver.js ]; then
  echo "not built — run: (cd sdk/typescript && npm install && npm run build)" >&2
  exit 1
fi
exec node dist/conformance-driver.js
