#!/usr/bin/env sh
# Runs the conformance driver inside this package's environment.
#
# The suite executes a driver as a plain executable and gives it no way to say
# "but activate this virtualenv first", so the indirection lives here rather
# than in the runner: the driver contract stays "any executable", which is what
# lets a TypeScript driver plug into the identical socket.
set -e
cd "$(dirname "$0")"
exec uv run --quiet python conformance_driver.py
