#!/usr/bin/env bash
# Fail if anything linked into the binaries carries a licence we cannot
# redistribute under Apache-2.0 (ADR-13).
#
# This is the guard, not the headers. ADR-13 draws the grant boundary at the
# repository "rather than argued file-by-file", so per-file SPDX headers would
# be churn against the decision's own rationale — they also guard nothing. What
# can actually break the outbound grant is an *inbound* dependency: one GPL or
# SSPL module linked into gurdy-proxy and the Apache-2.0 we publish is no longer
# a licence we are in a position to offer. That regression is silent, arrives in
# a routine `go get`, and is discovered by someone else's legal review.
#
# Deliberately not `go-licenses`: it needs a Go install of a Google tool in CI
# to do what 40 lines of shell does against the module cache we already have.
#
# ponytail: matches licence *text*, not SPDX metadata. A module whose LICENSE is
# a bare URL or an unusual dual-licence header lands in UNRECOGNISED and needs a
# human — which is the correct failure direction. Switch to go-licenses or
# scancode if that list ever gets long enough to be annoying.
set -euo pipefail
cd "$(dirname "$0")/../proxy"

# Copyleft and source-available markers. Checked first, so a dual-licensed file
# that mentions both cannot pass on the permissive half alone without a human
# looking at it.
DENY='GNU GENERAL PUBLIC|GNU LESSER GENERAL|GNU AFFERO|Mozilla Public License|Common Development and Distribution|Server Side Public License|Business Source License|Commons Clause|European Union Public Licence'

# Permissive families we can redistribute under Apache-2.0.
ALLOW='Apache License|MIT License|Permission is hereby granted, free of charge|Redistribution and use in source and binary forms|Permission to use, copy, modify, and/or distribute|The Unlicense|CC0 1.0'

fail=0
unrecognised=()

# `go list -deps` is the set actually linked, which is the set that matters.
# `go list -m all` would also drag in test-only and indirect modules that never
# reach a shipped binary, and failing the build over those would be wrong.
mods=$(go list -deps -f '{{if not .Standard}}{{.Module.Path}}{{end}}' ./... | sort -u | grep -v '^$' | grep -v '^github.com/GurdyAI/')

for m in $mods; do
  dir=$(go list -m -f '{{.Dir}}' "$m" 2>/dev/null || true)
  if [ -z "$dir" ] || [ ! -d "$dir" ]; then
    echo "FAIL  $m — module not in the local cache; run 'go mod download'"
    fail=1; continue
  fi
  lf=$(find "$dir" -maxdepth 1 -iname 'LICENSE*' -o -maxdepth 1 -iname 'COPYING*' | head -1)
  if [ -z "$lf" ]; then
    echo "FAIL  $m — no licence file; cannot confirm we may redistribute it"
    fail=1; continue
  fi
  if grep -qE "$DENY" "$lf"; then
    echo "FAIL  $m — copyleft or source-available licence: $lf"
    fail=1; continue
  fi
  if ! grep -qE "$ALLOW" "$lf"; then
    unrecognised+=("$m ($lf)")
    continue
  fi
done

if [ ${#unrecognised[@]} -gt 0 ]; then
  echo "FAIL  licence text not recognised — a human must read these:"
  printf '        %s\n' "${unrecognised[@]}"
  fail=1
fi

[ $fail -eq 0 ] && echo "OK    $(echo "$mods" | wc -l | tr -d ' ') linked modules, all Apache-2.0-redistributable"
exit $fail
