#!/usr/bin/env bash
# Every commit in a pull request must carry a Signed-off-by matching its author
# (DCO, see ../DCO and CONTRIBUTING.md).
#
# Usage: check-dco.sh <base-ref> <head-ref>
#
# We chose a DCO over a CLA because contributed code stays in the open half and
# is never moved into the paid product. That promise runs in both directions:
# the contributor's sign-off is the only record that they had the right to
# submit the patch, so a sign-off nobody verifies is the whole agreement
# decaying into an honour system. The codebase already says a rule enforced by
# discipline decays; this is that rule applied to itself.
#
# ponytail: matches the sign-off email against the commit author's, which is the
# claim that actually matters — someone else's name on the line is not the
# author certifying. Not checked: that the email is real, or that a
# `Signed-off-by` from a third party carries a genuine DCO (c) chain of custody.
# Both need a human, and both are why maintainers read patches.
set -euo pipefail

base=${1:?usage: check-dco.sh <base-ref> <head-ref>}
head=${2:?usage: check-dco.sh <base-ref> <head-ref>}

# --no-merges: a merge commit is not a contribution, and requiring a sign-off on
# one only teaches people to pass --no-verify.
commits=$(git rev-list --no-merges "$base".."$head")

if [ -z "$commits" ]; then
  echo "OK    no non-merge commits to check"
  exit 0
fi

fail=0
n=0
for c in $commits; do
  n=$((n + 1))
  author=$(git show -s --format='%ae' "$c" | tr '[:upper:]' '[:lower:]')
  subject=$(git show -s --format='%s' "$c")
  # A commit may carry several sign-offs (DCO (c), a patch passed along). At
  # least one must be the author's.
  if git show -s --format='%B' "$c" \
     | grep -i '^Signed-off-by:' \
     | grep -qiF "<$author>"; then
    continue
  fi
  echo "FAIL  ${c:0:9}  $subject"
  echo "      no 'Signed-off-by: ... <$author>' in the commit message"
  fail=1
done

if [ $fail -ne 0 ]; then
  cat <<'EOF'

Fix with:
  git rebase --signoff <base-branch>     # sign off everything on this branch
  git commit --amend -s --no-edit        # just the tip

Then force-push. See CONTRIBUTING.md — it is a one-line certification, not a CLA.
EOF
  exit 1
fi

echo "OK    $n commit(s) signed off"
