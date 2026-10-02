#!/usr/bin/env bash
# The secret-scan target: exits 0 only if both scans are clean.
#  1. history  — every commit reachable from any ref (a secret that ever landed is a finding forever)
#  2. worktree — every tracked or untracked-but-not-ignored file as it is on disk now (catches
#     uncommitted edits). Gitignored files (lab/.lab.env, .env*) are deliberately out of scope: they
#     are where secrets are allowed to live and git never sees them.
# Usage: tools/secrets/scan.sh [--history-only|--tree-only]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(git rev-parse --show-toplevel)
cd "$root"
mode=${1:-all}
gl() { "$here/gitleaks.sh" "$@" --config "$root/.gitleaks.toml" --redact --no-banner; }
rc=0

if [ "$mode" != "--tree-only" ]; then
  echo ">> history scan"
  gl git "$root" || rc=1
fi
if [ "$mode" != "--history-only" ]; then
  echo ">> worktree scan (tracked + untracked, gitignored excluded)"
  snap=$(mktemp -d); trap 'rm -rf "$snap"' EXIT
  git ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' f; do
    [ -f "$f" ] || continue
    mkdir -p "$snap/$(dirname "$f")"; cp -p "$f" "$snap/$f"
  done
  # snapshot paths are relative to the root, so path allowlists match exactly as they do in git
  ( cd "$snap" && "$here/gitleaks.sh" dir . --config "$root/.gitleaks.toml" --redact --no-banner ) || rc=1
fi
[ "$rc" -eq 0 ] && echo "secret scan clean" || echo "SECRET SCAN FAILED" >&2
exit "$rc"
