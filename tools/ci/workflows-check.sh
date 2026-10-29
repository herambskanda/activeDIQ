#!/usr/bin/env bash
# T-0261: the workflow files may not weaken a gate or leave an action unpinned.
#   - no `continue-on-error`
#   - every `uses:` is pinned to a 40-hex commit SHA
#   - release.yml verifies the signatures it makes before publishing
# Usage: workflows-check.sh [dir]   (default .github/workflows)
set -uo pipefail
dir=${1:-.github/workflows}
bad=0
shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)
if [ ${#files[@]} -eq 0 ]; then echo "workflows-check: no workflow files in $dir" >&2; exit 1; fi
for f in "${files[@]}"; do
  if grep -nE '^\s*(-\s*)?continue-on-error' "$f"; then echo "$f: continue-on-error disables a gate" >&2; bad=1; fi
  while IFS= read -r l; do
    echo "$l" | grep -qE 'uses:\s*\S+@[0-9a-f]{40}(\s|$)' || { echo "$f: action not pinned to a commit SHA: $l" >&2; bad=1; }
  done < <(grep -E '^\s*(-\s*)?uses:' "$f")
done
if [ -f "$dir/release.yml" ] && ! grep -q 'sign verify' "$dir/release.yml"; then
  echo "$dir/release.yml: publishes without verifying the signatures" >&2; bad=1
fi
[ $bad -eq 0 ] && echo "workflows-check: ok"
exit $bad
