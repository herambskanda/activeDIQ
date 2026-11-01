#!/usr/bin/env bash
# T-0261: the workflow files may not weaken a gate or leave an action unpinned.
#   - no `continue-on-error`
#   - every `uses:` is pinned to a 40-hex commit SHA
#   - release.yml verifies the signatures it makes before publishing
#   - release.yml judges the built agent MSI with `fitness-built-msi -require` (T-0724): the gate may not
#     revert to inactive, and the agent-msi artefact is downloaded before it runs
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
if [ -f "$dir/release.yml" ]; then
  # -require makes a missing MSI a failure; without it the gate prints "inactive" and passes (T-0697).
  # The line of `name: agent-msi` inside an actions/download-artifact step (not the upload in the build job).
  dl=$(awk '/uses:.*actions\/download-artifact@/ {d=NR} /^[[:space:]]*-[[:space:]]/ && !/download-artifact/ {d=0} d && /name:[[:space:]]*agent-msi[[:space:]]*$/ {print NR; exit}' "$dir/release.yml")
  gate=$(grep -nE '^\s*(run:\s*)?go run \./tools/fitness/builtmsi\s+-require(\s|$)' "$dir/release.yml" | head -1 | cut -d: -f1)
  if [ -z "$gate" ]; then
    echo "$dir/release.yml: does not run 'go run ./tools/fitness/builtmsi -require' (the built-MSI gate would be inactive)" >&2; bad=1
  elif [ -z "$dl" ] || [ "$dl" -ge "$gate" ]; then
    echo "$dir/release.yml: the agent-msi artefact is not downloaded before the built-MSI gate" >&2; bad=1
  fi
fi
[ $bad -eq 0 ] && echo "workflows-check: ok"
exit $bad
