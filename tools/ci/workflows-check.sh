#!/usr/bin/env bash
# T-0261: the workflow files may not weaken a gate or leave an action unpinned.
#   - no `continue-on-error`
#   - every `uses:` is pinned to a 40-hex commit SHA
#   - release.yml verifies the signatures it makes before publishing
#   - release.yml judges the built agent MSI with `fitness-built-msi -require` (T-0724): the gate may not
#     revert to inactive, and the agent-msi artefact is downloaded before it runs
#   - release.yml token hygiene (T-0724): top-level permissions are read-only, only the publish job asks for
#     contents: write, and every checkout sets persist-credentials: false
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
if [ -f "$dir/release.yml" ]; then
  # Builds run code fetched from the network (WiX dotnet tool, Go modules); a write token in .git/config or
  # in the job's environment would let it move a tag or edit a release.
  out=$(awk '
    function flush_checkout() { if (co && !pc) printf "checkout at line %d has no persist-credentials: false\n", co; co = 0; pc = 0 }
    { line = $0; sub(/[[:space:]]*#.*$/, "", line) }
    line ~ /^[[:space:]]*-[[:space:]]/ { flush_checkout() }
    line ~ /^[^[:space:]]/ { top = (line ~ /^permissions:/); job = "" }
    line ~ /^  [A-Za-z0-9_-]+:[[:space:]]*$/ && !top { j = line; gsub(/[[:space:]:]/, "", j); job = j }
    line ~ /^jobs:/ { job = ""; injobs = 1 }
    line ~ /uses:[[:space:]]*actions\/checkout@/ { co = NR; pc = 0 }
    line ~ /persist-credentials:[[:space:]]*false[[:space:]]*$/ { pc = 1 }
    line ~ /contents:[[:space:]]*write/ {
      if (top) print "top-level permissions grant contents: write"
      else if (job != "publish") printf "job %s requests contents: write (only publish may)\n", (job == "" ? "?" : job)
      else wrote = 1
    }
    line ~ /permissions:[[:space:]]*write-all/ { print "write-all permissions are not allowed" }
    line ~ /contents:[[:space:]]*read/ && top { topread = 1 }
    END { flush_checkout(); if (!topread) print "no top-level permissions: contents: read"; if (!wrote) print "publish job does not request contents: write" }
  ' "$dir/release.yml")
  if [ -n "$out" ]; then
    while IFS= read -r l; do echo "$dir/release.yml: token hygiene: $l" >&2; done <<<"$out"; bad=1
  fi
fi
[ $bad -eq 0 ] && echo "workflows-check: ok"
exit $bad
