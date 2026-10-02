#!/bin/sh
# Points this clone (and all its worktrees, which share .git/config) at the tracked hooks in .githooks/
# and makes sure the pinned gitleaks is installed. Idempotent.
set -eu
root=$(git rev-parse --show-toplevel)
current=$(git config --get core.hooksPath || true)
if [ -n "$current" ] && [ "$current" != ".githooks" ]; then
  echo "core.hooksPath is already set to '$current'; not overwriting. Chain $root/.githooks/pre-commit from it." >&2
  exit 1
fi
git config core.hooksPath .githooks
"$root/tools/secrets/install-gitleaks.sh"
echo "pre-commit secret scanning active (core.hooksPath=.githooks)"
