#!/bin/sh
# Runs the pinned gitleaks. Resolution order: the per-user cache (see install-gitleaks.sh), then `gitleaks` on PATH —
# either must report exactly the pinned version, otherwise we stop (a different version means
# different rules, so a "pass" would not mean what CI means by pass). Missing => install it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
ver=$(tr -d ' \n' < "$here/gitleaks.version")
tools_dir=${ACTIVEDIQ_TOOLS_DIR:-${HOME:-/nonexistent}/.cache/activediq}
for cand in "$tools_dir/gitleaks/$ver/gitleaks" "$(command -v gitleaks 2>/dev/null || true)"; do
  [ -n "$cand" ] && [ -x "$cand" ] || continue
  if [ "$("$cand" version 2>/dev/null)" = "$ver" ]; then exec "$cand" "$@"; fi
done
echo "gitleaks $ver not found. Run: make secrets-install   (tools/secrets/install-gitleaks.sh)" >&2
exit 127
