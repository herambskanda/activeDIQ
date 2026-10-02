#!/bin/sh
# Installs the pinned gitleaks (tools/secrets/gitleaks.version) into a per-user cache shared by every
# worktree of every clone: ${ACTIVEDIQ_TOOLS_DIR:-$HOME/.cache/activediq}/gitleaks/<version>/gitleaks
# (never inside the repo, so nothing binary is ever tracked).
# The archive is verified against tools/secrets/gitleaks.sha256 before anything is extracted.
# Usage: tools/secrets/install-gitleaks.sh        (idempotent; re-run is a no-op when the pin is present)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
ver=$(tr -d ' \n' < "$here/gitleaks.version")
tools_dir=${ACTIVEDIQ_TOOLS_DIR:-${HOME:?HOME is not set}/.cache/activediq}
bindir="$tools_dir/gitleaks/$ver"
bin="$bindir/gitleaks"

if [ -x "$bin" ] && "$bin" version 2>/dev/null | grep -qx "$ver"; then
  echo "gitleaks $ver already installed at $bin"; exit 0
fi

case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) echo "unsupported OS $(uname -s); install gitleaks $ver manually onto PATH" >&2; exit 2 ;; esac
case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=x64 ;; *) echo "unsupported arch $(uname -m)" >&2; exit 2 ;; esac
archive="gitleaks_${ver}_${os}_${arch}.tar.gz"
want=$(grep -E "^[0-9a-f]{64}  $archive\$" "$here/gitleaks.sha256" | cut -d' ' -f1)
[ -n "$want" ] || { echo "no pinned checksum for $archive in gitleaks.sha256" >&2; exit 2; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/$archive" "https://github.com/gitleaks/gitleaks/releases/download/v${ver}/${archive}"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$archive" | cut -d' ' -f1); else got=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1); fi
[ "$got" = "$want" ] || { echo "CHECKSUM MISMATCH for $archive: expected $want, got $got" >&2; exit 1; }

mkdir -p "$bindir"
tar -xzf "$tmp/$archive" -C "$tmp" gitleaks
mv "$tmp/gitleaks" "$bin"; chmod 755 "$bin"
echo "installed gitleaks $ver (sha256 verified) at $bin"
