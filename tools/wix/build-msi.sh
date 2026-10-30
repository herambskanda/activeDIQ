#!/usr/bin/env bash
# Build an MSI from a WiX v4/v5 source with the pinned toolchain (tools/wix/Dockerfile).
#   tools/wix/build-msi.sh packaging/windows/msi/Server.wxs out/ActiveDIQ-Server.msi
# Compile defects fail the build (non-zero exit, no output file). Needs docker only.
set -euo pipefail
src=${1:?usage: build-msi.sh <file.wxs> <out.msi>}; out=${2:?usage: build-msi.sh <file.wxs> <out.msi>}
srcdir=$(cd "$(dirname "$src")" && pwd); name=$(basename "$src")
mkdir -p "$(dirname "$out")"; outdir=$(cd "$(dirname "$out")" && pwd); outname=$(basename "$out")
docker build -q -t activediq-wix:5.0.2 "$(dirname "$0")" >/dev/null
rm -f "$outdir/$outname"
docker run --rm -e OWNER="$(id -u):$(id -g)" -v "$srcdir":/src:ro -v "$outdir":/out -w /src activediq-wix:5.0.2 \
  bash -c 'xvfb-run -a wine /opt/dotnet/dotnet.exe /opt/wix/tools/net6.0/any/wix.dll build -arch x64 "$0" -o "/out/$1" 2>&1 | grep -v "X connection\|syswow64"; rc=${PIPESTATUS[0]}; chown "$OWNER" "/out/$1" 2>/dev/null; test "$rc" = 0 -a -s "/out/$1"' "$name" "$outname"
sha256sum "$outdir/$outname"
