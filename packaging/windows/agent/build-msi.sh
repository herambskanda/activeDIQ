#!/usr/bin/env bash
# T-0724: build the agent MSI (Agent.wxs, WiX v4) on a Windows host. Usage: build-msi.sh <tag> <outdir>
# Fixed arguments only; the tag is validated, never interpolated into a command line. WiX only supports
# Windows, so this runs on the release job's Windows runner (or a lab VM), not on Linux.
# WiX 4.0.5 is pinned (MS-RL line; the licence register row stays "Candidate" until devops confirms).
set -euo pipefail
tag=${1:?tag}; out=${2:?outdir}
[[ $tag =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?$ ]] || { echo "build-msi: tag '$tag' is not vMAJOR.MINOR.PATCH[-pre]" >&2; exit 1; }
version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
mkdir -p "$out/bin"
export CGO_ENABLED=0 GOOS=windows GOARCH=amd64
go build -trimpath -o "$out/bin/activediq-agent.exe" ./cmd/agent
go build -trimpath -o "$out/bin/agentsetup.exe" ./cmd/agentsetup
dotnet tool install --global wix --version 4.0.5
wix extension add -g WixToolset.Util.wixext/4.0.5
wix build packaging/windows/agent/Agent.wxs -arch x64 -ext WixToolset.Util.wixext \
  -d "Version=$version" -d "AgentExe=$out/bin/activediq-agent.exe" -d "SetupExe=$out/bin/agentsetup.exe" \
  -o "$out/activediq-agent-$version.msi"
