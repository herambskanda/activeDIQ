#!/usr/bin/env bash
# T-0724: build the agent MSI (packaging/windows/agent/Agent.wxs) on a Windows host. Lives outside packaging/ because
# fitness-agent-host refuses any script there that is not reviewed (it does not touch the account, SID or privileges). Usage: build-agent-msi.sh <tag> <outdir>
# Fixed arguments only; the tag is validated, never interpolated into a command line. WiX only supports
# Windows, so this runs on the release job's Windows runner (or a lab VM), not on Linux.
# WiX 5.0.2 is pinned: the version that built the agent MSI on the lab DC (windows-lab.md section 13) and the last
# fee-free line (tools/wix/Dockerfile: never past 5.x without a money decision). MS-RL, build tool only.
set -euo pipefail
tag=${1:?tag}; out=${2:?outdir}
[[ $tag =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?$ ]] || { echo "build-msi: tag '$tag' is not vMAJOR.MINOR.PATCH[-pre]" >&2; exit 1; }
version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
mkdir -p "$out/bin"
export CGO_ENABLED=0 GOOS=windows GOARCH=amd64
go build -trimpath -o "$out/bin/activediq-agent.exe" ./cmd/agent
go build -trimpath -o "$out/bin/agentsetup.exe" ./cmd/agentsetup
dotnet tool install --global wix --version 5.0.2
wix build packaging/windows/agent/Agent.wxs -arch x64 -wx -sw1149 \
  -d "Version=$version" -d "AgentExe=$out/bin/activediq-agent.exe" -d "SetupExe=$out/bin/agentsetup.exe" \
  -o "$out/activediq-agent-$version.msi"
