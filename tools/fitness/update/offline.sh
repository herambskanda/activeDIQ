#!/usr/bin/env bash
# TM-F-UPDATE, offline courier, with the network removed (ENH-07 AC-8): builds the proof as a static
# binary and runs it in a container with `--network none`. First shows the container really has no
# network (a connection attempt must fail), then runs the offline courier through the same matrix.
# Needs Docker; the image is the digest-pinned PostgreSQL alpine image the other fitness checks already
# use (it carries a shell and wget; nothing from it is shipped).
set -euo pipefail
cd "$(dirname "$0")/../../.."
IMAGE=${FITNESS_UPDATE_IMAGE:-postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 GOOS=linux go build -trimpath -o "$tmp/update" ./tools/fitness/update
chmod 755 "$tmp" "$tmp/update"
if docker run --rm --network none "$IMAGE" wget -q -T 3 -O /dev/null http://1.1.1.1/ >/dev/null 2>&1; then
  echo "fitness-update-offline: FAIL: the container reached the network under --network none" >&2
  exit 1
fi
echo "fitness-update-offline: container has no network (connection refused, as required)"
docker run --rm --network none --read-only --tmpfs /tmp --user 65534:65534 -v "$tmp:/proof:ro" "$IMAGE" /proof/update -courier offline
