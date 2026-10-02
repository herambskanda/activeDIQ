#!/usr/bin/env bash
# Fails (exit 1) and lists the files if any Go file under the given directories (default: .) is not
# gofmt-clean. Used by `make lint`; `tools/ci/proof.sh` proves it fails on a badly formatted file.
set -euo pipefail
bad=$(gofmt -l "${@:-.}")
if [ -n "$bad" ]; then
  echo "gofmt: these files are not formatted (run: gofmt -w <file>):" >&2
  echo "$bad" >&2
  exit 1
fi
