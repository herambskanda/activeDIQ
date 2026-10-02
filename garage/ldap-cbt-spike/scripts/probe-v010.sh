#!/bin/sh
# Shows that the released go-krb5/krb5 v0.1.0 cannot build the adapter: it has no channel binding.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp -r "$here/krb5gssapi" "$here/go.mod" "$here/go.sum" "$tmp/"
rm -f "$tmp/krb5gssapi/client_test.go"
cd "$tmp"
go mod edit -require=github.com/go-krb5/krb5@v0.1.0
echo "# build of krb5gssapi against github.com/go-krb5/krb5 v0.1.0 (released 2026-02-15)"
GOFLAGS=-mod=mod go build ./... 2>&1 || true
echo "# exit: build must FAIL above (undefined: gssapi.ChannelBinding ...)"
