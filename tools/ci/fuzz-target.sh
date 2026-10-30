#!/usr/bin/env bash
# fuzz-target.sh <package-dir> <FuzzTarget> <fuzztime> (T-0490): run one Go fuzz target for a fixed time as
# a CI gate. Fails on any crasher/oracle violation, and when the target does not exist or never ran
# (go test -fuzz exits non-zero for "no fuzz tests to fuzz"; we also require the "fuzz: elapsed" output
# so a silent no-op cannot pass). A crasher is written under testdata/fuzz/ of the package: commit it.
set -uo pipefail
if [ $# -ne 3 ]; then echo "usage: fuzz-target.sh <package-dir> <FuzzTarget> <fuzztime>" >&2; exit 2; fi
pkg=$1 target=$2 fuzztime=$3
out=$(mktemp)
trap 'rm -f "$out"' EXIT
(cd "$pkg" && go test -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" .) >"$out" 2>&1
rc=$?
cat "$out"
if [ $rc -ne 0 ]; then echo "fuzz-target: $target FAILED in $pkg (exit $rc)" >&2; exit $rc; fi
if ! grep -q 'fuzz: elapsed' "$out"; then echo "fuzz-target: $target did not fuzz (no 'fuzz: elapsed' output)" >&2; exit 1; fi
echo "fuzz-target: $target ok ($fuzztime)"
