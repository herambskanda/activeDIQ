#!/usr/bin/env bash
# The light filter (merge plan 5.4): what the gate runs on a ticket BEFORE its full `make ci`, side by side with another ticket's
# gate run. The 5-minute prescreen, the cheap fitness checks, and the Go tests of the packages the merge result changes plus
# everything that imports them. It prints only problems `main` does not already have: a Go test that fails here is re-run on
# main's commit, and counts only if it passes there. Run in a merge-result tree (HEAD^1 = main). On plain main (no second
# parent) it runs only the prescreen and the fitness checks, which is what the gate's baseline for this command is.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
LIGHT_FITNESS="${LIGHT_FITNESS:-fitness-modules fitness-tenancy fitness-domain-keys fitness-profiles fitness-api fitness-operation fitness-audit fitness-reports fitness-keys}"
rc=0
make prescreen || rc=1   # main itself may fail some checks (known findings); the gate's ratchet judges, so keep going
make -k -j2 -O $LIGHT_FITNESS || rc=1
if git rev-parse -q --verify HEAD^2 >/dev/null; then
  base=$(git rev-parse HEAD^1)
  pk=$(python3 "$HERE/affected-packages.py" "$base")
  echo "light: affected packages: $(echo "$pk" | wc -w)"
  [ "$pk" = ALL ] && pk="./..."
  if [ -n "$pk" ]; then
    go test -count=1 -p 3 -timeout 30m $pk > light-tests.log 2>&1; trc=$?
    if [ $trc -ne 0 ]; then
      mt=$(mktemp -d); git worktree add -q --detach "$mt" "$base"
      bad=$(grep -E '^FAIL\s+\S+' light-tests.log | awk '{print $2}' | sort -u)
      (cd "$mt" && go test -count=1 -p 3 -timeout 30m $bad > "$mt/main-tests.log" 2>&1)
      grep -E '^--- FAIL: ' light-tests.log | sort -u > cand.fails; grep -E '^--- FAIL: ' "$mt/main-tests.log" | sort -u > main.fails
      grep -E '^FAIL\s+\S+.*(build failed|setup failed)' light-tests.log | sort -u > cand.build; grep -E '^FAIL\s+\S+.*(build failed|setup failed)' "$mt/main-tests.log" | sort -u > main.build
      new=$(comm -23 cand.fails main.fails; comm -23 cand.build main.build)
      git worktree remove --force "$mt"
      if [ -n "$new" ]; then echo "$new" | sed 's/ (.*//'; rc=1; else echo "light: Go test failures all exist on main too"; fi
    fi
  fi
fi
exit $rc
