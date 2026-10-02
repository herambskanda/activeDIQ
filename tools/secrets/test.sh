#!/usr/bin/env bash
# Proves the secret-scanning gates fail when they should and pass when they should (T-0013).
# Works in a throwaway git repo that carries copies of the real hook, config and scripts, so it never
# touches this repo's history. Fake secrets are assembled at runtime from fragments, so this file
# itself stays clean under the scan it tests. Usage: tools/secrets/test.sh   (or: make secrets-test)
set -u
src=$(cd "$(dirname "$0")/../.." && pwd)
"$src/tools/secrets/gitleaks.sh" version >/dev/null 2>&1 || "$src/tools/secrets/install-gitleaks.sh" || exit 1

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid

new_repo() { # $1 = dir
  mkdir -p "$1/tools" && cd "$1" || exit 1
  git init -q -b main .
  cp "$src/.gitleaks.toml" .; cp -R "$src/.githooks" .; mkdir -p tools/secrets
  cp "$src"/tools/secrets/*.sh "$src"/tools/secrets/gitleaks.version tools/secrets/
  : > .gitignore
  git config core.hooksPath .githooks
  git add -A && git -c core.hooksPath=/dev/null commit -q -m init
}

fake_aws() { printf '%s%s' 'AKIA' 'QYLPMN5HHHFPZAM2'; }           # shaped like an AWS access key id, not issued
fake_lab() { printf '%s%s' 'LAB_ADMIN_PASS' "WORD=Zk9fQ2xhdW5kZXI3NzEh"; }

pass=0; fail=0
check() { # $1 name, $2 expected (0|nonzero), then command
  local name=$1 want=$2; shift 2
  local out; out=$("$@" 2>&1); local rc=$?
  if { [ "$want" = 0 ] && [ $rc -eq 0 ]; } || { [ "$want" = nonzero ] && [ $rc -ne 0 ]; }; then
    echo "ok   - $name"; pass=$((pass+1))
  else
    echo "FAIL - $name (exit $rc, wanted $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
  fi
}
commit_refused_naming() { # commit must fail AND mention the rule
  local out; out=$(git commit -q -m "add" 2>&1); local rc=$?
  [ $rc -ne 0 ] && echo "$out" | grep -q "$1"
}

new_repo "$work/r1"
# AC1: staged fake AWS key => commit refused
fake_aws | sed 's/^/aws_access_key_id = /' > config.ini; git add config.ini
check "staged fake AWS key: commit is refused, rule aws-access-token named" 0 commit_refused_naming aws-access-token
git rm -q --cached -f config.ini; rm config.ini
# the key must not be redacted away only in output: the finding is redacted, the commit did not happen
check "refused commit left no new commit" 0 test "$(git rev-list --count HEAD)" = 1

# clean change commits
echo "hello" > notes.txt; git add notes.txt
check "clean staged file: commit succeeds" 0 git commit -q -m notes

# activeDIQ lab-credential rule
fake_lab > labcfg.sh; git add labcfg.sh
check "staged literal lab credential: commit is refused, rule named" 0 commit_refused_naming activediq-lab-credential
git rm -q --cached -f labcfg.sh; rm labcfg.sh
echo 'LAB_ADMIN_PASSWORD="$(openssl rand -hex 16)"' > labgen.sh; git add labgen.sh
check "lab credential generated at runtime (not a literal): commit succeeds" 0 git commit -q -m gen

# vendor documentation example keys are the only allowlisted values
echo 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE' > doc.md; git add doc.md
check "vendor documentation example key is allowlisted" 0 git commit -q -m doc

# no gitleaks available => the hook refuses (fail closed) and says how to install it
new_repo "$work/r4"
echo "clean" > z.txt; git add z.txt
fails_closed() { local out; out=$(HOME=$work/nohome ACTIVEDIQ_TOOLS_DIR= PATH=/usr/bin:/bin git commit -q -m z 2>&1); [ $? -ne 0 ] && echo "$out" | grep -q 'make secrets-install'; }
check "no gitleaks on the machine: commit is refused with the install hint" 0 fails_closed
cd "$work/r1"

# scan target: tree mode
check "scan --tree-only passes on a clean tree" 0 tools/secrets/scan.sh --tree-only
fake_aws > untracked.key.txt
check "scan --tree-only fails on an untracked file holding a fake AWS key" nonzero tools/secrets/scan.sh --tree-only
rm untracked.key.txt

# scan target: history mode — a key forced past the hook (--no-verify) is still caught
check "scan --history-only passes before the leak" 0 tools/secrets/scan.sh --history-only
fake_aws > leaked.txt; git add leaked.txt; git commit -q --no-verify -m leak
check "scan --history-only fails after a key was committed with --no-verify" nonzero tools/secrets/scan.sh --history-only
git rm -q leaked.txt; git commit -q --no-verify -m "remove (secret still in history)"
check "scan (all) still fails after the file is deleted — history keeps it" nonzero tools/secrets/scan.sh

# gitignored secrets stay out of scope
new_repo "$work/r2"
fake_aws > .env; printf '.env\n' >> .gitignore
check "scan ignores a gitignored .env (secrets may live there)" 0 tools/secrets/scan.sh --tree-only

# hook installer
new_repo "$work/r3"; git config --unset core.hooksPath
check "install-hooks.sh sets core.hooksPath" 0 sh -c 'tools/secrets/install-hooks.sh >/dev/null && test "$(git config core.hooksPath)" = .githooks'

echo; echo "$pass passed, $fail failed"; [ "$fail" -eq 0 ]
