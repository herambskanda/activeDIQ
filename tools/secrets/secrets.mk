# Secret scanning targets (T-0013). Standard: knowledge/development/standards/secret-scanning.md
.PHONY: secrets-install secrets-install-hooks secrets-scan secrets-test

secrets-install: ## Install the pinned, checksum-verified gitleaks into tools/secrets/bin
	tools/secrets/install-gitleaks.sh

secrets-install-hooks: ## Enable the pre-commit secret scan for this clone (all worktrees) + install gitleaks
	tools/secrets/install-hooks.sh

secrets-scan: secrets-install ## Scan full git history and the working tree for secrets; exit 0 only if clean
	tools/secrets/scan.sh

secrets-test: secrets-install ## Prove the hook and scan fail on a fake AWS key / lab credential and pass on clean input
	tools/secrets/test.sh
