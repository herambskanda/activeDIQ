# AD lab targets (T-0012). Runbook: knowledge/development/runbooks/ad-lab.md
# Needs only Docker (Compose v2), openssl and a POSIX shell on the host.
LAB_DIR      := lab
LAB_ENV      := $(LAB_DIR)/.lab.env
LAB_CA       := $(LAB_DIR)/.lab-ca.pem
LAB_TIER     ?= standard
LAB_BUILD_FLAGS ?= -q          # e.g. LAB_BUILD_FLAGS=--no-cache for a from-scratch image build
# Per-worktree isolation (T-0373): same derivation as lab/bin/lab-env, so no env file is needed to address it.
LAB_HASH     := $(shell printf '%s' "$(CURDIR)" | (sha256sum 2>/dev/null || shasum -a 256) | cut -c1-8)
LAB_PROJECT  := activediq-lab-$(LAB_HASH)
COMPOSE      := docker compose -p $(LAB_PROJECT) -f $(LAB_DIR)/docker-compose.yml
# The seed version changes whenever the generator, the image recipe or the tier change, so a stale
# snapshot is never reused. It is also tied to the credentials file (a new .lab.env => a new lab).
LAB_SEED_HASH := $(shell cat $(LAB_DIR)/seed/generate.py $(LAB_DIR)/seed/post-start.sh $(LAB_DIR)/seed/schema-seed.sh $(LAB_DIR)/samba/entrypoint.sh $(LAB_DIR)/samba/Dockerfile 2>/dev/null | shasum -a 256 | cut -c1-12)
export LAB_TIER
# One-off `compose run` containers (init/version/restore) survive an interrupted make and hold the
# project network, so lab-destroy cannot remove it (T-1858). Remove them by compose labels.
LAB_RUN_CLEAN = docker ps -aq --filter label=com.docker.compose.project=$(LAB_PROJECT) --filter label=com.docker.compose.oneoff=True | xargs -r docker rm -f >/dev/null

.PHONY: lab-up lab-reset lab-rebuild lab-down lab-destroy lab-status lab-logs lab-shell lab-test lab-test-unit lab-test-live lab-test-connector entra-lab-bootstrap entra-lab-verify

lab-up: ## Start the AD lab (provision + seed on first run, ~3-4 min); prints connection details
	@set -e; t0=$$(date +%s); \
	command -v docker >/dev/null || { echo "docker not found"; exit 1; }; \
	docker info >/dev/null 2>&1 || { echo "Docker daemon is not running"; exit 1; }; \
	$(LAB_DIR)/bin/lab-env $(LAB_ENV); \
	set -a; . $(LAB_ENV); set +a; \
	$(LAB_RUN_CLEAN); \
	$(COMPOSE) build $(LAB_BUILD_FLAGS) dc; \
	want="$(LAB_SEED_HASH)-$(LAB_TIER)-$$LAB_ENV_ID"; \
	have=$$($(COMPOSE) run --rm --no-deps -T dc version 2>/dev/null | tail -1 | tr -d '\r'); \
	if [ "$$have" != "$$want" ]; then \
	  echo ">> provisioning and seeding (tier=$(LAB_TIER)); first run only"; \
	  $(COMPOSE) run --rm --no-deps -T -e LAB_SEED_VERSION="$$want" dc init; \
	else echo ">> state volume already holds seed $$want — keeping it (make lab-reset to restore the snapshot)"; fi; \
	$(COMPOSE) up -d --wait --wait-timeout 240 dc; \
	$(COMPOSE) cp dc:/var/lib/samba/lab-tls/ca.pem $(LAB_CA) >/dev/null; \
	$(LAB_DIR)/bin/lab-info; \
	echo "lab-up finished in $$(( $$(date +%s) - t0 ))s"

lab-reset: ## Restore the lab to the exact seeded snapshot (seconds)
	@set -e; t0=$$(date +%s); set -a; . $(LAB_ENV); set +a; \
	$(COMPOSE) stop -t 20 dc; \
	$(COMPOSE) run --rm --no-deps -T dc restore; \
	$(COMPOSE) up -d --wait --wait-timeout 240 dc; \
	echo "lab-reset finished in $$(( $$(date +%s) - t0 ))s"

lab-rebuild: lab-destroy lab-up ## Throw the lab away and provision + seed from scratch

lab-down: ## Stop the lab (state and snapshot are kept)
	$(COMPOSE) down

lab-destroy: ## Remove the lab containers (incl. stale one-off dc-run ones), volumes and generated credentials
	-@$(LAB_RUN_CLEAN)
	-$(COMPOSE) down -v --remove-orphans
	rm -f $(LAB_ENV) $(LAB_CA)

lab-status: ## Show lab health and connection details
	@$(COMPOSE) ps; $(LAB_DIR)/bin/lab-info

lab-logs: ## Follow the DC logs
	$(COMPOSE) logs -f dc

lab-shell: ## Shell inside the DC container (samba-tool, ldapsearch…)
	$(COMPOSE) exec dc bash

lab-test-unit: ## Seed-generator unit tests (no Docker needed)
	python3 -m unittest discover -s $(LAB_DIR)/tests -p 'test_*.py' -v
	$(LAB_DIR)/tests/test_schema_seed.sh && $(LAB_DIR)/tests/test_schema_seed.sh --selftest
	python3 -I -m unittest discover -s $(LAB_DIR)/proxmox/tests -p 'test_*.py'

lab-test-live: ## Verify the running lab, then prove lab-reset returns it to the seeded state
	$(LAB_DIR)/tests/verify.sh

lab-test-connector: ## internal/connector/ad against the running lab (T-0092)
	go test -count=1 -tags lab ./internal/connector/ad/

lab-test: lab-test-unit lab-test-live ## All lab tests

# Entra lab (T-0183, D-0001): a Microsoft 365 Developer sandbox. DEV TENANT ONLY. Runbook: ad-lab.md §5.
entra-lab-bootstrap: ## CEO, once per (re)created sandbox: device-code sign-in as its Global Admin; creates the activeDIQ-lab app + certificate, consent, seed objects; writes lab/.entra-lab.env and .entra-lab.pem (0600)
	$(LAB_DIR)/bin/entra-lab-bootstrap

entra-lab-verify: ## Check the handover: certificate token acquired, consented Graph permissions == lab/entra/permissions.txt, no role, no secret
	$(LAB_DIR)/bin/entra-lab-verify
