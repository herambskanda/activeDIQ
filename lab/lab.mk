# AD lab targets (T-0012). Runbook: knowledge/development/runbooks/ad-lab.md
# Needs only Docker (Compose v2), openssl and a POSIX shell on the host.
LAB_DIR      := lab
LAB_ENV      := $(LAB_DIR)/.lab.env
LAB_CA       := $(LAB_DIR)/.lab-ca.pem
LAB_TIER     ?= standard
LAB_BUILD_FLAGS ?= -q          # e.g. LAB_BUILD_FLAGS=--no-cache for a from-scratch image build
COMPOSE      := docker compose -f $(LAB_DIR)/docker-compose.yml
# The seed version changes whenever the generator, the image recipe or the tier change, so a stale
# snapshot is never reused. It is also tied to the credentials file (a new .lab.env => a new lab).
LAB_SEED_HASH := $(shell cat $(LAB_DIR)/seed/generate.py $(LAB_DIR)/seed/post-start.sh $(LAB_DIR)/samba/entrypoint.sh $(LAB_DIR)/samba/Dockerfile 2>/dev/null | shasum -a 256 | cut -c1-12)
export LAB_TIER

.PHONY: lab-up lab-reset lab-rebuild lab-down lab-destroy lab-status lab-logs lab-shell lab-test lab-test-unit lab-test-live

lab-up: ## Start the AD lab (provision + seed on first run, ~3-4 min); prints connection details
	@set -e; t0=$$(date +%s); \
	command -v docker >/dev/null || { echo "docker not found"; exit 1; }; \
	docker info >/dev/null 2>&1 || { echo "Docker daemon is not running"; exit 1; }; \
	$(LAB_DIR)/bin/lab-env $(LAB_ENV); \
	. $(LAB_ENV); \
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
	@set -e; t0=$$(date +%s); . $(LAB_ENV); \
	$(COMPOSE) stop -t 20 dc; \
	$(COMPOSE) run --rm --no-deps -T dc restore; \
	$(COMPOSE) up -d --wait --wait-timeout 240 dc; \
	echo "lab-reset finished in $$(( $$(date +%s) - t0 ))s"

lab-rebuild: lab-destroy lab-up ## Throw the lab away and provision + seed from scratch

lab-down: ## Stop the lab (state and snapshot are kept)
	$(COMPOSE) down

lab-destroy: ## Remove the lab containers, volumes and generated credentials
	-$(COMPOSE) down -v
	rm -f $(LAB_ENV) $(LAB_CA)

lab-status: ## Show lab health and connection details
	@$(COMPOSE) ps; $(LAB_DIR)/bin/lab-info

lab-logs: ## Follow the DC logs
	$(COMPOSE) logs -f dc

lab-shell: ## Shell inside the DC container (samba-tool, ldapsearch…)
	$(COMPOSE) exec dc bash

lab-test-unit: ## Seed-generator unit tests (no Docker needed)
	python3 -m unittest discover -s $(LAB_DIR)/tests -p 'test_*.py' -v

lab-test-live: ## Verify the running lab, then prove lab-reset returns it to the seeded state
	$(LAB_DIR)/tests/verify.sh

lab-test: lab-test-unit lab-test-live ## All lab tests
