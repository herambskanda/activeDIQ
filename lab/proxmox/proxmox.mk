# Proxmox lab pool (T-1326, D-0022). Runbook: knowledge/development/runbooks/windows-lab.md, "Proxmox lab pool (D-0022)".
# PVE_HOST is exported to the script by make; it is never spliced into a shell command line.
.PHONY: proxmox-lab-bootstrap proxmox-lab-revoke proxmox-lab-verify proxmox-lab-test

proxmox-lab-bootstrap: ## CEO, once: make proxmox-lab-bootstrap PVE_HOST=<proxmox address> (type your own root login when ssh asks); creates pool adiq-lab, role, user and a pool-scoped token; writes lab/.proxmox-lab.env (0600); secret never printed. Add ARGS=--dry-run to see the exact remote commands first
	@test -n "$$PVE_HOST" || { echo "usage: make proxmox-lab-bootstrap PVE_HOST=<proxmox address>"; exit 2; }
	lab/proxmox/bin/proxmox-lab-bootstrap bootstrap $(ARGS)

proxmox-lab-revoke: ## CEO: make proxmox-lab-revoke PVE_HOST=<proxmox address>; removes the token, user, role, ACLs and the local env file; no VM and not the pool is touched
	@test -n "$$PVE_HOST" || { echo "usage: make proxmox-lab-revoke PVE_HOST=<proxmox address>"; exit 2; }
	lab/proxmox/bin/proxmox-lab-bootstrap revoke $(ARGS)

proxmox-lab-verify: ## Fail unless the token sees only pool adiq-lab and holds only the lab role
	lab/proxmox/bin/proxmox-lab verify-scope

proxmox-lab-test: ## Offline proof of the driver and bootstrap against a stub API and a fake ssh/pveum (no Proxmox needed)
	python3 -I -m unittest discover -s lab/proxmox/tests -p 'test_*.py' -v
