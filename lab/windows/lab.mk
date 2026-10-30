# Windows Server 2025 evaluation lab on local KVM (T-0254, D-0003). Runbook: knowledge/development/runbooks/windows-lab.md
WINLAB := lab/windows/bin/windows-lab
.PHONY: windows-agent-harness-build windows-lab-up windows-lab-reset windows-lab-down windows-lab-destroy windows-lab-rebuild windows-lab-status windows-lab-preflight lab-test-connector-windows lab-test-windows-unit

windows-lab-preflight: ## Check KVM/libvirt tooling and disk space for the Windows lab
	$(WINLAB) preflight
windows-lab-up: ## Download the WS2025 eval ISO, build dc1 + fs1 (random passwords), snapshot "clean" (~45 min first run)
	$(WINLAB) up
windows-lab-reset: ## Revert dc1 + fs1 to the clean snapshot (minutes)
	$(WINLAB) reset
windows-lab-down: ## Shut the Windows lab VMs down (disks and snapshots kept)
	$(WINLAB) down
windows-lab-destroy: ## Delete the VMs, disks, network and generated credentials (ISO kept)
	$(WINLAB) destroy
windows-lab-rebuild: windows-lab-destroy windows-lab-up ## Rebuild from scratch (the licence answer is rebuild, not rearm)
windows-lab-status: ## VM state and connection details
	$(WINLAB) status
lab-test-connector-windows: ## internal/connector/ad against dc1 over LDAPS (tags lab,windowslab); log in knowledge/development/runbooks/windows-lab-runs/
	$(WINLAB) test-connector
lab-test-windows-unit: ## Offline proof of the Windows lab tooling (dry run; no KVM needed)
	python3 -m unittest discover -s lab/windows/tests -p 'test_*.py' -v

.PHONY: windows-agent-harness-build
windows-agent-harness-build: ## Cross-build the lab-only service stub for T-0613 (copy with Install-AgentLabHarness.ps1 to the Windows host)
	mkdir -p lab/windows/.state/agent-harness
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o lab/windows/.state/agent-harness/svcstub.exe ./lab/windows/agent-harness/svcstub
