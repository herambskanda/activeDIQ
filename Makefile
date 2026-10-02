# activeDIQ — root Makefile. Targets are added by the ticket that owns them
# (lab-*: T-0012; ci/lint/build arrive with T-0014/T-0015/T-0022).
.DEFAULT_GOAL := help
.PHONY: help
help:
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

include lab/lab.mk
