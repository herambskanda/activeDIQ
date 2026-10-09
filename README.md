# activeDIQ

Enterprise Active Directory management and identity product by **skenzeriq**, built to displace
ManageEngine's AD suite (ADManager Plus, ADAudit Plus, ADSelfService Plus, AD360) with feature
parity, meaningful enhancements and a far better experience. Self-hosted first, SaaS-ready.

**Status:** pre-implementation / early build (milestone M1). Everything here, including the
strategy, research and the factory that builds the product, is published openly.

## What is in this repository

| Path | What |
| --- | --- |
| `knowledge/` | Strategy, research, product specs, architecture, ADRs, standards, memory |
| `factory/` | The AI code factory: operating model, CLI, dispatcher, board, templates, reports |
| `.claude/` | Claude Code setup: agents, skills, hooks, settings, agent memory |
| `helm.yaml`, `.helm/` | Helm project setup |
| `internal/`, `cmd/`, `api/`, `migrations/`, `web/`, `sidecars/`, `proto/` | Product code |
| `lab/`, `tools/`, `testdata/` | AD test lab, analyzers and fitness functions, fixtures |
| `garage/` | Time-boxed prototypes and spikes |

Start with [`CLAUDE.md`](CLAUDE.md), [`factory/OPERATING-MODEL.md`](factory/OPERATING-MODEL.md) and
[`knowledge/README.md`](knowledge/README.md). Run the factory board with `factory/bin/factory up`
(http://127.0.0.1:4747).

## Licence

Source-available under the [Business Source License 1.1](LICENSE): you can read, modify and use the
code non-commercially or to manage your own environments, but not offer it as a competing product
or service. On **2030-10-09** (or four years after each version's release) it converts to Apache-2.0.
This is not an OSI-approved open-source licence.
