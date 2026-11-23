// Package connector is the root of the connector (blueprint §5.3): the only place that imports
// directory protocol and Graph libraries and the only place that unseals directory credentials
// (ADR-0002 rule 3). Subpackages: provider (EP-11: the core Provider interface and the facets
// DCBound, ObjectReader, Searcher and RightsSource, with Supports deriving the Describe rows),
// provider/ad (the AD provider over one session, with every facet) and provider/entra (the Entra
// provider over graph); service (the one assembly: service.New builds the verify, read and write
// handlers over a provider and returns the composite ConnectorServer, called by both composition
// roots); refusal (the gRPC refusal type shared by the handlers); read (the Read and ScopedSearch
// handlers); tier0 (computed tier0 set; Entra half E1-E5); ad (the AD session layer); graph
// (read-only Microsoft Graph client, app-only certificate auth), graph/graphtest (in-process fake
// Graph for tests), rights (the VerifyConnection rights check: AD half, threat-model §6.5, with the
// shrink baseline; Entra half: §6.6) and write (the Plan/Apply handlers, the write gate and the
// independent Tier-0 guard, contract §8; no write call may exist in this tree outside write/ops).
package connector
