// Package connector is the root of the connector (blueprint §5.3): the only place that imports
// directory protocol and Graph libraries and the only place that unseals directory credentials
// (ADR-0002 rule 3). Subpackages: tier0 (computed tier0 set; Entra half E1-E5), graph (read-only
// Microsoft Graph client, app-only certificate auth), graph/graphtest (in-process fake Graph for
// tests) and rights (the VerifyConnection rights check; Entra half: threat-model §6.6).
package connector
