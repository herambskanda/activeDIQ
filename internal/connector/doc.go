// Package connector is the root of the connector (blueprint §5.3): the only place that imports
// directory protocol and Graph libraries and the only place that unseals directory credentials
// (ADR-0002 rule 3). Subpackages: graph (read-only Microsoft Graph client, app-only certificate auth) and
// graph/graphtest (in-process fake Graph for tests).
package connector
