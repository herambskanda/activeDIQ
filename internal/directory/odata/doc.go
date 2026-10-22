// Package odata is safe primitive P8 (knowledge/development/architecture/safe-primitives-odata.md):
// the only place that writes OData URL text for Microsoft Graph. Feature code builds a typed filter
// AST and a Request; URL renders it. Quote doubling, percent-encoding and key-segment syntax live
// here and nowhere else.
//
// Everything is sealed. Strings enter through Str (validated), identifiers through guid.GUID, and
// property names through the declarations in package graphschema. No Or, Not, lambda or $search in
// this version: each is an amendment with its own vectors (spec §8).
package odata
