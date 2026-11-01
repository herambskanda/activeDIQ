// Package report is the EP-8 host: the pure types a report is made of and the validation that turns
// a definition plus run parameters into the one resolved Query a run executes
// (reports module contract §2, §3; ADR-0010).
//
// It holds no SQL driver (FF-SP1) and builds no SQL: identifiers are validated here and quoted once
// by the registry in store/reportsql, which is also the only producer of dynamic SQL. A report is
// data. A Definition names a Dataset, columns, presets and typed parameters; Resolve checks every
// name, operator and value against the Dataset and returns a Query, or a ValidationError and no
// Query. No parameter is ever LDAP or SQL text.
package report
