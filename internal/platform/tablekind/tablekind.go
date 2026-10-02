// Package tablekind is where a package declares what each of its database tables is, for the
// domain-model invariants that must hold by construction (domain-model.md §0 X3 to X5). The
// fitness-domain-keys job (tools/fitness/domainkeys, T-0050) reads these declarations from source and
// checks the migrated schema against them, so there is no second, hand-kept table list in the check.
//
// A package that owns tables declares each one next to its migration's owner code:
//
//	var _ = tablekind.Declare(tablekind.Table{
//		Name:   "public.change_record",
//		Entity: "DM-18",
//		Kind:   tablekind.Directory,
//		AppendOnly: true,
//	})
//
// The literal must be statically readable: string literals, the Kind constants and true/false. The job
// reads source without running it, and a declaration it cannot read is a finding. A table without a
// declaration is a finding too, so a new table cannot skip the invariants.
//
// The package is a leaf with no state and no behaviour beyond validation: it is safe to import from
// any kernel or domain package.
package tablekind

import (
	"fmt"
	"regexp"
)

// Kind is a table's scope, in the domain model's own notation (domain-model.md, "Kinds").
type Kind string

const (
	// Platform (P): a registered-global table (ADR-0002 rule 4), set by the installation operator.
	Platform Kind = "P"
	// Tenant (T): tenant_id plus forced RLS, set only through the public API.
	Tenant Kind = "T"
	// Directory (D): tenant scope, written only by sync or by an Action's verified outcome. A
	// directory object is referenced by (tenant_id, connection_id, object_guid) and never by a DN,
	// SID, sAMAccountName, UPN or display name (X3).
	Directory Kind = "D"
)

// Table declares one database table (or the root of one partitioned table: its partitions follow it).
type Table struct {
	// Name is the schema-qualified table name as the migrations create it: "public.tenants".
	Name string
	// Entity is the domain-model entity the table stores, "DM-nn". Several tables may store one
	// entity (DM-24's findings, DM-26's DC observations); each is declared with the entity's ID.
	Entity string
	// Kind is the table's scope. It must equal the kind in the entity's domain-model heading when
	// that heading names exactly one.
	Kind Kind
	// AppendOnly is X5: rows are only ever inserted, the runtime role can neither UPDATE nor DELETE
	// them (only the retention role deletes), and the table has no lifecycle-state column. It covers
	// DM-25's insert-only Tier0Override as well. It must be true exactly for the entities whose
	// domain-model heading says "append-only" or "insert-only".
	AppendOnly bool
	// Sealed lists the columns that hold a sealed (encrypted under the tenant data key) value or key
	// material: DM-11 sealed_secret, DM-37 sealed_secret, DM-63, DM-82 and DM-85 sealed_credentials,
	// DM-02 wrapped_dek. They are the only columns allowed a secret-attribute name (X4) and must be
	// bytea.
	Sealed []string
	// NameOK lists columns whose name trips the X3 identity-name rule or the X5 state-column rule
	// but which hold neither (a `status` that is an HTTP status code written once at insert, a
	// `name` that is a setting key). Each entry is reviewed with the declaration. An entry that no
	// longer needs the exemption is a finding.
	NameOK []string
}

var (
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
	entityPattern = regexp.MustCompile(`^DM-[0-9]{2}$`)
	columnPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// Validate reports why a declaration is malformed. The job applies the same rules to the source it
// reads, and Declare applies them at start-up.
func (t Table) Validate() error {
	switch {
	case !namePattern.MatchString(t.Name):
		return fmt.Errorf("tablekind: table name %q is not schema.table in lower case", t.Name)
	case !entityPattern.MatchString(t.Entity):
		return fmt.Errorf("tablekind: %s: entity %q is not DM-nn", t.Name, t.Entity)
	case t.Kind != Platform && t.Kind != Tenant && t.Kind != Directory:
		return fmt.Errorf("tablekind: %s: kind %q is not P, T or D", t.Name, t.Kind)
	}
	for _, list := range [][]string{t.Sealed, t.NameOK} {
		seen := map[string]bool{}
		for _, c := range list {
			if !columnPattern.MatchString(c) || seen[c] {
				return fmt.Errorf("tablekind: %s: column %q is malformed or listed twice", t.Name, c)
			}
			seen[c] = true
		}
	}
	return nil
}

// Declare records that the package owns the table and returns it unchanged. Its value is the call
// site: the fitness job finds declarations by reading Declare calls and Table literals. It panics on
// a malformed declaration, which is a programming error found by any test run that loads the package.
func Declare(t Table) Table {
	if err := t.Validate(); err != nil {
		panic(err)
	}
	return t
}
