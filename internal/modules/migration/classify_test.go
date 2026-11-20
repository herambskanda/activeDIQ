package migration_test

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/migration"
)

// No resolver: a directory scope cannot be cleared, so it fails closed; a non-directory grant is fine.
func TestClassifyFailsClosed(t *testing.T) {
	c, err := migration.Classify(context.Background(), nil, nil, 0, exact("r", migration.Grant{Permission: "inventory.read", Scope: []string{plainOU}}))
	if err != nil || c.Class != migration.ClassNotSupported || c.Reason != migration.ReasonTier0Unknown || c.Proposal != nil {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = migration.Classify(context.Background(), nil, nil, 0, exact("r", migration.Grant{Permission: "inventory.read"}))
	if err != nil || c.Class != migration.ClassExact || c.Proposal == nil {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestClassifyRejectsMalformed(t *testing.T) {
	bad := exact("r")
	bad.Declared = migration.ClassManual // an importer cannot pick a class that skips the rules
	if _, err := migration.Classify(context.Background(), nil, nil, 0, bad); err == nil {
		t.Error("manual declared class accepted")
	}
	bad = exact("r")
	bad.Config = nil
	if _, err := migration.Classify(context.Background(), nil, nil, 0, bad); err == nil {
		t.Error("applicable item without config accepted")
	}
	bad = exact("r")
	bad.Declared = migration.ClassChanged
	if _, err := migration.Classify(context.Background(), nil, nil, 0, bad); err == nil {
		t.Error("changed without diff accepted")
	}
}

// Importer flags never import, whatever else the item carries.
func TestClassifyNeverImported(t *testing.T) {
	for name, mod := range map[string]func(*migration.Item){
		"cred": func(i *migration.Item) { i.Credential = true },
		"sql":  func(i *migration.Item) { i.RawSQL = true },
		"open": func(i *migration.Item) { i.OpenRequest = true },
	} {
		it := exact("r")
		mod(&it)
		c, err := migration.Classify(context.Background(), nil, nil, 0, it)
		if err != nil || c.Class != migration.ClassNotSupported || c.Proposal != nil {
			t.Errorf("%s: %+v %v", name, c, err)
		}
	}
}
