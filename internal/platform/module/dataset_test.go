package module_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// dataset is a minimal valid dataset over the given tables.
func dataset(id report.DatasetID, tables ...string) report.Dataset {
	return report.Dataset{
		ID:     id,
		Base:   report.Relation{Table: report.Ident(tables[0])},
		RowKey: report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{{ID: "t", Table: report.Ident(tables[0]), Mode: report.RowAnchor,
			Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}},
		Columns:   []report.Column{{ID: "guid", Label: "GUID", Type: report.TypeGUID, Source: report.Attr{Col: "object_guid"}}},
		Freshness: report.FreshNCWatermark,
		Tables:    tables,
	}
}

func datasets(ds ...report.Dataset) func(*module.Registrar) error {
	return func(r *module.Registrar) error {
		for _, d := range ds {
			if err := r.Dataset(d); err != nil {
				return err
			}
		}
		return nil
	}
}

func ownerMap(m map[string]string) module.BootOption {
	return module.WithTableOwners(func(t string) (string, bool) { o, ok := m[t]; return o, ok })
}

// AC 3: a dataset registered over a table owned by another module makes Boot fail, naming the table.
func TestBootFailsForDatasetOverForeignTable(t *testing.T) {
	m := &fake{id: "reports", register: datasets(dataset("reports.runs", "report_runs", "directory_objects"))}
	_, err := moduletest.Register(m, ownerMap(map[string]string{"report_runs": "reports", "directory_objects": "inventory"}))
	var te *report.TableOwnershipError
	if !errors.As(err, &te) || te.Table != "directory_objects" || te.Actual != "inventory" || te.Owner != "reports" {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, report.ErrTableOwnership) || !strings.Contains(err.Error(), `"directory_objects"`) {
		t.Fatalf("error does not name the table: %v", err)
	}
	// Through Boot itself, with other modules before it: still no partial result.
	ok := &fake{id: "other", register: actions()}
	c, err := module.Boot(context.Background(), []module.Entry{{ID: "other", Module: ok}, {ID: "reports", Module: m}}, capability.NewSet(),
		ownerMap(map[string]string{"report_runs": "reports", "directory_objects": "inventory"}))
	if err == nil || c != nil {
		t.Fatalf("Boot = %v, %v", c, err)
	}
}

func TestBootFailsForUnownedTableAndWithNoMap(t *testing.T) {
	m := &fake{id: "reports", register: datasets(dataset("reports.runs", "report_runs"))}
	if _, err := moduletest.Register(m, ownerMap(map[string]string{})); !errors.Is(err, report.ErrTableOwnership) {
		t.Fatalf("unowned table: %v", err)
	}
}

// T-0997 AC 2, against the generated map (store/owners, from the migrations) that Boot uses by default:
// a module registering a dataset over a table it owns passes CheckTables; over a foreign table, or one no
// migration creates, it still fails and names the table.
func TestBootWithGeneratedOwnershipMap(t *testing.T) {
	own := &fake{id: "reports", register: datasets(dataset("reports.runs", "report_runs", "report_run_rows"))}
	if _, err := moduletest.Register(own); err != nil {
		t.Fatalf("a dataset over the tables reports owns: %v", err)
	}
	for table, actual := range map[string]string{"directory_objects": "inventory", "authn_accounts": "authn"} {
		foreign := &fake{id: "reports", register: datasets(dataset("reports.runs", "report_runs", table))}
		_, err := moduletest.Register(foreign)
		var te *report.TableOwnershipError
		if !errors.As(err, &te) || te.Table != table || te.Actual != actual || te.Owner != "reports" {
			t.Fatalf("foreign table %s: %v", table, err)
		}
	}
	missing := &fake{id: "reports", register: datasets(dataset("reports.runs", "report_runs", "no_such_table"))}
	if _, err := moduletest.Register(missing); !errors.Is(err, report.ErrTableOwnership) {
		t.Fatalf("a table no migration creates: %v", err)
	}
}

func TestBootCollectsOwnedDatasets(t *testing.T) {
	m := &fake{id: "reports", register: datasets(dataset("reports.runs", "report_runs"))}
	c, err := moduletest.Register(m, ownerMap(map[string]string{"report_runs": "reports"}))
	if err != nil {
		t.Fatal(err)
	}
	sets := c.Datasets()
	if len(sets) != 1 || sets[0].Owner != "reports" || len(sets[0].Datasets) != 1 || sets[0].Datasets[0].ID != "reports.runs" {
		t.Fatalf("datasets = %+v", sets)
	}
}

func TestRegistrarDatasetRules(t *testing.T) {
	owners := ownerMap(map[string]string{"report_runs": "reports"})
	for name, tc := range map[string]struct {
		reg  func(*module.Registrar) error
		want error
	}{
		"outside the namespace": {datasets(dataset("inventory.users", "report_runs")), module.ErrNamespace},
		"duplicate":             {datasets(dataset("reports.runs", "report_runs"), dataset("reports.runs", "report_runs")), module.ErrDuplicate},
		"invalid structure": {datasets(func() report.Dataset {
			d := dataset("reports.runs", "report_runs")
			d.Anchors = nil
			return d
		}()), module.ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := moduletest.Register(&fake{id: "reports", register: tc.reg}, owners)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
	var zero module.Registrar
	if err := zero.Dataset(dataset("reports.runs", "report_runs")); !errors.Is(err, module.ErrClosed) {
		t.Fatalf("zero registrar: %v", err)
	}
}
