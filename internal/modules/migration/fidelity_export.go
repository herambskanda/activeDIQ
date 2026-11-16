package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/export"
	exportcsv "github.com/skenzeriq/activediq/internal/platform/export/csv"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// fidelityColumns are the columns of the sign-off CSV (MIG-03).
var fidelityColumns = []export.Column{{Label: "Item"}, {Label: "Kind"}, {Label: "Name"}, {Label: "Class"},
	{Label: "Reason"}, {Label: "Differences"}, {Label: "Text"}, {Label: "Proposal"}}

// ExportFidelityCSV writes the fidelity report of a job as CSV through the shared encoder (T-0150), so
// every cell is neutralised and bounded there; the report's text is data. The caller must hold
// migration.import (deny by default: a Service without Authz refuses).
func (s *Service) ExportFidelityCSV(ctx context.Context, t tenant.ID, actor authority.Chain, jobID string, w io.Writer) (export.RenderReport, error) {
	if s.Authz == nil {
		return export.RenderReport{}, ErrDenied
	}
	ref := authority.TargetRef{GUID: jobID, Class: TargetClassJob}
	if err := s.Authz.Authorize(ctx, actor, PermImport, ref, authority.Facts{}); err != nil {
		return export.RenderReport{}, fmt.Errorf("%w: %s", ErrDenied, PermImport)
	}
	if !uuidRe.MatchString(jobID) {
		return export.RenderReport{}, fmt.Errorf("%w: job id malformed", ErrInvalid)
	}
	enc, err := exportcsv.NewWriter(w, exportcsv.Options{})
	if err != nil {
		return export.RenderReport{}, err
	}
	err = s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		_, found, err := getJob(ctx, tx, jobID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNoSuchJob
		}
		if err := enc.Header(fidelityColumns); err != nil {
			return err
		}
		return listFidelity(ctx, tx, jobID, func(r FidelityRow) error {
			return enc.Row(rowCells(r))
		})
	})
	if err != nil {
		return export.RenderReport{}, err
	}
	return enc.Close()
}

func rowCells(r FidelityRow) []export.Cell {
	prop := "no"
	if r.HasProposal {
		prop = "yes"
	}
	var diffs []string
	for _, d := range r.Diff {
		b, _ := json.Marshal(d.Field)
		diffs = append(diffs, strings.TrimSpace(string(b))+": "+d.Source+" -> "+d.Ours)
	}
	return []export.Cell{export.Text(r.Ref), export.Text(r.Kind), export.Text(r.Name), export.Text(r.Class),
		export.Text(r.Reason), export.Multi(diffs...), export.Text(r.Detail), export.Text(prop)}
}
