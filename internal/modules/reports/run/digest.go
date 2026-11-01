package run

import (
	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// typed is a stored row's cells in canonical form for export.Digester, the one implementation of the
// digest of spec §8.3 (B9).
func typed(cells []report.Cell) []export.Typed {
	out := make([]export.Typed, len(cells))
	for i, c := range cells {
		out[i] = export.Typed{Tag: c.DigestTag(), Value: c.DigestValue()}
	}
	return out
}
