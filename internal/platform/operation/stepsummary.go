package operation

import (
	"context"
	"encoding/json/v2"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// gateSampleSteps bounds how many steps a gate sees of a chunked plan. The gate decides on the Action,
// the counts and the worst reversibility; a sample is for display, so routing memory does not grow with
// the number of items (T-2073 AC3).
const gateSampleSteps = 100

// stepSummary is the bounded view of a persisted plan that routing and approval need.
type stepSummary struct {
	Items     int
	Worst     Reversibility
	Sample    []StepPlan
	Truncated bool
}

// summariseSteps reads the item count and worst reversibility by aggregate query and loads at most
// gateSampleSteps steps. A plan that was not planned in chunks is bounded by the inline threshold and is
// loaded whole, so its gate contract is unchanged.
func summariseSteps(ctx context.Context, tx store.Tx, t tenant.ID, op string) (stepSummary, error) {
	var chunked bool
	if err := tx.QueryRow(ctx, `SELECT plan_items IS NOT NULL FROM public.operations WHERE tenant_id = $1::uuid AND id = $2::uuid`,
		t.String(), op).Scan(&chunked); err != nil {
		return stepSummary{}, fmt.Errorf("operation: reading plan shape: %w", err)
	}
	if !chunked {
		rows, err := loadSteps(ctx, tx, t, op)
		if err != nil {
			return stepSummary{}, err
		}
		steps := make([]StepPlan, len(rows))
		for i, sr := range rows {
			steps[i] = sr.Plan
		}
		return stepSummary{Items: len(steps), Worst: worst(steps), Sample: steps}, nil
	}
	var s stepSummary
	var w string
	// Reversibility ranks: reversible < lossy < irreversible (Reversibility.rank).
	if err := tx.QueryRow(ctx, `SELECT count(*), COALESCE(max(CASE plan->>'Reversibility'
    WHEN 'irreversible' THEN 3 WHEN 'lossy' THEN 2 WHEN 'reversible' THEN 1 ELSE 0 END), 0)::text
FROM public.operation_steps WHERE tenant_id = $1::uuid AND operation_id = $2::uuid`, t.String(), op).Scan(&s.Items, &w); err != nil {
		return stepSummary{}, fmt.Errorf("operation: summarising steps: %w", err)
	}
	s.Worst = Reversible
	switch w {
	case "3":
		s.Worst = Irreversible
	case "2":
		s.Worst = Lossy
	}
	rows, err := tx.Query(ctx, `SELECT plan FROM public.operation_steps WHERE tenant_id = $1::uuid AND operation_id = $2::uuid
ORDER BY item_no, step_no LIMIT $3`, t.String(), op, gateSampleSteps)
	if err != nil {
		return stepSummary{}, fmt.Errorf("operation: sampling steps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var sp StepPlan
		if err := rows.Scan(&raw); err != nil {
			return stepSummary{}, err
		}
		if err := json.Unmarshal(raw, &sp); err != nil {
			return stepSummary{}, fmt.Errorf("operation: corrupt plan: %w", err)
		}
		s.Sample = append(s.Sample, sp)
	}
	s.Truncated = s.Items > len(s.Sample)
	return s, rows.Err()
}
