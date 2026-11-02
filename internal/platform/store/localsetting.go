package store

import (
	"context"
	"fmt"
	"strconv"
)

// TrigramThreshold bounds pg_trgm.word_similarity_threshold: below 0.1 a fuzzy probe matches nearly
// every key, above 1 nothing can match.
const (
	MinTrigramThreshold = 0.1
	MaxTrigramThreshold = 1.0
)

// SetTrigramThreshold sets pg_trgm.word_similarity_threshold for the transaction tx runs in (it is
// transaction-local, so it ends with it) and returns a function that puts the earlier value back for
// whatever else the caller runs. It is the one place the setting is written (search rule SE2); the value
// is a bound parameter. A threshold outside the bounds is refused before any SQL runs.
func SetTrigramThreshold(ctx context.Context, tx Tx, threshold float64) (restore func(), err error) {
	if !(threshold >= MinTrigramThreshold && threshold <= MaxTrigramThreshold) {
		return nil, fmt.Errorf("store: trigram threshold %v outside %v..%v", threshold, MinTrigramThreshold, MaxTrigramThreshold)
	}
	var prior string
	if err := tx.QueryRow(ctx, `SELECT current_setting('pg_trgm.word_similarity_threshold')`).Scan(&prior); err != nil {
		return nil, fmt.Errorf("store: read trigram threshold: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)`, trigramThresholdText(threshold)); err != nil {
		return nil, fmt.Errorf("store: set trigram threshold: %w", err)
	}
	return func() {
		// Best effort: a failed transaction is rolled back by the caller and the setting goes with it.
		_, _ = tx.Exec(ctx, `SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)`, prior)
	}, nil
}

func trigramThresholdText(threshold float64) string {
	return strconv.FormatFloat(threshold, 'f', 3, 64)
}

// TrigramThresholdValue is the double precision value that SetTrigramThreshold leaves in
// pg_trgm.word_similarity_threshold for threshold: the number the fuzzy candidate bound of the search
// template must compare with, so the bound and the <% recheck use one threshold (ADR-0011 rule 5a).
func TrigramThresholdValue(threshold float64) float64 {
	v, err := strconv.ParseFloat(trigramThresholdText(threshold), 64)
	if err != nil {
		return threshold
	}
	return v
}
