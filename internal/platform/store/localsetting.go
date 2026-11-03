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

// defaultTrigramThreshold is pg_trgm's own default, put back when the backend had no value to return to.
const defaultTrigramThreshold = "0.6"

// SetTrigramThreshold sets pg_trgm.word_similarity_threshold for the transaction tx runs in (it is
// transaction-local, so it ends with it) and returns a function that puts the earlier value back for
// whatever else the caller runs. It is the one place the setting is written (search rule SE2); the value
// is a bound parameter. A threshold outside the bounds is refused before any SQL runs.
func SetTrigramThreshold(ctx context.Context, tx Tx, threshold float64) (restore func(), err error) {
	if !(threshold >= MinTrigramThreshold && threshold <= MaxTrigramThreshold) {
		return nil, fmt.Errorf("store: trigram threshold %v outside %v..%v", threshold, MinTrigramThreshold, MaxTrigramThreshold)
	}
	// missing_ok: a backend that has not yet run a pg_trgm operator does not know the setting and,
	// without the flag, raises 42704 before the connection can ever warm itself.
	var prior string
	if err := tx.QueryRow(ctx, `SELECT coalesce(current_setting('pg_trgm.word_similarity_threshold', true), '')`).Scan(&prior); err != nil {
		return nil, fmt.Errorf("store: read trigram threshold: %w", err)
	}
	if prior == "" {
		prior = defaultTrigramThreshold
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)`, strconv.FormatFloat(threshold, 'f', 3, 64)); err != nil {
		return nil, fmt.Errorf("store: set trigram threshold: %w", err)
	}
	return func() {
		// Best effort: a failed transaction is rolled back by the caller and the setting goes with it.
		_, _ = tx.Exec(ctx, `SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)`, prior)
	}, nil
}
