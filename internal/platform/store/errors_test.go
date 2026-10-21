package store

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestErrorClassifiers(t *testing.T) {
	if !IsNoRows(fmt.Errorf("wrapped: %w", pgx.ErrNoRows)) || IsNoRows(errors.New("other")) || IsNoRows(nil) {
		t.Fatal("IsNoRows must match pgx.ErrNoRows through wrapping and nothing else")
	}
	if got := SQLState(fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "AD403", Message: "secret detail"})); got != "AD403" {
		t.Fatalf("SQLState = %q, want AD403", got)
	}
	if SQLState(errors.New("plain")) != "" || SQLState(nil) != "" {
		t.Fatal("SQLState must be empty for a non-database error")
	}
}
