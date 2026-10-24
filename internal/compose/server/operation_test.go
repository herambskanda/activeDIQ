package server

import (
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/operation"
)

func TestBuildOperationRefusesWithoutMinter(t *testing.T) {
	reg, _ := operation.NewRegistry()
	_, err := buildOperation(func() bool { return false }, nil, directoryFacts(), denyAuthorizer{}, reg)
	if !errors.Is(err, ErrNoMinter) {
		t.Fatalf("err = %v, want ErrNoMinter", err)
	}
}

func TestBuildOperationRefusesWithoutFacts(t *testing.T) {
	reg, _ := operation.NewRegistry()
	_, err := buildOperation(operation.HoldsMinter, nil, nil, denyAuthorizer{}, reg)
	if !errors.Is(err, ErrNoFacts) {
		t.Fatalf("err = %v, want ErrNoFacts", err)
	}
}

func TestRealMinterIsHeld(t *testing.T) {
	if !operation.HoldsMinter() {
		t.Fatal("operation does not hold the minter")
	}
}
