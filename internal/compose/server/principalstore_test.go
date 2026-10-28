package server

import (
	"context"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/limiter"
)

func twoNodeMemory() config.Config {
	return config.Config{DatabaseDSN: "postgres://unused", APIBodyBudget: config.DefaultAPIBodyBudget,
		APIAddr: "127.0.0.1:0", Nodes: 2, PrincipalStore: config.PrincipalStoreMemory}
}

// T-0274 acceptance 3: with more than one node and the in-memory store, the server refuses to start,
// before it opens the database (the DSN here is unusable, so reaching it would give another error).
func TestRunRefusesMemoryStoreOnMultipleNodes(t *testing.T) {
	useKEKEnv(t)
	err := Run(context.Background(), twoNodeMemory())
	if err == nil || !strings.Contains(err.Error(), config.EnvPrincipalStore) {
		t.Fatalf("Run = %v, want the principal-store refusal", err)
	}
}

func TestPrincipalStoreSelection(t *testing.T) {
	one := twoNodeMemory()
	one.Nodes = 1
	ps, err := principalStore(one, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ps.(*limiter.MemoryStore); !ok {
		t.Fatalf("memory on one node gave %T", ps)
	}
	if _, err := principalStore(twoNodeMemory(), nil); err == nil {
		t.Fatal("memory on two nodes accepted")
	}
	pg := twoNodeMemory()
	pg.PrincipalStore = config.PrincipalStorePostgres
	if _, err := principalStore(pg, nil); err == nil {
		t.Fatal("postgres store without a database accepted")
	}
	bad := twoNodeMemory()
	bad.Nodes = 0
	if _, err := principalStore(bad, nil); err == nil {
		t.Fatal("zero nodes accepted")
	}
}
