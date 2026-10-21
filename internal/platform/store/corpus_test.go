package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// TestCorpus runs the shared sql corpus (testdata/safe-primitives/sql.jsonl, FF-SP4) against the store
// code that exists today: tenant.Parse (SQL-03), Open's simple-protocol refusal (SQL-20) and the
// transport policy (SQL-23, SQL-24). Every refusal happens before a connection is attempted; the
// handler bounds Open with a short deadline so a weakened check fails instead of hanging.
func TestCorpus(t *testing.T) {
	ca := writeCA(t)
	corpustest.Run(t, "go/sql", "sql", func(r corpus.Record) (corpus.Result, error) {
		switch r.Call {
		case "tenant.Parse":
			in, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			id, err := tenant.Parse(in.Text())
			if err == nil {
				return corpustest.Value(map[string]string{"parsed": id.String()})
			}
			if errors.Is(err, tenant.ErrInvalidID) && id.IsZero() && !strings.Contains(err.Error(), in.Text()) {
				return corpustest.Err("InvalidID"), nil
			}
			return corpustest.Err("Unexpected"), nil
		case "Open":
			dsn, err := r.Arg("dsn")
			if err != nil {
				return corpus.Result{}, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			db, err := Open(ctx, Config{DSN: dsn.Text()})
			if err == nil {
				db.pool.Close()
				return corpustest.Value(map[string]bool{"accepted": true})
			}
			if errors.Is(err, ErrSimpleProtocolForbidden) && db == nil {
				return corpustest.Err("SimpleProtocolForbidden"), nil
			}
			return corpustest.Err("Unexpected"), nil
		case "CheckTransport":
			dsn, err := r.Arg("dsn")
			if err != nil {
				return corpus.Result{}, err
			}
			clearPGEnv(t)
			if _, ok := r.Args["env"]; ok {
				env, err := r.Arg("env")
				if err != nil {
					return corpus.Result{}, err
				}
				k, v, ok := strings.Cut(env.Text(), "=")
				if !ok {
					return corpus.Result{}, errors.New("env must be NAME=value")
				}
				t.Setenv(k, v)
			}
			st, err := CheckTransport(strings.ReplaceAll(dsn.Text(), "{CA}", ca), false)
			if err != nil {
				var te *TransportError
				if errors.Is(err, ErrInsecureTransport) && errors.As(err, &te) {
					if strings.Contains(err.Error(), "s3cret") {
						return corpustest.Err("PasswordInMessage"), nil
					}
					return corpustest.Err("InsecureTransport"), nil
				}
				return corpustest.Err("Unexpected"), nil
			}
			relaxed := st.RelaxedHosts
			if relaxed == nil {
				relaxed = []string{}
			}
			return corpustest.Value(map[string]any{"accepted": true, "relaxed": relaxed})
		}
		return corpus.Result{}, errors.New("unknown call " + r.Call)
	})
}

// FuzzSQL fuzzes the two parsers that take outside text: tenant.Parse (accepted text round-trips to the
// canonical form and nothing else is accepted) and the transport policy (without the operator override
// an accepted DSN never reports a relaxed host). DSNs that make pgx read files are skipped: the target
// must not open arbitrary paths.
func FuzzSQL(f *testing.F) {
	corpustest.Seed(f, "sql")
	f.Fuzz(func(t *testing.T, in []byte) {
		s := string(in)
		if id, err := tenant.Parse(s); err == nil {
			canon := id.String()
			id2, err := tenant.Parse(canon)
			if err != nil || id2 != id || !strings.EqualFold(canon, s) || len(canon) != 36 {
				t.Fatalf("Parse(%q) = %v; round trip gave %v, %v", s, canon, id2, err)
			}
		}
		low := strings.ToLower(s)
		for _, k := range []string{"sslrootcert", "sslcert", "sslkey", "passfile", "service", "sslpassword"} {
			if strings.Contains(low, k) {
				return
			}
		}
		clearPGEnv(t)
		if st, err := CheckTransport(s, false); err == nil && st.Insecure() {
			t.Fatalf("CheckTransport(%q, false) accepted with relaxed hosts %v", s, st.RelaxedHosts)
		}
	})
}
