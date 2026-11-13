//go:build lab

package replstatus_test

import (
	"bufio"
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/replstatus"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1723 on Samba: `make lab-up && go test -tags lab ./internal/connector/replstatus -run TestLab`.
// CC-REPL-01 and -02 against a real single-DC Samba. Samba's answers are expected to be partial
// (spec §7.3.1 [UNVERIFIED]); this test asserts the shape, records what Samba returned, and proves
// nothing about Windows values (CC-REPL-04..06 are the [LAB: Windows] follow-up under T-1510). The
// two-DC / stopped-DC run (CC-REPL-03) needs the two-DC lab and is the fault-injected case in
// handler_test.go until that lab exists.

type sink struct {
	ms []*connectorv1.ReadReplicationStatusResponse
}

func (s *sink) Send(m *connectorv1.ReadReplicationStatusResponse) error {
	s.ms = append(s.ms, m)
	return nil
}

func labEnv(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "lab", ".lab.env"))
	if err != nil {
		t.Fatalf("lab not up (make lab-up): %v", err)
	}
	defer f.Close()
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			env[k] = strings.Trim(v, `"'`)
		}
	}
	return env
}

func TestLabReadReplicationStatusSingleDC(t *testing.T) {
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + env["LAB_LDAPS_PORT"]}, RootCAs: pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))}})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	rd, err := sess.RootDSE(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("vendorName=%q samba=%v (capability row: %v)", rd.VendorName, rd.IsSamba(), replstatus.Capability(1, rd.IsSamba()).State)

	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: "lab"}}
	h, err := replstatus.New(&replstatus.Bound{Sess: sess, Ident: ident})
	if err != nil {
		t.Fatal(err)
	}
	out := &sink{}
	err = h.ReadReplicationStatus(ctx, &connectorv1.ReadReplicationStatusRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: "lab", DirectoryIdentity: ident},
		Scope:      connectorv1.PerDcScope_PER_DC_SCOPE_ALL,
	}, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.ms) != 2 || out.ms[0].GetResult() == nil || out.ms[1].GetSummary() == nil {
		t.Fatalf("stream shape: %v", out.ms)
	}
	sum := out.ms[1].GetSummary()
	if sum.DcsInScope != 1 || sum.DcsAnswered != 1 || sum.Coverage != connectorv1.Coverage_COVERAGE_COMPLETE {
		t.Fatalf("summary %v", sum)
	}
	st := out.ms[0].GetResult().GetState()
	if st == nil || len(st.Attributes) != 4 {
		t.Fatalf("result %v", out.ms[0])
	}
	for _, o := range st.Attributes {
		t.Logf("%v: %v %q", o.Attribute, o.Kind, o.DetailCode)
		switch o.Kind {
		case connectorv1.OutcomeKind_NOT_RETURNED, connectorv1.OutcomeKind_PERMISSION_DENIED:
		case connectorv1.OutcomeKind_RETURNED:
		case connectorv1.OutcomeKind_DECODE_FAILED:
			t.Logf("Samba text refused with a fixed code - capture it for the decoder tests")
		default:
			t.Errorf("attribute %v has no outcome kind", o.Attribute)
		}
	}
	// CC-REPL-02: never a RETURNED attribute that produced nothing.
	got := map[connectorv1.ReplicationAttribute]int{
		connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_INBOUND_NEIGHBORS:   len(st.Neighbors),
		connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_PENDING_OPS:         len(st.PendingOps),
		connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_CONNECTION_FAILURES: len(st.ConnectionFailures),
		connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_LINK_FAILURES:       len(st.LinkFailures),
	}
	for _, o := range st.Attributes {
		if o.Kind == connectorv1.OutcomeKind_RETURNED && got[o.Attribute] == 0 {
			t.Errorf("%v is RETURNED with an empty list", o.Attribute)
		}
	}
}
