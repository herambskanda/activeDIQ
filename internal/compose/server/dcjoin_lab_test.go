//go:build lab

package server

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	modad "github.com/skenzeriq/activediq/internal/modules/ad"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1636 AC1 (ADM-134 "Impersonate as Admin", impersonate-as-admin-attribution.md §5-6): a technician
// resets a user password through the real runner, the real ad module Action, the real client.Write and the
// real connector write handler over LDAPS to the Samba lab. The DC log must name only the bound service
// account, never the technician, and the step audit event must carry the technician as Requester plus
// the dc and credential_id that join it to the DC log.
//
//	make lab-up && go test -tags lab ./internal/compose/server -run TestLabDCLogJoin
//
// What is real: Postgres, runner, audit chain, rbac authorizer, Action, write client, write handler and
// guard, the LDAPS session and the DC. What is not: the Tier0Context builder is a stub (a "no hybrid
// link" statement for the target; the real builder has its own tests) and the AccountReader is a lab
// adapter over ReadAccount, because no production AccountReader exists yet (T-2303).
// Samba's `DSDB Change` line is not a Windows 4738/5136 event; AC2 is the Windows lab (T-2304).

// labAccounts is a client.AccountReader over the lab session.
type labAccounts struct{ sess *ad.Session }

func (l labAccounts) Account(ctx context.Context, _ authority.Pins, target authority.TargetRef) (client.AccountState, error) {
	g, err := guid.Parse(target.GUID)
	if err != nil {
		return client.AccountState{}, err
	}
	st, err := l.sess.ReadAccount(ctx, dn.GUIDRef(g))
	if err != nil {
		return client.AccountState{}, err
	}
	class := ""
	for _, c := range st.Classes {
		switch strings.ToLower(c) {
		case "computer":
			class = "computer"
		case "user":
			if class == "" {
				class = "user"
			}
		}
	}
	return client.AccountState{Exists: true, Class: class, UserAccountControl: strconv.Itoa(int(st.UAC)),
		LockoutTime: strconv.FormatInt(st.LockoutTime, 10), PwdLastSet: strconv.FormatInt(st.PwdLastSet, 10)}, nil
}

// handlerTransport is client.Transport over the in-process connector write handler. Like the read
// transport, it stamps the connection's directory identity on the request: client.Write sends only the
// connection ID, and no production write transport exists yet to add it (T-2303).
type handlerTransport struct {
	h     *write.Handler
	ident *connectorv1.DirectoryIdentity
}

func (t handlerTransport) Plan(ctx context.Context, q *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	q.Connection.DirectoryIdentity = t.ident
	return t.h.Plan(ctx, q)
}

func (t handlerTransport) Apply(ctx context.Context, q *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	q.Connection.DirectoryIdentity = t.ident
	return t.h.Apply(ctx, q)
}

// noLinkTier0 is the stub Tier0 builder: one "no hybrid link" statement for the write's target.
type noLinkTier0 struct{}

func (noLinkTier0) Build(_ context.Context, _ client.Stage, op client.WriteOp) (client.Tier0, error) {
	g, err := guid.Parse(op.Target.GUID)
	if err != nil {
		return client.Tier0{}, err
	}
	return client.Tier0{Context: &connectorv1.Tier0Context{Tier0Revision: 1, Statements: []*connectorv1.CorrelationStatement{{
		Object: write.GUIDToWire(g), ComputedAt: timestamppb.Now(),
		Correlation: &connectorv1.CorrelationStatement_NoHybridLink{NoHybridLink: &connectorv1.NoHybridLink{}}}}}}, nil
}

// logRecorder prints the connector's write events (identifiers and reasons only, by contract).
type logRecorder struct{ t *testing.T }

func (l logRecorder) Record(e write.Event) { l.t.Logf("connector event: %+v", e) }

// logWriter prints the error of a refused write (the client's errors carry no plan value, by contract).
type logWriter struct {
	client.AccountWriter
	t *testing.T
}

func (l logWriter) Write(ctx context.Context, s step.Step, op client.WriteOp) (client.Result, error) {
	res, err := l.AccountWriter.Write(ctx, s, op)
	if err != nil {
		l.t.Logf("write error: %v", err)
	}
	return res, err
}

type allowDynamic struct{}

func (allowDynamic) CheckPropertyWrite(context.Context, tier0.PropertyWrite) (tier0.DynamicRuleRefusal, error) {
	return tier0.DynamicRuleRefusal{}, nil
}

func dockerExec(t *testing.T, container string, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", container}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// newPassword is the value the technician sets; it must appear nowhere in the DC log.
const newPassword = "Lab-Reset-Pw-9x!Aq"

var sidRE = regexp.MustCompile(`S-1-5-21(?:-\d+){4}`)

func TestLabDCLogJoin(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		var gate *write.GateBook
		r := newLabRigWith(t, s, func(t *testing.T, p labParts) []operation.Action {
			var err error
			gate, err = write.NewGateBook(labBaseline{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			p.prov.Dynamic = allowDynamic{}
			h, err := write.New(p.prov, gate, write.WithRecorder(logRecorder{t}))
			if err != nil {
				t.Fatal(err)
			}
			cl := client.New(client.WithTransport(handlerTransport{h, p.prov.Identity()}), client.WithTier0Builder(noLinkTier0{}),
				client.WithFacts(client.NewConnectorFacts(p.reads)))
			as, err := modad.Actions(labAccounts{p.sess}, logWriter{cl, t})
			if err != nil {
				t.Fatal(err)
			}
			return as
		})
		ctx, cancel := context.WithTimeout(r.ctx, 4*time.Minute)
		defer cancel()
		pass := write.Run{VerificationID: make([]byte, 16), CompletedAt: time.Now(), Verdict: connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS,
			Checks: map[connectorv1.VerificationCheck]connectorv1.CheckOutcome{
				connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE:   connectorv1.CheckOutcome_CHECK_OUTCOME_PASS,
				connectorv1.VerificationCheck_VERIFICATION_CHECK_V8_READ_SUFFICIENCY: connectorv1.CheckOutcome_CHECK_OUTCOME_PASS}}
		gate.Complete(r.e.ad, pass)

		// The technician may disable users in the Kid OU; the service account may write there.
		r.e.exec(t, `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission)
			SELECT $1::uuid, r.id, 'objects.user.disable' FROM public.authz_roles r WHERE r.tenant_id = $1::uuid AND r.role_name = 'helpdesk-operator'`, r.e.ten.String())
		sc := r.le.Container
		svcSID := sidRE.FindString(dockerExec(t, sc, "samba-tool", "user", "show", "svc-activediq", "--attributes=objectSid"))
		if svcSID == "" {
			t.Fatal("service account SID not found")
		}
		kidDN := strings.SplitN(r.plainDN, ",", 2)[1]
		dockerExec(t, sc, "samba-tool", "dsacl", "set", "--objectdn="+kidDN, "--sddl=(A;CIOI;GA;;;"+svcSID+")")
		// dsdb_audit:3 logs failures only; raise it for the run so the success is logged.
		dockerExec(t, sc, "smbcontrol", "all", "debug", "auth_audit:5 dsdb_audit:5 dsdb_password_audit:5")
		t.Cleanup(func() {
			_, _ = exec.Command("docker", "exec", sc, "smbcontrol", "all", "debug", "auth_audit:3 dsdb_audit:3 dsdb_password_audit:3").CombinedOutput()
		})
		const logPath = "/var/log/samba/log.samba"
		off, err := strconv.Atoi(strings.Fields(dockerExec(t, sc, "wc", "-c", logPath))[0])
		if err != nil {
			t.Fatal(err)
		}

		pre, _ := labAccounts{r.sess}.Account(ctx, nil, authority.TargetRef{GUID: r.plain})
		sub, err := r.runner.SubmitDirectory(ctx, operation.Request{Tenant: r.e.ten, Action: modad.ResetPasswordID, Actor: r.human(), FreshStepUp: true,
			Secrets: map[int]secret.Secret{0: secret.FromBytes([]byte(newPassword))},
			Input:   operation.Input(fmt.Sprintf(`{"connectionId":%q,"objectGuid":%q,"namingContext":%q}`, r.e.ad, r.plain, r.nc))})
		if err != nil || sub.Planned != 1 || sub.Blocked != 0 {
			t.Fatalf("submit: %+v, %v (item reason %q)", sub, err, itemReason(t, r.e, sub.Operation))
		}
		w, err := jobs.NewWorker(r.e.db, r.jr, jobs.WorkerConfig{PollMin: 20 * time.Millisecond, PollMax: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		wctx, stop := context.WithCancel(ctx)
		defer stop()
		go func() { _ = w.Run(wctx) }()
		var state string
		for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			st, err := r.runner.StatusOf(ctx, r.e.ten, string(sub.Operation))
			if err != nil {
				t.Fatal(err)
			}
			state = string(st.State)
			if state == "verified" || state == "failed" || state == "applied" {
				break
			}
		}
		stop()
		t.Logf("operation state: %s", state)
		var stState, stReason string
		if err := r.e.db.WithTenant(ctx, r.e.ten, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT state, coalesce(reason,'') FROM public.operation_steps WHERE operation_id = $1::uuid AND item_no = 0 AND step_no = 0`, string(sub.Operation)).Scan(&stState, &stReason)
		}); err != nil {
			t.Fatal(err)
		}
		t.Logf("step: state %s reason %q", stState, stReason)

		// The write happened on the DC.
		acct, err := labAccounts{r.sess}.Account(ctx, nil, authority.TargetRef{GUID: r.plain})
		if err != nil {
			t.Fatal(err)
		}
		if acct.PwdLastSet == pre.PwdLastSet {
			t.Fatalf("pwdLastSet unchanged (%s, operation %s): the write did not reach the DC", acct.PwdLastSet, state)
		}

		// The DC log: only what this run added.
		log := dockerExec(t, sc, "tail", "-c", "+"+strconv.Itoa(off+1), logPath)
		changeLine := ""
		for _, l := range strings.Split(log, "\n") {
			if strings.Contains(l, "DSDB Change") && strings.Contains(l, "Modify") && strings.Contains(l, "unicodePwd") {
				changeLine = l
			}
		}
		if changeLine == "" {
			t.Fatalf("no DSDB Change line for the disable in the DC log:\n%s", log)
		}
		sids := map[string]bool{}
		for _, l := range strings.Split(log, "\n") {
			if strings.Contains(l, "DSDB Change") || strings.Contains(l, "became") {
				for _, m := range sidRE.FindAllString(l, -1) {
					sids[m] = true
				}
			}
		}
		if len(sids) != 1 || !sids[svcSID] {
			t.Errorf("DC log names SIDs %v, want exactly the bound service account %s", sids, svcSID)
		}
		for _, bad := range []string{newPassword, r.helpdsk, strings.ToLower(r.helpdsk), "helpdesk"} {
			if strings.Contains(log, bad) {
				t.Errorf("DC log contains the technician identifier %q", bad)
			}
		}

		// The step audit event joins to it.
		human := authority.Chain{Requester: authority.Principal{ID: "auditor", Kind: authority.Human}}
		b, err := audit.NewExporter(r.cp).Export(ctx, r.e.db, r.e.ten, human, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, ev := range b.Events {
			env, err := chain.ParseEnvelope(ev.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			// The step event is the one of the Action's own audit kind; started and completed are operation-level.
			if env.Operation != string(sub.Operation) || env.Kind != string(modad.AuditPasswordReset) || !env.HasStep || env.Outcome != string(audit.Success) {
				continue
			}
			found = true
			t.Logf("step event %s: requester %s connection %s target %s details %v", env.EventID, env.Requester.ID, env.Connection, env.TargetGUID, env.Details)
			d := map[string]string{}
			for _, x := range env.Details {
				d[x.Key] = x.Value
			}
			if string(env.Requester.ID) != r.helpdsk {
				t.Errorf("event Requester = %q, want the technician %q", env.Requester.ID, r.helpdsk)
			}
			// The pinner's host for the lab DC (labDCs); the DSA GUID half of the pin is on the operation row.
			if d["dc"] != "localhost" {
				t.Errorf("event dc = %q, want the pinned DC host %q", d["dc"], "localhost")
			}
			if want := bkCred; d["credential_id"] != want {
				t.Errorf("event credential_id = %q, want the connection's credential %q", d["credential_id"], want)
			}
			for k, v := range d {
				if strings.Contains(v, svcSID) || strings.Contains(strings.ToLower(v), "svc-activediq") {
					t.Errorf("event detail %s names the bind account: %q", k, v)
				}
			}
			if env.Connection != r.e.ad || env.TargetGUID != r.plain {
				t.Errorf("event connection/target = %q/%q, want %q/%q", env.Connection, env.TargetGUID, r.e.ad, r.plain)
			}
		}
		if !found {
			t.Fatalf("no applied step event for operation %s in the audit export", sub.Operation)
		}
	})
}
