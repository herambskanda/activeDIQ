package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	setupsecret "github.com/skenzeriq/activediq/internal/platform/setup"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// setupStore is the first-run setup store under the API TLS directory (a subdirectory inherits the
// directory's 0700 mode and its Windows ACL). It is nil when the install has no durable directory: that
// is loopback development, which has no installing administrator to hand a secret to.
func setupStore(cfg config.Config, now func() time.Time) (*setupsecret.Store, error) {
	if cfg.APITLSDir == "" {
		return nil, nil
	}
	ttl := cfg.SetupTTL
	if ttl == 0 {
		ttl = config.DefaultSetupTTL
	}
	st, err := setupsecret.New(filepath.Join(cfg.APITLSDir, setupsecret.DirName), ttl, setupsecret.WithClock(now))
	if err != nil {
		return nil, fmt.Errorf("server: first-run setup: %w", err)
	}
	return st, nil
}

// firstOwners creates the first tenant owner for the setup claim: the account, its tenant-owner grant and
// the audit of the claim and of the creation commit in one transaction. The install's single tenant is
// known only after bootstrap, so it is set later; a claim before that is a server fault, not a refusal.
type firstOwners struct {
	db     *store.DB
	audit  audit.Sink
	owners *rbac.OwnerAssignments
	tenant atomic.Pointer[tenant.ID]
	now    func() time.Time
}

var _ setupsecret.OwnerCreator = (*firstOwners)(nil)

func newFirstOwners(db *store.DB, sink audit.Sink, owners *rbac.OwnerAssignments) (*firstOwners, error) {
	if db == nil || sink == nil || owners == nil {
		return nil, errors.New("server: first-run owner needs a database, an audit sink and the owner writer")
	}
	return &firstOwners{db: db, audit: sink, owners: owners, now: time.Now}, nil
}

// SetTenant tells the creator which tenant the install has.
func (f *firstOwners) SetTenant(t tenant.ID) { f.tenant.Store(&t) }

// setupActor is who the audit names for the claim: the setup gate itself, not a person (none exists yet).
var setupActor = authority.Chain{Requester: authority.Principal{ID: "setup-claim", Kind: authority.System}}

// CreateFirstOwner implements setupsecret.OwnerCreator.
func (f *firstOwners) CreateFirstOwner(ctx context.Context, owner setupsecret.OwnerDetails, sourceIP string) error {
	tp := f.tenant.Load()
	if tp == nil {
		return errors.New("server: first-run owner: the install's tenant is not ready")
	}
	t := *tp
	return f.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		// The owner lock first: two claims, or a claim and any other owner writer, are serialised.
		held, err := rbac.Owners{}.TenantOwners(ctx, tx, t)
		if err != nil {
			return err
		}
		if len(held) > 0 {
			return setupsecret.ErrOwnerExists
		}
		acct, err := authn.CreateIn(ctx, tx, authn.NewAccount{
			Tenant: t, Kind: authn.KindLocal, DisplayName: owner.DisplayName, Email: owner.Email, CreatedBy: "system",
		})
		if err != nil {
			return fmt.Errorf("server: first-run owner account: %w", err)
		}
		assignment, err := f.owners.GrantIn(ctx, tx, t, acct.ID, setupActor)
		if err != nil {
			return fmt.Errorf("server: first-run owner grant: %w", err)
		}
		at := f.now().UTC()
		common := []audit.Detail{ // strictly increasing key order
			{Key: "install_id", Value: t.String()},
			{Key: "source_ip", Value: sourceIP},
		}
		claimed := audit.Event{
			ID: "setup.claimed." + t.String(), Kind: KindSetupClaimed, At: at, Actor: setupActor,
			Target:    authority.TargetRef{GUID: t.String(), Class: "install"},
			Component: "setup", Outcome: audit.Success, Reason: "claimed", Details: common,
		}
		created := audit.Event{
			ID: "setup.owner_created." + acct.ID, Kind: KindSetupOwnerCreated, At: at.Add(time.Microsecond), Actor: setupActor,
			Target:    authority.TargetRef{GUID: acct.ID, Class: "account"},
			Component: "setup", Outcome: audit.Success, Reason: "created",
			Details: append([]audit.Detail{{Key: "assignment", Value: assignment}}, common...),
		}
		for _, ev := range []audit.Event{claimed, created} {
			if err := f.audit.Append(ctx, tx, ev); err != nil {
				return fmt.Errorf("server: first-run owner audit: %w", err)
			}
		}
		return nil
	})
}

// Audit kinds of the first-run claim. Details carry the install id and the source address, never the
// secret.
const (
	KindSetupClaimed      audit.Kind = "setup.claimed"
	KindSetupOwnerCreated audit.Kind = "setup.owner_created"
)

// buildSetup issues the one-time setup secret on an unclaimed install and returns the claim route. The
// secret is never logged: the log names the file the administrator reads it from and when it expires.
func buildSetup(cfg config.Config, now func() time.Time, owners setupsecret.OwnerCreator) ([]apihost.TagHandlers, error) {
	st, err := setupStore(cfg, now)
	if err != nil || st == nil {
		return nil, err
	}
	if owners == nil {
		return nil, errors.New("server: first-run setup needs an owner creator")
	}
	issued, exp, err := st.Issue()
	switch {
	case errors.Is(err, setupsecret.ErrAlreadyClaimed):
		slog.Info("server: first-run setup was already claimed")
	case err != nil:
		return nil, fmt.Errorf("server: first-run setup: %w", err)
	case issued:
		slog.Info("server: first-run setup secret issued; read it as the installing administrator with `activediq-server setup show`",
			"file", st.SecretPath(), "expires", exp.UTC().Format(time.RFC3339))
	default:
		slog.Info("server: first-run setup secret still valid", "expires", exp.UTC().Format(time.RFC3339))
	}
	// The route is mounted even when claimed: it answers the same refusal as for a wrong secret.
	return []apihost.TagHandlers{setupsecret.Handlers{Store: st, Owners: owners}.Bind()}, nil
}

// SetupShow is `activediq-server setup show`: it prints the setup secret to out for the installing
// administrator. It reads the file with the operating system's own access control, so anyone but the
// service account and administrators gets a permission error, not the secret.
func SetupShow(getenv func(string) string, out io.Writer) error {
	dir := getenv(config.EnvAPITLSDir)
	if dir == "" {
		return fmt.Errorf("%s is not set: the setup secret lives under the API TLS directory", config.EnvAPITLSDir)
	}
	b, err := os.ReadFile(filepath.Join(dir, setupsecret.DirName, setupsecret.SecretFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return errors.New("there is no setup secret: setup was already claimed, or the server has not started on this install")
	case err != nil:
		return fmt.Errorf("cannot read the setup secret: %w", err)
	}
	_, err = out.Write(b)
	return err
}
