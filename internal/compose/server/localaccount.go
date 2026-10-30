package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/provision"
)

// The first local console account (T-0783). First-run setup creates an owner with no credentials, and a
// console session needs a password (AN-8) and an enrolled TOTP (AN-10), so `activediq-server account
// init-local` creates one account on the host: a local account with a password, a confirmed TOTP
// enrolment, the role "console-directory-reader" (directory.read over the tenant store) and, when the
// tenant has no owner yet, the tenant-owner role. It runs as the service account with the same database
// and key settings as the server, so it is an administrator action on the host, not a network route.

// directoryReaderRole is the custom role the account holds. Its ID is derived from the tenant so a second
// run finds the first one's role.
const directoryReaderRole = "console-directory-reader"

var cliActor = authority.Chain{Requester: authority.Principal{ID: "cli-account-init-local", Kind: authority.System}}

type localAccountDeps struct {
	DB   *store.DB
	Sink audit.Sink
	Keys authn.KeySource
}

// LocalAccountSpec is what the administrator supplies.
type LocalAccountSpec struct {
	Username, DisplayName, Email string
	Password                     secret.Secret
}

// LocalAccount is a created account with its TOTP enrolment still to confirm.
type LocalAccount struct {
	Tenant tenant.ID
	ID     string
	TOTPID string
	Seed   secret.Secret // base32; shown once
}

func roleID(t tenant.ID) string {
	h := sha256.Sum256([]byte("activediq/role/" + directoryReaderRole + "/" + t.String()))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// createLocalAccount makes the account, its password and TOTP enrolment and grants the roles. The account
// stays inactive, so it cannot sign in and its roles are inert, until confirmTOTP succeeds.
func createLocalAccount(ctx context.Context, d localAccountDeps, spec LocalAccountSpec) (LocalAccount, error) {
	res, err := provision.FirstRun(ctx, d.DB, firstRunTenantName) // no initialisers: finds the tenant the server created
	if err != nil {
		return LocalAccount{}, fmt.Errorf("server: find the install's tenant: %w", err)
	}
	t := res.Tenant
	sessions, err := authn.New(authn.Config{DB: d.DB, Audit: d.Sink})
	if err != nil {
		return LocalAccount{}, err
	}
	pending, err := authn.NewPendingStore(d.DB, d.Sink, nil)
	if err != nil {
		return LocalAccount{}, err
	}
	local := &authn.LocalCredentials{DB: d.DB, Sessions: sessions, Pending: pending, Keys: d.Keys, Audit: d.Sink, Tenant: func() (tenant.ID, bool) { return t, true }}
	totp := &authn.Service{Keys: d.Keys, Failures: d.DB}
	owners, err := buildOwnerAssignments(d.DB, d.Sink, sessions)
	if err != nil {
		return LocalAccount{}, err
	}
	name := spec.DisplayName
	if name == "" {
		name = spec.Username
	}
	var out LocalAccount
	out.Tenant = t
	err = d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		acct, err := authn.CreateIn(ctx, tx, authn.NewAccount{Tenant: t, Kind: authn.KindLocal, DisplayName: name, Email: spec.Email, CreatedBy: "system"})
		if err != nil {
			return err
		}
		out.ID = acct.ID
		if err := local.SetPassword(ctx, tx, t, acct.ID, spec.Username, spec.Password, cliActor); err != nil {
			return err
		}
		// Nothing else on a booted server seeds the built-in roles yet; the call is idempotent.
		if err := rbac.SeedBuiltIns(ctx, tx, t); err != nil {
			return fmt.Errorf("server: seed built-in roles: %w", err)
		}
		held, err := rbac.Owners{}.TenantOwners(ctx, tx, t)
		if err != nil {
			return err
		}
		if len(held) == 0 {
			if _, err := owners.GrantIn(ctx, tx, t, acct.ID, cliActor); err != nil {
				return err
			}
		}
		p, err := totp.Enroll(ctx, tx, t, authn.Subject{AccountID: acct.ID}, "activeDIQ "+spec.Username)
		if err != nil {
			return err
		}
		out.TOTPID, out.Seed = p.ID, p.Seed
		return nil
	})
	if err != nil {
		return LocalAccount{}, mapInitErr(err)
	}
	if err := grantDirectoryReader(ctx, d, t, out.ID); err != nil {
		return LocalAccount{}, err
	}
	return out, nil
}

func mapInitErr(err error) error {
	switch {
	case errors.Is(err, authn.ErrUsernameTaken):
		return errors.New("server: that username is already taken")
	case errors.Is(err, authn.ErrWeakPassword):
		return fmt.Errorf("server: the password must have at least %d characters", authn.MinPasswordLength)
	}
	return fmt.Errorf("server: create local account: %w", err)
}

func grantDirectoryReader(ctx context.Context, d localAccountDeps, t tenant.ID, account string) error {
	src, err := rbac.NewStore(d.DB)
	if err != nil {
		return err
	}
	az, err := rbac.New(src)
	if err != nil {
		return err
	}
	g, err := rbac.NewGrants(az)
	if err != nil {
		return err
	}
	rid := roleID(t)
	return d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		// The role is created in its own savepoint-free step: an existing role (a second account) is fine.
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authz_roles WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), rid).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if err := g.CreateRole(ctx, tx, cliActor, rid, directoryReaderRole, rbac.Tier2, []authz.Permission{"directory.read"}); err != nil {
				return fmt.Errorf("server: create role: %w", err)
			}
		}
		var aid string
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&aid); err != nil {
			return err
		}
		return g.GrantBootstrap(ctx, tx, cliActor, rbac.GrantInput{
			ID: aid, RoleID: rid, Subject: rbac.SubjectRef{Kind: rbac.SubjectAccount, Account: account},
			Roots: []rbac.Root{{Kind: rbac.TenantStore, Connection: t.String(), GUID: t.String()}},
		})
	})
}

// confirmTOTP activates the enrolment with the first code from the administrator's authenticator, then
// activates the account. A wrong code leaves the account inactive.
func confirmTOTP(ctx context.Context, d localAccountDeps, la LocalAccount, code string) error {
	totp := &authn.Service{Keys: d.Keys, Failures: d.DB}
	if err := d.DB.WithTenant(ctx, la.Tenant, func(ctx context.Context, tx store.Tx) error {
		return totp.Activate(ctx, tx, la.Tenant, la.TOTPID, code)
	}); err != nil {
		return err
	}
	sessions, err := authn.New(authn.Config{DB: d.DB, Audit: d.Sink})
	if err != nil {
		return err
	}
	accounts, err := authn.NewAccounts(d.DB, sessions, rbac.Owners{})
	if err != nil {
		return err
	}
	if _, err := accounts.SetState(ctx, la.Tenant, la.ID, authn.AccountActive, cliActor); err != nil {
		return fmt.Errorf("server: activate account: %w", err)
	}
	return nil
}

// otpauthURI is the provisioning URI an authenticator app reads (RFC 6238 defaults: SHA-1, 6 digits, 30 s).
func otpauthURI(username string, seed secret.Secret) string {
	var s string
	seed.Expose(func(b []byte) { s = string(b) })
	q := url.Values{"secret": {s}, "issuer": {"activeDIQ"}}
	return "otpauth://totp/" + url.PathEscape("activeDIQ:"+username) + "?" + q.Encode()
}

// LocalAccountInit is `activediq-server account init-local --username U [--display-name N] [--email E]`.
// The password is the first line of stdin (pipe it; it is never an argument or an environment value). The
// TOTP seed is printed once and the first code is read from the next line of stdin.
func LocalAccountInit(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("account init-local", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var spec LocalAccountSpec
	fs.StringVar(&spec.Username, "username", "", "")
	fs.StringVar(&spec.DisplayName, "display-name", "", "")
	fs.StringVar(&spec.Email, "email", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(spec.Username) == "" {
		return errors.New("usage: activediq-server account init-local --username NAME [--display-name TEXT] [--email ADDR]   (password on the first line of stdin)")
	}
	if _, ok := authn.NormaliseUsername(spec.Username); !ok {
		return errors.New("server: the username is empty or too long")
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	if cfg.DatabaseDSN == "" {
		return ErrNoDatabase
	}
	kc, err := LoadKEKConfig(getenv)
	if err != nil {
		return err
	}
	kekp, err := platformKeyProvider(kc)
	if err != nil {
		return fmt.Errorf("server: key provider: %w", err)
	}
	in := bufio.NewReader(stdin)
	pw, err := readPassword(stdin, in, stdout)
	if err != nil {
		return err
	}
	spec.Password = secret.FromBytes(pw)
	defer spec.Password.Destroy()
	db, err := store.Open(ctx, store.Config{DSN: cfg.DatabaseDSN})
	if err != nil {
		return fmt.Errorf("server: open store: %w", err)
	}
	defer db.Close()
	d := localAccountDeps{DB: db, Sink: audit.NewChainer(db), Keys: keys.NewStore(kekp).KeySource()}
	la, err := createLocalAccount(ctx, d, spec)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Account %s created. Add this to your authenticator app (shown once):\n  %s\n  setup key: ", la.ID, otpauthURI(spec.Username, la.Seed))
	la.Seed.Expose(func(b []byte) { _, _ = stdout.Write(b) })
	fmt.Fprint(stdout, "\nEnter the current 6-digit code: ")
	code, _ := in.ReadString('\n')
	if err := confirmTOTP(ctx, d, la, strings.TrimSpace(code)); err != nil {
		return fmt.Errorf("server: the code was not accepted, so the account %s stays inactive and %q cannot sign in: %w", la.ID, spec.Username, err)
	}
	fmt.Fprintln(stdout, "\nAuthenticator confirmed. The account can sign in at /auth/break-glass/password.")
	return nil
}

// readPassword reads the password: without echo when stdin is a terminal, else the first line of the pipe.
func readPassword(stdin io.Reader, in *bufio.Reader, stdout io.Writer) ([]byte, error) {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(stdout, "Password: ")
		pw, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stdout)
		if err != nil {
			return nil, errors.New("server: could not read the password")
		}
		return pw, nil
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return nil, errors.New("server: the password is the first line of stdin")
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}
