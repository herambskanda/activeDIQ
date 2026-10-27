package authn

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_accounts", Entity: "DM-30", Kind: tablekind.Tenant})

// Errors. None carries a stored value or SQL.
var (
	ErrAccountNotFound = errors.New("authn: no such account")
	// ErrAccountExists: a live account already holds this IdP subject or directory object.
	ErrAccountExists = errors.New("authn: account already exists")
	// ErrAlreadyBound: the account already has an anchor binding. A binding is never rewritten here
	// (DM-30.I5); rebinding is an audited administrative action of its own.
	ErrAlreadyBound = errors.New("authn: account already bound")
	// ErrBadTransition: the lifecycle does not allow that state change.
	ErrBadTransition = errors.New("authn: account state transition refused")
	// ErrLastOwner: the change would leave the tenant without an active tenant-owner (DM-30.I4).
	ErrLastOwner = errors.New("authn: at least one active tenant-owner is required")
)

// AccountKind is how an account authenticates (DM-30).
type AccountKind string

// Kinds.
const (
	KindLocal     AccountKind = "local"
	KindSSO       AccountKind = "sso"
	KindDirectory AccountKind = "directory"
)

// AccountState is the DM-30 lifecycle: invited → active ⇄ disabled → deleted.
type AccountState string

// States.
const (
	AccountInvited  AccountState = "invited"
	AccountActive   AccountState = "active"
	AccountDisabled AccountState = "disabled"
	AccountDeleted  AccountState = "deleted"
)

// AnchorKind is the claim a binding came from (DM-30.I5). Only these two bind; a UPN, email, name or
// immutable ID never does.
type AnchorKind string

// Anchor kinds.
const (
	AnchorOID       AnchorKind = "oid"
	AnchorOnpremSID AnchorKind = "onprem_sid"
)

// DirectoryRef names a directory object by connection and objectGUID, never by DN. IDs are canonical
// lower-case UUID text.
type DirectoryRef struct {
	ConnectionID string
	ObjectGUID   string
}

// Anchor is the binding evidence of an sso account: the claim and its value. TenantID (the Entra tid)
// is required for oid and must be empty for onprem_sid.
type Anchor struct {
	Kind     AnchorKind
	Value    string // oid as lower-case UUID, or the SID string
	TenantID string
}

// Account is a DM-30 row. Anchor is non-nil only for a bound sso account, and then Ref is the resolved
// directory_ref.
type Account struct {
	Tenant      tenant.ID
	ID          string
	Kind        AccountKind
	DisplayName string
	Email       string
	MFARequired bool
	State       AccountState
	CreatedBy   string // "system" or the creating account's ID
	SSOIssuer   string
	SSOSubject  string
	Ref         *DirectoryRef
	Anchor      *Anchor
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewAccount is the input of Create. Local accounts always require MFA (DM-30.I1), so MFARequired is
// ignored for them. An sso account starts unbound; Bind adds the anchor.
type NewAccount struct {
	Tenant      tenant.ID
	Kind        AccountKind
	DisplayName string
	Email       string
	CreatedBy   string
	MFARequired bool
	SSOIssuer   string
	SSOSubject  string
	Ref         *DirectoryRef // directory accounts only
}

// Audit kinds of the account lifecycle (DM-30). Events carry the account's ID, never a secret.
const (
	KindAccountBound        audit.Kind = "authn.account.bound"
	KindAccountStateChanged audit.Kind = "authn.account.state_changed"
	// KindAccountStateRefused records a disable or delete refused because it would remove the last
	// active tenant-owner (DM-30.I4).
	KindAccountStateRefused audit.Kind = "authn.account.state_refused"
)

// Accounts is the DM-30 store. It is safe for concurrent use. Disabling or deleting an account ends
// its sessions through the session store inside the same transaction (DM-31.I2), and binding and
// state changes are audited there too, so a failure of either rolls the change back.
type Accounts struct {
	db       *store.DB
	sessions *Store
	owners   OwnerSource
}

// OwnerSource tells the account store who holds the tenant-owner role (authz data, DM-36), so DM-30.I4
// is enforced on the write path without authn reading authz tables. TenantOwners must take a
// transaction-scoped lock that serialises every writer able to remove an owner, then return the
// holders; the lock is held until tx ends.
type OwnerSource interface {
	TenantOwners(ctx context.Context, tx store.Tx, t tenant.ID) ([]string, error)
}

// NewAccounts returns the account store over db. sessions is the session store whose audit sink and
// revocation the account changes use. owners is required: without it DM-30.I4 could not be enforced,
// so there is no unguarded construction.
func NewAccounts(db *store.DB, sessions *Store, owners OwnerSource) (*Accounts, error) {
	if db == nil || sessions == nil || owners == nil {
		return nil, errors.New("authn: accounts need a database, a session store and an owner source")
	}
	return &Accounts{db: db, sessions: sessions, owners: owners}, nil
}

func (s *Accounts) emit(ctx context.Context, tx store.Tx, now time.Time, id string, kind audit.Kind, eid string, by authority.Chain, reason string, details []chain.Detail, outcome ...audit.Outcome) error {
	oc := audit.Success
	if len(outcome) > 0 {
		oc = outcome[0]
	}
	ev := audit.Event{
		ID: "authn.account." + id + "." + eid, Kind: kind, At: now, Actor: by,
		Target:    authority.TargetRef{GUID: id, Class: "account"},
		Component: "authn", Outcome: oc, Reason: reason, Details: details,
	}
	if err := s.sessions.audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("authn: audit account event: %w", err)
	}
	return nil
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sidRe  = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,15}$`)
)

func (r DirectoryRef) valid() bool {
	return uuidRe.MatchString(r.ConnectionID) && uuidRe.MatchString(r.ObjectGUID)
}

func (a Anchor) valid() bool {
	switch a.Kind {
	case AnchorOID:
		return uuidRe.MatchString(a.Value) && uuidRe.MatchString(a.TenantID)
	case AnchorOnpremSID:
		return sidRe.MatchString(a.Value) && a.TenantID == ""
	}
	return false
}

func (n NewAccount) validate() error {
	if n.Tenant.IsZero() || n.DisplayName == "" || len(n.DisplayName) > 200 || len(n.Email) > 320 ||
		(n.CreatedBy != "system" && !uuidRe.MatchString(n.CreatedBy)) {
		return ErrInvalidInput
	}
	switch n.Kind {
	case KindLocal:
		if n.SSOIssuer != "" || n.SSOSubject != "" || n.Ref != nil {
			return ErrInvalidInput
		}
	case KindSSO:
		if n.SSOIssuer == "" || n.SSOSubject == "" || len(n.SSOIssuer) > 2048 || len(n.SSOSubject) > 512 || n.Ref != nil {
			return ErrInvalidInput
		}
	case KindDirectory:
		if n.SSOIssuer != "" || n.SSOSubject != "" || n.Ref == nil || !n.Ref.valid() {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

const accountCols = `id::text, kind, display_name, COALESCE(email, ''), mfa_required, state, created_by,
  COALESCE(sso_issuer, ''), COALESCE(sso_subject, ''), directory_connection_id::text, directory_object_guid::text,
  anchor_kind, anchor_value, anchor_tid::text, created_at, updated_at`

func scanAccount(t tenant.ID, row interface{ Scan(dest ...any) error }) (Account, error) {
	var (
		a                        = Account{Tenant: t}
		kind, state              string
		conn, guid, ak, av, atid *string
	)
	if err := row.Scan(&a.ID, &kind, &a.DisplayName, &a.Email, &a.MFARequired, &state, &a.CreatedBy,
		&a.SSOIssuer, &a.SSOSubject, &conn, &guid, &ak, &av, &atid, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return Account{}, err
	}
	a.Kind, a.State = AccountKind(kind), AccountState(state)
	if conn != nil && guid != nil {
		a.Ref = &DirectoryRef{ConnectionID: *conn, ObjectGUID: *guid}
	}
	if ak != nil && av != nil {
		an := &Anchor{Kind: AnchorKind(*ak), Value: *av}
		if atid != nil {
			an.TenantID = *atid
		}
		a.Anchor = an
	}
	return a, nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Create inserts an account. A local account always requires MFA. A directory or sso account that
// would duplicate a live one is refused with ErrAccountExists. The new account is invited.
func (s *Accounts) Create(ctx context.Context, in NewAccount) (Account, error) {
	if err := in.validate(); err != nil {
		return Account{}, err
	}
	mfa := in.MFARequired || in.Kind == KindLocal
	var conn, guid *string
	if in.Ref != nil {
		conn, guid = &in.Ref.ConnectionID, &in.Ref.ObjectGUID
	}
	var out Account
	err := s.db.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO public.authn_accounts
			(tenant_id, kind, display_name, email, mfa_required, created_by, sso_issuer, sso_subject, directory_connection_id, directory_object_guid)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::uuid, $10::uuid) RETURNING `+accountCols,
			in.Tenant.String(), string(in.Kind), in.DisplayName, nilIfEmpty(in.Email), mfa, in.CreatedBy,
			nilIfEmpty(in.SSOIssuer), nilIfEmpty(in.SSOSubject), conn, guid)
		a, err := scanAccount(in.Tenant, row)
		out = a
		return err
	})
	if err != nil {
		if store.SQLState(err) == "23505" {
			return Account{}, ErrAccountExists
		}
		return Account{}, fmt.Errorf("authn: create account: %w", err)
	}
	return out, nil
}

// Get reads one account by ID.
func (s *Accounts) Get(ctx context.Context, t tenant.ID, id string) (Account, error) {
	if t.IsZero() || !uuidRe.MatchString(id) {
		return Account{}, ErrInvalidInput
	}
	return s.one(ctx, t, `WHERE tenant_id = $1 AND id = $2::uuid`, t.String(), id)
}

// LookupSSO finds the live account for an IdP issuer and subject.
func (s *Accounts) LookupSSO(ctx context.Context, t tenant.ID, issuer, subject string) (Account, error) {
	if t.IsZero() || issuer == "" || subject == "" {
		return Account{}, ErrInvalidInput
	}
	return s.one(ctx, t, `WHERE tenant_id = $1 AND kind = 'sso' AND sso_issuer = $2 AND sso_subject = $3 AND state <> 'deleted'`,
		t.String(), issuer, subject)
}

func (s *Accounts) one(ctx context.Context, t tenant.ID, where string, args ...any) (Account, error) {
	var out Account
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		a, err := scanAccount(t, tx.QueryRow(ctx, `SELECT `+accountCols+` FROM public.authn_accounts `+where, args...))
		out = a
		return err
	})
	if store.IsNoRows(err) {
		return Account{}, ErrAccountNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("authn: read account: %w", err)
	}
	return out, nil
}

// Bind records the anchor and the directory object it resolved to on an unbound sso account
// (DM-30.I5). The caller resolves the anchor through DirectoryAnchors first and passes the GUID;
// the SID is never stored as the reference. An already-bound account returns ErrAlreadyBound: this
// never rebinds. by is the actor (authority.Chain with a system requester for an admission-rule
// sign-in); the binding and its authn.account.bound event commit together.
func (s *Accounts) Bind(ctx context.Context, t tenant.ID, id string, an Anchor, ref DirectoryRef, by authority.Chain) (Account, error) {
	if t.IsZero() || !uuidRe.MatchString(id) || !an.valid() || !ref.valid() || by.Validate() != nil {
		return Account{}, ErrInvalidInput
	}
	var tid *string
	if an.TenantID != "" {
		tid = &an.TenantID
	}
	var out Account
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		a, err := scanAccount(t, tx.QueryRow(ctx, `UPDATE public.authn_accounts
			SET directory_connection_id = $3::uuid, directory_object_guid = $4::uuid,
			    anchor_kind = $5, anchor_value = $6, anchor_tid = $7::uuid, updated_at = $8
			WHERE tenant_id = $1 AND id = $2::uuid AND kind = 'sso' AND anchor_kind IS NULL AND state <> 'deleted'
			RETURNING `+accountCols, t.String(), id, ref.ConnectionID, ref.ObjectGUID, string(an.Kind), an.Value, tid, now))
		if err != nil {
			return err
		}
		out = a
		// Keys are in increasing order, as the envelope requires.
		return s.emit(ctx, tx, now, id, KindAccountBound, "bound", by, string(an.Kind), []chain.Detail{
			{Key: "anchor_kind", Value: string(an.Kind)},
			{Key: "connection_id", Value: ref.ConnectionID},
			{Key: "object_guid", Value: ref.ObjectGUID},
		})
	})
	if store.IsNoRows(err) {
		// Distinguish a missing or non-sso account from one that is already bound.
		cur, gerr := s.Get(ctx, t, id)
		if gerr != nil {
			return Account{}, gerr
		}
		if cur.Kind == KindSSO && cur.Anchor != nil {
			return Account{}, ErrAlreadyBound
		}
		return Account{}, ErrInvalidInput
	}
	if err != nil {
		if store.SQLState(err) == "23505" {
			return Account{}, ErrAccountExists
		}
		return Account{}, fmt.Errorf("authn: bind account: %w", err)
	}
	return out, nil
}

// allowed is the DM-30 lifecycle: invited → active ⇄ disabled → deleted.
var allowed = map[AccountState][]AccountState{
	AccountInvited:  {AccountActive, AccountDisabled, AccountDeleted},
	AccountActive:   {AccountDisabled, AccountDeleted},
	AccountDisabled: {AccountActive, AccountDeleted},
}

// SetState moves an account along its lifecycle. Moving to disabled or deleted ends every session of
// the account in the same transaction (DM-31.I2): if the revocation or either audit event fails, the
// state is unchanged. by is the real actor behind the change.
func (s *Accounts) SetState(ctx context.Context, t tenant.ID, id string, to AccountState, by authority.Chain) (Account, error) {
	if t.IsZero() || !uuidRe.MatchString(id) || by.Validate() != nil {
		return Account{}, ErrInvalidInput
	}
	var out Account
	refused := false
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		cur, err := scanAccount(t, tx.QueryRow(ctx, `SELECT `+accountCols+` FROM public.authn_accounts WHERE tenant_id = $1 AND id = $2::uuid FOR UPDATE`, t.String(), id))
		if err != nil {
			return err
		}
		ok := false
		for _, n := range allowed[cur.State] {
			ok = ok || n == to
		}
		if !ok {
			return ErrBadTransition
		}
		now, err := s.sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if cur.State == AccountActive && (to == AccountDisabled || to == AccountDeleted) {
			last, err := s.isLastOwner(ctx, tx, t, id)
			if err != nil {
				return err
			}
			if last {
				// Commit only the refusal's audit event; the state change is not made.
				refused = true
				return s.emit(ctx, tx, now, id, KindAccountStateRefused, fmt.Sprintf("state-refused.%s.%s.%d", cur.State, to, now.UnixNano()), by, "last_tenant_owner", []chain.Detail{
					{Key: "from", Value: string(cur.State)},
					{Key: "to", Value: string(to)},
				}, audit.Denied)
			}
		}
		out, err = scanAccount(t, tx.QueryRow(ctx, `UPDATE public.authn_accounts SET state = $3, updated_at = $4 WHERE tenant_id = $1 AND id = $2::uuid RETURNING `+accountCols, t.String(), id, string(to), now))
		if err != nil {
			return err
		}
		if to == AccountDisabled || to == AccountDeleted {
			if _, err := s.sessions.OnAccountDisabled(ctx, tx, t, id, by); err != nil {
				return err
			}
		}
		return s.emit(ctx, tx, now, id, KindAccountStateChanged, fmt.Sprintf("state.%s.%s.%d", cur.State, to, now.UnixNano()), by, string(to), []chain.Detail{
			{Key: "from", Value: string(cur.State)},
			{Key: "to", Value: string(to)},
		})
	})
	switch {
	case err == nil && refused:
		return Account{}, ErrLastOwner
	case store.IsNoRows(err):
		return Account{}, ErrAccountNotFound
	case errors.Is(err, ErrBadTransition):
		return Account{}, err
	case err != nil:
		return Account{}, fmt.Errorf("authn: set account state: %w", err)
	}
	return out, nil
}

// isLastOwner reports whether id is an active tenant-owner and no other active account is. It takes the
// owner lock first (via the source), so a concurrent removal of another owner has either committed and
// is seen here, or waits for this transaction.
func (s *Accounts) isLastOwner(ctx context.Context, tx store.Tx, t tenant.ID, id string) (bool, error) {
	holders, err := s.owners.TenantOwners(ctx, tx, t)
	if err != nil {
		return false, fmt.Errorf("authn: reading tenant owners: %w", err)
	}
	self := false
	var others []string
	for _, h := range holders {
		if h == id {
			self = true
		} else {
			others = append(others, h)
		}
	}
	if !self {
		return false, nil
	}
	var n int
	if len(others) > 0 {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_accounts WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND state = 'active'`, t.String(), others).Scan(&n); err != nil {
			return false, fmt.Errorf("authn: counting active owners: %w", err)
		}
	}
	return n == 0, nil
}
