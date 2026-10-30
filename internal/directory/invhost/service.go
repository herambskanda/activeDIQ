package invhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Audit kinds and reason codes.
const (
	KindRegistered audit.Kind = "inventory.host.registered"
	KindRefused    audit.Kind = "inventory.host.refused"

	ReasonNotInventory = "not_inventory"
	ReasonNotHuman     = "not_human"
	component          = "invhost"
)

// DC is a domain controller as discovery found it. SRV is set when the name came from the domain's
// _ldap._tcp.dc._msdcs SRV records and NTDSDSA when the DC's nTDSDSA object was read and names it.
type DC struct {
	FQDN    string
	SRV     bool
	NTDSDSA bool
}

// DCSource is the discovery port. ConfirmedDC reports a DC the discovery code has found for the tenant's
// forest; it never fabricates one from a directory attribute value.
type DCSource interface {
	ConfirmedDC(ctx context.Context, tid tenant.ID, fqdn string) (DC, bool, error)
}

// Store is the registry of admin-registered servers. Its methods run in the caller's tenant transaction.
type Store interface {
	// Find reports whether fqdn (already normalised) is registered.
	Find(ctx context.Context, tx store.Tx, tid tenant.ID, fqdn string) (bool, error)
	// Insert registers fqdn and returns the row id; it reports false, with no error, if fqdn is already
	// registered.
	Insert(ctx context.Context, tx store.Tx, tid tenant.ID, fqdn, by string) (id string, inserted bool, err error)
}

// Runner runs fn in a tenant transaction; (*store.DB).WithTenant is one.
type Runner func(ctx context.Context, tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error

// Service holds the two constructors.
type Service struct {
	Run   Runner
	Store Store
	DCs   DCSource
	Audit audit.Sink
	Now   func() time.Time // tests only
	NewID func() string    // tests only; default is 128 random bits
}

func (s *Service) ready() error {
	if s == nil || s.Run == nil || s.Store == nil || s.DCs == nil || s.Audit == nil {
		return ErrNotConfigured
	}
	return nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) id() string {
	if s.NewID != nil {
		return s.NewID()
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Register is the admin-registered constructor. The caller has already authorised actor for the
// registration (it is an Action's write function); this records it. The name must be a plain DNS name
// (ErrInvalidHostname otherwise, audited as a refusal). Registering a name that is already registered
// returns the existing host and writes nothing new. The row and its audit event commit together.
func (s *Service) Register(ctx context.Context, tid tenant.ID, actor authority.Chain, name string) (InventoryHost, error) {
	if err := s.ready(); err != nil {
		return InventoryHost{}, err
	}
	if tid.IsZero() {
		return InventoryHost{}, ErrNoTenant
	}
	if err := actor.Validate(); err != nil {
		return InventoryHost{}, err
	}
	// Only a human admin acting directly may register: an automation, system or API-token requester could
	// otherwise launder a host read from the directory (homeDirectory, dNSHostName) into the inventory.
	if actor.Requester.Kind != authority.Human || len(actor.Via) != 0 {
		if aerr := s.refuse(ctx, tid, actor, ReasonNotHuman, name); aerr != nil {
			return InventoryHost{}, errors.Join(ErrNotHuman, aerr)
		}
		return InventoryHost{}, ErrNotHuman
	}
	fqdn, err := Normalize(name)
	if err != nil {
		if aerr := s.refuse(ctx, tid, actor, "invalid_hostname", name); aerr != nil {
			return InventoryHost{}, errors.Join(err, aerr)
		}
		return InventoryHost{}, err
	}
	var host InventoryHost
	err = s.Run(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		id, inserted, err := s.Store.Insert(ctx, tx, tid, fqdn, string(actor.Requester.ID))
		if err != nil {
			return err
		}
		host = InventoryHost{fqdn: fqdn, origin: OriginRegistered}
		if !inserted {
			return nil
		}
		return s.Audit.Append(ctx, tx, audit.Event{
			ID: s.id(), Kind: KindRegistered, At: s.now(), Actor: actor,
			Target:    authority.TargetRef{GUID: id, Class: "server"},
			Component: component, Outcome: audit.Success,
			Details: []audit.Detail{{Key: "fqdn", Value: fqdn}},
		})
	})
	if err != nil {
		return InventoryHost{}, err
	}
	return host, nil
}

// Resolve is the lookup constructor for a caller that holds a candidate name (an admin's choice of file
// server, say). The candidate is a key only: the host is returned if it is a registered server or a
// discovered, confirmed DC, and carries the inventory's name. Otherwise Resolve records a denied audit event
// and returns ErrNotInventoryHost, having dialled nothing. A UNC path, an IP literal and an invalid name are
// all just "not in inventory". A store or audit error is returned as such, never as a host.
func (s *Service) Resolve(ctx context.Context, tid tenant.ID, actor authority.Chain, candidate string) (InventoryHost, error) {
	if err := s.ready(); err != nil {
		return InventoryHost{}, err
	}
	if tid.IsZero() {
		return InventoryHost{}, ErrNoTenant
	}
	if err := actor.Validate(); err != nil {
		return InventoryHost{}, err
	}
	if fqdn, err := Normalize(candidate); err == nil {
		var found bool
		if err := s.Run(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			var ferr error
			found, ferr = s.Store.Find(ctx, tx, tid, fqdn)
			return ferr
		}); err != nil {
			return InventoryHost{}, fmt.Errorf("invhost: registry lookup: %w", err)
		}
		if found {
			return InventoryHost{fqdn: fqdn, origin: OriginRegistered}, nil
		}
		dc, ok, err := s.DCs.ConfirmedDC(ctx, tid, fqdn)
		if err != nil {
			return InventoryHost{}, fmt.Errorf("invhost: dc lookup: %w", err)
		}
		if ok && dc.SRV && dc.NTDSDSA {
			if n, nerr := Normalize(dc.FQDN); nerr == nil && n == fqdn {
				return InventoryHost{fqdn: fqdn, origin: OriginDiscoveredDC}, nil
			}
		}
	}
	if err := s.refuse(ctx, tid, actor, ReasonNotInventory, candidate); err != nil {
		return InventoryHost{}, errors.Join(ErrNotInventoryHost, err)
	}
	return InventoryHost{}, ErrNotInventoryHost
}

// refuse appends a denied event in its own transaction. The candidate is attacker-controlled text, so only
// a short digest of it is recorded, enough to match two refusals, never the text.
func (s *Service) refuse(ctx context.Context, tid tenant.ID, actor authority.Chain, reason, candidate string) error {
	sum := sha256.Sum256([]byte(candidate))
	return s.Run(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		return s.Audit.Append(ctx, tx, audit.Event{
			ID: s.id(), Kind: KindRefused, At: s.now(), Actor: actor,
			Target:    authority.TargetRef{Class: "server"},
			Component: component, Outcome: audit.Denied, Reason: reason,
			Details: []audit.Detail{{Key: "candidate_sha256", Value: hex.EncodeToString(sum[:8])}},
		})
	})
}
