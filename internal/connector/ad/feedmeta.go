package ad

import (
	"context"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// The directory facts the change-feed pre-checks (contract §6.3) read on the bound DC.

// DefaultTombstoneLifetime is what Microsoft documents for a forest whose tombstoneLifetime is
// absent. The shorter default is the safe one for an age check: the real value is never smaller
// than the lifetime a forest created since Windows Server 2003 SP1 uses.
const DefaultTombstoneLifetime = 60 * 24 * time.Hour

// CheckDirSyncAttributes validates the attribute names of a feed request exactly as DirSync does,
// but without a request: wildcards, constructed read-only attributes and SecretAttrs members fail
// here, so a refused name costs the DC nothing.
func (s *Session) CheckDirSyncAttributes(names []string) error {
	_, _, err := s.dirSyncAttrs(names)
	return err
}

// HighestCommittedUSN reads the bound DC's highestCommittedUSN. A missing or non-positive value is
// an error: zero would look like a USN rollback to every cookie.
func (s *Session) HighestCommittedUSN(ctx context.Context) (int64, error) {
	rd, err := s.RootDSE(ctx)
	if err != nil {
		return 0, err
	}
	if rd.HighestCommittedUSN <= 0 {
		return 0, fail(CodeProtocol, "highestCommittedUSN unavailable", nil)
	}
	return rd.HighestCommittedUSN, nil
}

// DomainNCGUID is the objectGUID of the domain naming context the bound DC serves
// (defaultNamingContext): the one partition a DirSync feed of this connection may follow.
func (s *Session) DomainNCGUID(ctx context.Context) (guid.GUID, error) {
	rd, err := s.RootDSE(ctx)
	if err != nil {
		return guid.GUID{}, err
	}
	ref, err := dn.ParseObjectRef(rd.DefaultNamingContext)
	if err != nil {
		return guid.GUID{}, fail(CodeProtocol, "default naming context is not a DN", err)
	}
	e, err := s.Read(ctx, ref, []string{"objectGUID"}, ReadOptions{})
	if err != nil {
		return guid.GUID{}, err
	}
	return e.GUID()
}

// DeletionLifetime is how long a deletion stays observable: the smaller of tombstoneLifetime and
// msDS-DeletedObjectLifetime (contract §6.3). An absent tombstoneLifetime is
// DefaultTombstoneLifetime; an absent msDS-DeletedObjectLifetime equals tombstoneLifetime.
func (s *Session) DeletionLifetime(ctx context.Context) (time.Duration, error) {
	rd, err := s.RootDSE(ctx)
	if err != nil {
		return 0, err
	}
	d, err := dn.Parse(rd.ConfigurationNamingContext, dn.Strict)
	if err != nil {
		return 0, fail(CodeProtocol, "configuration naming context is not a DN", err)
	}
	for _, rdn := range [][2]string{{"CN", "Services"}, {"CN", "Windows NT"}, {"CN", "Directory Service"}} {
		t, err := dn.ParseRDNType(rdn[0])
		if err != nil {
			return 0, fail(CodeProtocol, "directory service object", err)
		}
		if d, err = dn.Child(d, t, rdn[1]); err != nil {
			return 0, fail(CodeProtocol, "directory service object", err)
		}
	}
	e, err := s.Read(ctx, dn.DNRef(d), []string{"tombstoneLifetime", "msDS-DeletedObjectLifetime"}, ReadOptions{})
	if err != nil {
		return 0, err
	}
	days := func(name string) (time.Duration, bool, error) {
		v := e.Raw(name)
		if len(v) == 0 {
			return 0, false, nil
		}
		n, perr := strconv.ParseInt(string(v[0]), 10, 32)
		if perr != nil || n <= 0 {
			return 0, false, fail(CodeProtocol, "deletion lifetime is not a positive number of days", nil)
		}
		return time.Duration(n) * 24 * time.Hour, true, nil
	}
	tomb, ok, err := days("tombstoneLifetime")
	if err != nil {
		return 0, err
	}
	if !ok {
		tomb = DefaultTombstoneLifetime
	}
	del, ok, err := days("msDS-DeletedObjectLifetime")
	if err != nil {
		return 0, err
	}
	if ok && del < tomb {
		return del, nil
	}
	return tomb, nil
}
