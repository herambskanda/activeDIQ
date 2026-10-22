package connection

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// connectionsTable declares public.connections (DM-10) for fitness-domain-keys.
var connectionsTable = tablekind.Declare(tablekind.Table{
	Name:   "public.connections",
	Entity: "DM-10",
	Kind:   tablekind.Tenant,
})

// Kind is what a connection connects to.
type Kind string

// The two kinds of directory.
const (
	KindADForest    Kind = "ad_forest"
	KindEntraTenant Kind = "entra_tenant"
)

// Transport is how an AD connection secures LDAP (DM-10 transport_security). Entra has none.
type Transport string

// The two TLS mechanisms. There is no third: the security floor is not configurable (I4).
const (
	TransportLDAPS    Transport = "ldaps"
	TransportStartTLS Transport = "starttls"
)

// ID identifies a connection. Build one with ParseID; the database mints new ones.
type ID string

// CredentialID names the DM-11 credential row a connection uses. It is a reference, never material.
type CredentialID string

// DirectoryIdentity is the AD forest root NC objectGUID or the Entra tenant ID, in canonical
// lower-case UUID text. The empty value means "not yet verified" (I1).
type DirectoryIdentity string

var uuidText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ParseID accepts a canonical UUID (either case) and returns it lower-cased.
func ParseID(s string) (ID, error) {
	v, ok := canonUUID(s)
	if !ok {
		return "", ErrInvalid
	}
	return ID(v), nil
}

// ParseCredentialID accepts a canonical UUID (either case).
func ParseCredentialID(s string) (CredentialID, error) {
	v, ok := canonUUID(s)
	if !ok {
		return "", ErrInvalid
	}
	return CredentialID(v), nil
}

// ParseDirectoryIdentity accepts a canonical UUID (either case). The error never echoes the input.
func ParseDirectoryIdentity(s string) (DirectoryIdentity, error) {
	v, ok := canonUUID(s)
	if !ok {
		return "", ErrInvalid
	}
	return DirectoryIdentity(v), nil
}

func canonUUID(s string) (string, bool) {
	l := strings.ToLower(s)
	if !uuidText.MatchString(l) || l == "00000000-0000-0000-0000-000000000000" {
		return "", false
	}
	return l, true
}

// Connection is DM-10 as stored. It carries no secret.
type Connection struct {
	ID                 ID
	Kind               Kind
	DisplayName        string
	DirectoryIdentity  DirectoryIdentity
	CredentialID       CredentialID
	State              State
	LastVerificationID string // empty until a verification is recorded
	VerifiedAt         *time.Time
	RetiredAt          *time.Time
	LastStampAt        *time.Time
	Transport          Transport // empty for Entra
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// New is what Create needs. A connection is born a draft with no identity (L1).
type New struct {
	Kind         Kind
	DisplayName  string
	CredentialID CredentialID
	Transport    Transport // required for ad_forest, forbidden for entra_tenant
}

func (n New) validate() error {
	switch n.Kind {
	case KindADForest:
		if n.Transport != TransportLDAPS && n.Transport != TransportStartTLS {
			return fmt.Errorf("%w: an AD forest needs transport ldaps or starttls", ErrInvalid)
		}
	case KindEntraTenant:
		if n.Transport != "" {
			return fmt.Errorf("%w: an Entra tenant has no LDAP transport", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unknown kind", ErrInvalid)
	}
	if n.DisplayName == "" || utf8.RuneCountInString(n.DisplayName) > 200 || !utf8.ValidString(n.DisplayName) || strings.ContainsRune(n.DisplayName, 0) {
		return fmt.Errorf("%w: display name must be 1 to 200 characters", ErrInvalid)
	}
	if _, ok := canonUUID(string(n.CredentialID)); !ok {
		return fmt.Errorf("%w: credential id", ErrInvalid)
	}
	return nil
}

// Typed errors. None carries a value from the directory or the database.
var (
	// ErrInvalid is a malformed input.
	ErrInvalid = errors.New("connection: invalid input")
	// ErrNotFound: no such connection in this tenant.
	ErrNotFound = errors.New("connection: not found")
	// ErrNoTenant: the call ran without a tenant context.
	ErrNoTenant = errors.New("connection: no tenant context")
	// ErrIllegalTransition: the requested state change is not in the DM-10 table.
	ErrIllegalTransition = errors.New("connection: illegal state transition")
	// ErrStateConflict: the connection is no longer in the state the caller saw.
	ErrStateConflict = errors.New("connection: state changed concurrently")
	// ErrIdentityFixed: directory_identity cannot change once set (I1).
	ErrIdentityFixed = errors.New("connection: directory identity is fixed once set (I1)")
	// ErrIdentityState: an identity is set only by a verification, so only while verifying.
	ErrIdentityState = errors.New("connection: identity can be set only while verifying")
	// ErrDuplicateIdentity: another live connection of this tenant already holds the identity
	// (I2, spec L10: the V5 check fails with duplicate_identity).
	ErrDuplicateIdentity = errors.New("connection: duplicate_identity")
)

// CodeDuplicateIdentity is the stable code V5 reports for ErrDuplicateIdentity.
const CodeDuplicateIdentity = "duplicate_identity"
