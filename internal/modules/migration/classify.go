package migration

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"html"
	"regexp"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Class is the fidelity class of one parsed item (spec e2-11 §3.1, §6.2).
type Class string

// The four classes. Only Exact and Changed items get a proposal.
const (
	ClassExact        Class = "exact"
	ClassChanged      Class = "changed"
	ClassManual       Class = "manual"
	ClassNotSupported Class = "not_supported"
)

// Reasons recorded for manual and not_supported rows. They are codes, never content.
const (
	ReasonScript         = "script_body"            // §6.5: escaped text, no custom-script feature
	ReasonTenantOwner    = "tenant_owner"           // §6.4
	ReasonNeverImported  = "rbac_or_connections"    // §6.4: administers RBAC, delegation scopes or connections
	ReasonTier0          = "tier0_scope"            // §6.4: scope or target resolves to a tier0 object
	ReasonTier0Unknown   = "tier0_unresolved"       // fail closed: tier0 could not be ruled out
	ReasonScopeMalformed = "scope_malformed"        // a scope reference that is not an object GUID
	ReasonCredential     = "credential"             // §6.4: credential, key, token, technician password
	ReasonRawSQL         = "raw_sql"                // §6.4
	ReasonOpenRequest    = "open_request"           // §6.4: drained in ADMP per the playbook
	ReasonImporter       = "importer_not_supported" // the importer itself could not translate the item
)

// Limits of one recorded batch and of the stored text.
const (
	MaxItemsPerRecord = 100_000
	MaxDetailRunes    = 4096
	MaxConfigBytes    = 64 << 10
)

// DiffEntry is one before/after difference of a changed item.
type DiffEntry struct {
	Field  string `json:"field"`
	Source string `json:"source"`
	Ours   string `json:"ours"`
}

// Grant is one privilege a proposal would carry once applied. Scope lists object GUIDs (OU, container or
// object) the grant is limited to; an empty Scope means a non-directory grant.
type Grant struct {
	Permission  string   `json:"permission"`
	TenantOwner bool     `json:"tenantOwner,omitempty"`
	Scope       []string `json:"scope,omitempty"`
}

// Item is one parsed item as an importer submits it. Importers describe; Classify decides.
type Item struct {
	// Ref is the stable identity of the item in the source (unique within the job); Kind and Name are
	// for display.
	Ref, Kind, Name string
	// Declared is the importer's own verdict on a clean item: exact, changed or not_supported.
	// Classify may only make it stricter, never more permissive.
	Declared Class
	// Diff is required for changed items.
	Diff []DiffEntry
	// Script carries a script body, escaped on the way in; its presence makes the item manual.
	Script string
	// Credential, RawSQL and OpenRequest flag content that is never imported (§6.4).
	Credential, RawSQL, OpenRequest bool
	// Config is the intended configuration as a JSON object; Grants the privileges it carries.
	Config jsontext.Value
	Grants []Grant
}

// Tier0Resolver decides whether an object GUID is, or sits under, a tier0 object. An error means "could
// not rule it out" and Classify then refuses the item (fail closed).
type Tier0Resolver interface {
	ResolvesTier0(ctx context.Context, tx store.Tx, objectGUID string) (bool, error)
}

// Classified is the verdict on one item: its fidelity row and, only when applicable, its proposal.
type Classified struct {
	Seq      int
	Item     Item
	Class    Class
	Reason   string
	Detail   string // escaped, bounded text (the script body for a manual item); data, never executed
	Proposal *ProposalBody
}

// ProposalBody is the inert stored form of a proposal.
type ProposalBody struct {
	Config jsontext.Value `json:"config"`
	Grants []Grant        `json:"grants"`
}

var (
	kindRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	guidRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	permReOK = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
)

// Classify decides the class of one item. Order matters: what is never imported wins over a script, which
// wins over the importer's own verdict. A proposal exists only for exact and changed items; no path
// returns one for any other class. r may be nil: a grant with a directory scope is then not supported,
// because tier0 cannot be ruled out.
func Classify(ctx context.Context, tx store.Tx, r Tier0Resolver, seq int, it Item) (Classified, error) {
	if it.Ref == "" || len([]rune(it.Ref)) > 500 || !kindRe.MatchString(it.Kind) || len([]rune(it.Name)) > 500 {
		return Classified{}, fmt.Errorf("%w: item %d: ref, kind or name malformed", ErrInvalid, seq)
	}
	switch it.Declared {
	case ClassExact, ClassChanged, ClassNotSupported:
	default:
		return Classified{}, fmt.Errorf("%w: item %d: declared class must be exact, changed or not_supported", ErrInvalid, seq)
	}
	if (it.Declared == ClassChanged) != (len(it.Diff) > 0) && it.Declared != ClassNotSupported {
		return Classified{}, fmt.Errorf("%w: item %d: a changed item needs a diff and only a changed item has one", ErrInvalid, seq)
	}
	out := Classified{Seq: seq, Item: it, Class: it.Declared}
	out.Item.Script = "" // the raw body is not carried past this function
	if reason, err := neverImported(ctx, tx, r, it); err != nil {
		return Classified{}, err
	} else if reason != "" {
		out.Class, out.Reason = ClassNotSupported, reason
		return out, nil
	}
	if it.Script != "" {
		out.Class, out.Reason, out.Detail = ClassManual, ReasonScript, escapeText(it.Script)
		return out, nil
	}
	if it.Declared == ClassNotSupported {
		out.Reason = ReasonImporter
		return out, nil
	}
	cfg := it.Config
	if len(cfg) == 0 || len(cfg) > MaxConfigBytes || !isObject(cfg) {
		return Classified{}, fmt.Errorf("%w: item %d: an applicable item needs a JSON object config of at most %d bytes", ErrInvalid, seq, MaxConfigBytes)
	}
	grants := it.Grants
	if grants == nil {
		grants = []Grant{}
	}
	out.Proposal = &ProposalBody{Config: cfg, Grants: grants}
	return out, nil
}

// neverImported returns the reason an item must not become a proposal (§6.4), or "".
func neverImported(ctx context.Context, tx store.Tx, r Tier0Resolver, it Item) (string, error) {
	switch {
	case it.Credential:
		return ReasonCredential, nil
	case it.RawSQL:
		return ReasonRawSQL, nil
	case it.OpenRequest:
		return ReasonOpenRequest, nil
	}
	for _, g := range it.Grants {
		if g.TenantOwner {
			return ReasonTenantOwner, nil
		}
		if !permReOK.MatchString(g.Permission) {
			return ReasonNeverImported, nil // an unrecognisable permission is never carried
		}
		if p := authz.Permission(g.Permission); authz.NeverCrosses(p) || authz.IsPlatformOnly(p) {
			return ReasonNeverImported, nil
		}
		for _, o := range g.Scope {
			if !guidRe.MatchString(o) {
				return ReasonScopeMalformed, nil
			}
			if r == nil {
				return ReasonTier0Unknown, nil
			}
			t0, err := r.ResolvesTier0(ctx, tx, o)
			if err != nil {
				return ReasonTier0Unknown, nil //nolint:nilerr // fail closed: the item is refused, the batch goes on
			}
			if t0 {
				return ReasonTier0, nil
			}
		}
	}
	return "", nil
}

func isObject(b jsontext.Value) bool {
	var m map[string]jsontext.Value
	return jsonv2.Unmarshal(b, &m) == nil && m != nil
}

// escapeText makes imported text inert for any renderer: valid UTF-8, HTML-escaped, bounded. It is stored
// as data and still re-encoded on every output (T-0150).
func escapeText(s string) string {
	s, _ = export.Sanitize(s)
	if utf8.RuneCountInString(s) > MaxDetailRunes {
		s = string([]rune(s)[:MaxDetailRunes])
	}
	return html.EscapeString(s)
}
