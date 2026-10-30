package signin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Audit kinds of SSO sign-in (SSO-4). Neither carries a token, an assertion or a cookie.
const (
	KindSSOSucceeded audit.Kind = "auth.sso.succeeded"
	KindSSORefused   audit.Kind = "auth.sso.refused"
)

// AuditRecorder is the Recorder that appends SSO-4 events to the audit chain, each in its own tenant
// transaction (the callback has no transaction of its own to join).
//
// Issuer is recorded only for a verified response. The subject is recorded as a SHA-256 prefix, not in
// the clear: an IdP subject can be an email address, and an event detail never carries a personal value
// (ADR-0005 rule 12). The account ID, which is pseudonymous, names who signed in.
type AuditRecorder struct {
	DB   *store.DB
	Sink audit.Sink
	// Clock is nil in production (time.Now); tests set it.
	Clock func() time.Time
}

func (r *AuditRecorder) now() time.Time {
	if r.Clock != nil {
		return r.Clock().UTC()
	}
	return time.Now().UTC()
}

var _ Recorder = (*AuditRecorder)(nil)

// Record implements Recorder.
func (r *AuditRecorder) Record(ctx context.Context, o Outcome) error {
	if r == nil || r.DB == nil || r.Sink == nil || o.Tenant.IsZero() {
		return errors.New("signin: audit recorder not configured")
	}
	ev, err := r.event(ctx, o)
	if err != nil {
		return err
	}
	return r.DB.WithTenant(ctx, o.Tenant, func(ctx context.Context, tx store.Tx) error {
		if err := r.Sink.Append(ctx, tx, ev); err != nil {
			return fmt.Errorf("signin: append audit event: %w", err)
		}
		return nil
	})
}

func (r *AuditRecorder) event(ctx context.Context, o Outcome) (audit.Event, error) {
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return audit.Event{}, err
	}
	d := map[string]string{"idp": o.IdP}
	if o.Issuer != "" {
		d["issuer"] = o.Issuer
	}
	if o.Subject != "" {
		sum := sha256.Sum256([]byte(o.Subject))
		d["subject_sha256"] = hex.EncodeToString(sum[:8])
	}
	if o.Account != "" {
		d["account"] = o.Account
	}
	if len(o.Methods) > 0 {
		d["methods"] = strings.Join(o.Methods, ",")
	}
	if len(o.Warnings) > 0 {
		d["warnings"] = strings.Join(o.Warnings, ",")
	}
	if o.ClientIP.IsValid() {
		d["client_ip"] = o.ClientIP.Unmap().String()
	}
	if o.ResponseID != "" {
		d["response_id"] = o.ResponseID
	}
	ev := audit.Event{
		ID: "authn.sso." + hex.EncodeToString(id[:]), At: r.now(), Component: "authn",
		Target: authority.TargetRef{GUID: o.IdP, Class: "identity_provider"},
	}
	if o.Reason != "" {
		ev.Kind, ev.Outcome, ev.Reason = KindSSORefused, audit.Denied, o.Reason
		ev.Actor = authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}
	} else {
		d["kind"] = string(o.Kind)
		d["mfa_asserted"] = fmt.Sprint(o.MFAAsserted)
		if o.Kind == ResultSession && o.Ref != "" {
			d["session"] = o.Ref
		}
		ev.Kind, ev.Outcome = KindSSOSucceeded, audit.Success
		ev.Actor = authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(o.Account), Kind: authority.Human}}
	}
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ev.Details = append(ev.Details, audit.Detail{Key: k, Value: d[k]})
	}
	return ev, nil
}
