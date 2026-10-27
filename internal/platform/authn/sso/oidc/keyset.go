package oidc

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
)

const (
	jwksMinRefresh = time.Minute // OIDC-8: at most one refresh per IdP per minute
	jwksMaxAge     = time.Hour   // a cached key set is never trusted longer than this
)

// keySet caches the JWKS of one IdP. Only the pinned jwks_uri feeds it (OIDC-8).
type keySet struct {
	mu        sync.Mutex
	uri       string
	keys      map[string]jose.JSONWebKey
	lastFetch time.Time
}

// lookup returns the key with kid. An unknown kid (or a cache past jwksMaxAge) refreshes the set, but never
// more than once per jwksMinRefresh; a refresh that cannot run, or that does not produce kid, refuses.
func (k *keySet) lookup(ctx context.Context, hc HTTPClient, now time.Time, kid string) (jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.keys[kid]
	stale := k.lastFetch.IsZero() || now.Sub(k.lastFetch) >= jwksMaxAge
	if ok && !stale {
		return key, nil
	}
	if k.lastFetch.IsZero() || now.Sub(k.lastFetch) >= jwksMinRefresh {
		k.lastFetch = now // charged even when the fetch fails, so an unreachable IdP is not hammered
		if err := k.refresh(ctx, hc); err != nil {
			return jose.JSONWebKey{}, &sso.Refusal{Reason: ReasonKey, Cause: err}
		}
		if key, ok = k.keys[kid]; ok {
			return key, nil
		}
	}
	return jose.JSONWebKey{}, sso.Refuse(ReasonKey)
}

func (k *keySet) refresh(ctx context.Context, hc HTTPClient) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	body, err := fetch(hc, req, maxJWKSBytes)
	if err != nil {
		return err
	}
	var set struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return err
	}
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	ambiguous := map[string]bool{}
	for _, raw := range set.Keys {
		var jwk jose.JSONWebKey
		if json.Unmarshal(raw, &jwk) != nil { // one unusable key (unknown kty) does not void the others
			continue
		}
		if jwk.KeyID == "" || !jwk.Valid() || !jwk.IsPublic() {
			continue
		}
		if _, dup := keys[jwk.KeyID]; dup {
			ambiguous[jwk.KeyID] = true // an ambiguous kid names no key
		}
		keys[jwk.KeyID] = jwk
	}
	for kid := range ambiguous {
		delete(keys, kid)
	}
	k.keys = keys
	return nil
}
