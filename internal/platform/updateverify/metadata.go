package updateverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"time"
)

// Role names.
const (
	RoleRoot      = "root"
	RoleTimestamp = "timestamp"
	RoleSnapshot  = "snapshot"
	RoleTargets   = "targets"
)

var roles = []string{RoleRoot, RoleTimestamp, RoleSnapshot, RoleTargets}

const keyTypeEd25519 = "ed25519"

type envelope struct {
	Signed     jsontext.Value `json:"signed"`
	Signatures []signature    `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64 std
}

type header struct {
	Type    string    `json:"type"`
	Version uint64    `json:"version"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
}

type keyEntry struct {
	KeyType string `json:"keytype"`
	Public  string `json:"public"` // base64 std, 32 bytes
}

type roleEntry struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

type rootSigned struct {
	header
	Keys  map[string]keyEntry  `json:"keys"`
	Roles map[string]roleEntry `json:"roles"`
}

type fileRef struct {
	Version uint64 `json:"version"`
	Length  int64  `json:"length"`
	SHA256  string `json:"sha256"` // hex
}

type timestampSigned struct {
	header
	Snapshot fileRef `json:"snapshot"`
}

type snapshotSigned struct {
	header
	RootVersion uint64  `json:"root_version"`
	Targets     fileRef `json:"targets"`
}

// Release is one artefact the signed targets manifest describes.
type Release struct {
	Name           string `json:"name"`
	ProductVersion string `json:"product_version"`
	Platform       string `json:"platform"`
	Length         int64  `json:"length"`
	SHA256         string `json:"sha256"` // hex
	MinFrom        string `json:"min_from,omitempty"`
	Withdrawn      bool   `json:"withdrawn,omitempty"`
	// Security marks a security release (bypasses ring deferral; used by the scheduler, not here).
	Security bool `json:"security,omitempty"`
}

type targetsSigned struct {
	header
	Releases []Release `json:"releases"`
}

func decode[T any](raw []byte, wantType string) (*envelope, *T, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, refuse(ReasonTamper, wantType, "metadata is not well-formed")
	}
	var s T
	if err := json.Unmarshal(env.Signed, &s, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, refuse(ReasonTamper, wantType, "signed part is not well-formed")
	}
	return &env, &s, nil
}

func keyID(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// parseKey validates a key entry and returns the public key; the key ID must be the hash of the key.
func parseKey(id string, k keyEntry) (ed25519.PublicKey, error) {
	if k.KeyType != keyTypeEd25519 {
		return nil, fmt.Errorf("key type %q", k.KeyType)
	}
	b, err := base64.StdEncoding.DecodeString(k.Public)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key material")
	}
	if keyID(b) != id {
		return nil, fmt.Errorf("key id does not match key")
	}
	return ed25519.PublicKey(b), nil
}

func validateRoot(r *rootSigned) error {
	for id, k := range r.Keys {
		if _, err := parseKey(id, k); err != nil {
			return err
		}
	}
	for _, name := range roles {
		re, ok := r.Roles[name]
		if !ok {
			return fmt.Errorf("role %s missing", name)
		}
		if re.Threshold < 1 || re.Threshold > len(re.KeyIDs) {
			return fmt.Errorf("role %s threshold", name)
		}
		seen := map[string]bool{}
		for _, id := range re.KeyIDs {
			if _, ok := r.Keys[id]; !ok || seen[id] {
				return fmt.Errorf("role %s key list", name)
			}
			seen[id] = true
		}
	}
	if len(r.Roles) != len(roles) {
		return fmt.Errorf("unknown role")
	}
	return nil
}

// revokedSet remembers, per role, the public keys a later root removed from that role.
type revokedSet map[string]map[string]ed25519.PublicKey

// sigCheck counts valid, distinct signatures over env.Signed from the keys of role in root, and
// reports which valid signers are keys revoked for that role.
type sigCheck struct {
	valid   []string // distinct key IDs of the role that signed validly
	revoked []string // valid signatures from keys revoked for the role
}

func checkSignatures(env *envelope, root *rootSigned, role string, revoked revokedSet) sigCheck {
	var out sigCheck
	allowed := map[string]bool{}
	for _, id := range root.Roles[role].KeyIDs {
		allowed[id] = true
	}
	seen := map[string]bool{}
	for _, s := range env.Signatures {
		if seen[s.KeyID] {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		revPub, isRevoked := revoked[role][s.KeyID]
		var pub ed25519.PublicKey
		if isRevoked {
			pub = revPub
		} else if allowed[s.KeyID] {
			pub, _ = parseKey(s.KeyID, root.Keys[s.KeyID])
		}
		if pub == nil || !ed25519.Verify(pub, env.Signed, sig) {
			continue
		}
		seen[s.KeyID] = true
		if isRevoked {
			out.revoked = append(out.revoked, s.KeyID)
			continue
		}
		if allowed[s.KeyID] {
			out.valid = append(out.valid, s.KeyID)
		}
	}
	return out
}
