package connector

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// Local is the connector's install-time configuration: which connection it serves, which directory
// it binds to and as whom. It names files, never holds a secret. Parsed strictly: an unknown key, a
// trailing document or an oversize file is refused, never skipped.
type Local struct {
	// ConnectionID is the one connection this connector serves. A request for any other is refused.
	ConnectionID string `json:"connection_id"`
	// EnrollmentDir holds the enrolled mTLS leaf, key, pinned CA bundle and server endpoints (fleet/dial).
	EnrollmentDir string `json:"enrollment_dir"`
	// DataDir holds the durable baseline, tier0 records, write-gate ratchet and C13 pins. It must survive
	// restarts; the connector reloads it and never rebuilds it.
	DataDir string `json:"data_dir"`
	// Servers are the DC hosts (host or host:port, LDAPS only), tried in order.
	Servers []string `json:"servers"`
	// ServerName overrides the TLS name checked when Servers are addresses.
	ServerName string `json:"server_name,omitempty"`
	// CAFile is the customer CA bundle (PEM) that signs the DCs' LDAPS certificates.
	CAFile   string        `json:"ca_file"`
	Kerberos LocalKerberos `json:"kerberos"`
}

// LocalKerberos is the least-privilege service identity: a gMSA or service account whose keytab binds
// with SASL GSSAPI over LDAPS with channel binding. There is no password alternative.
type LocalKerberos struct {
	Principal  string   `json:"principal"`
	Realm      string   `json:"realm"`
	KeytabFile string   `json:"keytab_file"`
	KDCs       []string `json:"kdcs,omitempty"`
}

const maxLocalBytes = 16 << 10

var connectionIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ErrLocal is returned for an unusable local configuration; it names the problem, never a value.
var ErrLocal = errors.New("connector: local configuration is not usable")

// ParseLocal decodes and validates a local configuration document.
func ParseLocal(b []byte) (Local, error) {
	var l Local
	if len(b) == 0 || len(b) > maxLocalBytes {
		return Local{}, fmt.Errorf("%w: invalid size", ErrLocal)
	}
	// v2 Unmarshal rejects trailing data, duplicate names and invalid UTF-8 by itself.
	if err := json.Unmarshal(b, &l, json.RejectUnknownMembers(true)); err != nil {
		return Local{}, fmt.Errorf("%w: %v", ErrLocal, err)
	}
	switch {
	case !connectionIDRe.MatchString(l.ConnectionID):
		return Local{}, fmt.Errorf("%w: connection_id", ErrLocal)
	case !filepath.IsAbs(l.EnrollmentDir) || !filepath.IsAbs(l.DataDir) || !filepath.IsAbs(l.CAFile) || !filepath.IsAbs(l.Kerberos.KeytabFile):
		return Local{}, fmt.Errorf("%w: enrollment_dir, data_dir, ca_file and kerberos.keytab_file must be absolute paths", ErrLocal)
	case len(l.Servers) == 0 || len(l.Servers) > 16:
		return Local{}, fmt.Errorf("%w: servers", ErrLocal)
	case l.Kerberos.Principal == "" || l.Kerberos.Realm == "":
		return Local{}, fmt.Errorf("%w: kerberos principal and realm are required", ErrLocal)
	}
	return l, nil
}

// LoadLocal reads and parses the file at path.
func LoadLocal(path string) (Local, error) {
	if path == "" {
		return Local{}, ErrNoConfig
	}
	f, err := os.Open(path)
	if err != nil {
		return Local{}, fmt.Errorf("%w: unreadable", ErrLocal)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxLocalBytes+1))
	if err != nil {
		return Local{}, fmt.Errorf("%w: unreadable", ErrLocal)
	}
	return ParseLocal(b)
}
