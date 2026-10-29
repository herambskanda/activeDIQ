package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
)

// The policy store persists the verifier's whole memory (agentpolicy.State: anchor, keyset, highest
// policy sequence, installed policy) so that replay protection (P2), the anchor (P7) and "an installed
// policy stays in force until replaced" (ADR-0007 decision 3) survive a restart.
//
// Writes are write-to-temp, fsync, rename, so a crash leaves the old state or the new one. The file is
// in the data directory, whose DACL is the service SID, SYSTEM and Administrators (ADR-0006 decision
// 5); the host checks that directory at start (CheckDataDir) and never widens it.

const (
	stateFile = "policy-state.json"
	stateVer  = 1
)

// ErrStateCorrupt is returned with a fresh verifier when the stored state could not be read. The bad
// file is kept as policy-state.corrupt for the administrator. The agent then behaves as just enrolled:
// no anchor, no policy, nothing collected until the server delivers a keyset and a policy.
var ErrStateCorrupt = errors.New("agent: stored policy state is unreadable and was set aside")

type stateDoc struct {
	Version   int             `json:"version"`
	Tenant    string          `json:"tenant"`
	Component string          `json:"component"`
	Verifier  json.RawMessage `json:"verifier"`
}

// StateStore is the policy store for one data directory.
type StateStore struct{ dir string }

// NewStateStore returns the store rooted at dir. dir must exist.
func NewStateStore(dir string) *StateStore { return &StateStore{dir: dir} }

// Load restores the verifier for id. Absent state is a fresh verifier. State written for another
// tenant is discarded; state written for another component ID (a re-enrolment) keeps the installed
// policy but resets the anchor (ADR-0007 decision 5).
func (s *StateStore) Load(id fleet.Identity) (*agentpolicy.Verifier, error) {
	fresh, err := agentpolicy.NewVerifier(id.Tenant, id.Kind)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(s.dir, stateFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fresh, nil
	}
	if err != nil {
		return fresh, s.setAside(path)
	}
	var d stateDoc
	if json.Unmarshal(b, &d) != nil || d.Version != stateVer {
		return fresh, s.setAside(path)
	}
	if d.Tenant != id.Tenant.String() {
		return fresh, nil
	}
	v, err := agentpolicy.RestoreVerifier(id.Tenant, id.Kind, d.Verifier)
	if err != nil {
		return fresh, s.setAside(path)
	}
	if d.Component != id.ComponentID {
		v.Reenroll()
	}
	return v, nil
}

func (s *StateStore) setAside(path string) error {
	_ = os.Remove(path + ".corrupt")
	if err := os.Rename(path, filepath.Join(s.dir, "policy-state.corrupt")); err != nil {
		_ = os.Remove(path)
	}
	return ErrStateCorrupt
}

// Save persists v for id.
func (s *StateStore) Save(id fleet.Identity, v *agentpolicy.Verifier) error {
	snap, err := v.Snapshot()
	if err != nil {
		return err
	}
	b, err := json.Marshal(stateDoc{Version: stateVer, Tenant: id.Tenant.String(), Component: id.ComponentID, Verifier: snap})
	if err != nil {
		return err
	}
	return writeAtomic(s.dir, stateFile, b)
}

// writeAtomic replaces dir/name with data: temp file in the same directory, fsync, rename.
func writeAtomic(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	ok = true
	return nil
}

// Blobs is the small named-blob store a module gets instead of a path: its bookmark, for example. A
// name is a fixed vocabulary of lower-case letters, digits and dashes; there is no way to name a path.
type Blobs struct{ dir string }

// MaxBlobBytes bounds one blob.
const MaxBlobBytes = 64 << 10

var blobName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// NewBlobs returns a blob store in dir, which it creates.
func NewBlobs(dir string) (*Blobs, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Blobs{dir: dir}, nil
}

// Load returns the blob, or nil if there is none. A blob that cannot be read is treated as absent.
func (b *Blobs) Load(name string) ([]byte, error) {
	if !blobName.MatchString(name) {
		return nil, fmt.Errorf("agent: invalid blob name")
	}
	d, err := os.ReadFile(filepath.Join(b.dir, name+".blob"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || len(d) > MaxBlobBytes {
		return nil, nil
	}
	return d, nil
}

// Save replaces the blob atomically.
func (b *Blobs) Save(name string, data []byte) error {
	if !blobName.MatchString(name) || len(data) > MaxBlobBytes {
		return fmt.Errorf("agent: invalid blob")
	}
	return writeAtomic(b.dir, name+".blob", data)
}
