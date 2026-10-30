package connector

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// filePins is the connector host's durable write.PinStore: the C13 group pins only ever grow, and a
// pin held only in memory would re-open the rename hole on restart. One JSON file, replaced atomically
// (write, sync, rename, sync the directory) before PinC13 returns.
type filePins struct {
	mu   sync.Mutex
	path string
}

func (p *filePins) load() ([]string, error) {
	raw, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PinnedC13 returns every pinned GUID. A pin file that cannot be read or parsed is an error (an unknown
// answer), never an empty set.
func (p *filePins) PinnedC13(context.Context) ([]guid.GUID, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	txt, err := p.load()
	if err != nil {
		return nil, err
	}
	out := make([]guid.GUID, 0, len(txt))
	for _, s := range txt {
		g, err := guid.Parse(s)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// PinC13 adds the GUIDs (idempotent) and returns only once the file is durable.
func (p *filePins) PinC13(_ context.Context, gs []guid.GUID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur, err := p.load()
	if err != nil {
		return err
	}
	changed := false
	for _, g := range gs {
		if s := g.String(); !slices.Contains(cur, s) {
			cur = append(cur, s)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	slices.Sort(cur)
	raw, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.path)
	tmp, err := os.CreateTemp(dir, ".pins-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(e error) error { _ = tmp.Close(); _ = os.Remove(name); return e }
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(raw); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, p.path); err != nil {
		_ = os.Remove(name)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
