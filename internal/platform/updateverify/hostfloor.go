package updateverify

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// FileFloor is the host half of the floor: a small JSON file outside the database (and outside any
// backup the database is restored from). Writes are atomic (temp file, fsync, rename).
type FileFloor struct {
	Path string
	mu   sync.Mutex
}

func (f *FileFloor) Load(context.Context) (Floor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.load()
}

func (f *FileFloor) load() (Floor, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Floor{}, nil // first run: no floor yet
	}
	if err != nil {
		return Floor{}, err
	}
	var fl Floor
	if err := json.Unmarshal(b, &fl, json.RejectUnknownMembers(true)); err != nil {
		return Floor{}, fmt.Errorf("updateverify: host floor file is corrupt: %w", err)
	}
	return fl, nil
}

func (f *FileFloor) Raise(_ context.Context, n Floor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, err := f.load()
	if err != nil {
		return err
	}
	m, err := Max(cur, n)
	if err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".floor-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}
