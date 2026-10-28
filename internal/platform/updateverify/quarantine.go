package updateverify

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// QuarantineFile is a file being written into quarantine.
type QuarantineFile interface {
	io.WriteCloser
	// Path is where the finished file is, valid after Close.
	Path() string
	// Remove deletes the file; called on every failure.
	Remove() error
}

// Quarantine creates files in a directory outside the product's data path.
type Quarantine interface {
	Create() (QuarantineFile, error)
}

// DirQuarantine quarantines into Dir (created 0700 if missing). Files are 0600.
type DirQuarantine struct{ Dir string }

func (d DirQuarantine) Create() (QuarantineFile, error) {
	if d.Dir == "" {
		return nil, fmt.Errorf("updateverify: quarantine directory not set")
	}
	if err := os.MkdirAll(d.Dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(d.Dir, "artefact-*.part")
	if err != nil {
		return nil, err
	}
	return &dirFile{File: f}, nil
}

type dirFile struct{ *os.File }

func (f *dirFile) Path() string { return filepath.Clean(f.Name()) }
func (f *dirFile) Remove() error {
	f.File.Close()
	return os.Remove(f.Name())
}
