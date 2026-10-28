package updateverify

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// Open returns the verified artefact for the apply mechanism. It reopens the quarantined file,
// refuses a symlink or a replaced file, and re-checks the signed length and SHA-256 over the very
// descriptor it returns, so a swap after Verify yields a tamper refusal. The apply mechanism
// (T-0553) consumes the artefact only through Open and never reopens Path. The caller closes it.
func (r *Result) Open() (io.ReadSeekCloser, error) {
	if r == nil || r.Path == "" {
		return nil, errors.New("updateverify: no verified artefact")
	}
	want, err := hex.DecodeString(r.Release.SHA256)
	if err != nil || len(want) != sha256.Size {
		return nil, refuse(ReasonTamper, "artefact", "release hash is not valid")
	}
	li, err := os.Lstat(r.Path)
	if err != nil {
		return nil, refuse(ReasonTamper, "artefact", "quarantined artefact is gone")
	}
	if !li.Mode().IsRegular() {
		return nil, refuse(ReasonTamper, "artefact", "quarantined artefact is not a regular file")
	}
	f, err := os.Open(r.Path)
	if err != nil {
		return nil, fmt.Errorf("updateverify: open artefact: %w", err)
	}
	fail := func(e error) (io.ReadSeekCloser, error) { f.Close(); return nil, e }
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(li, fi) {
		return fail(refuse(ReasonTamper, "artefact", "quarantined artefact was replaced"))
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, r.Release.Length+1))
	if err != nil {
		return fail(fmt.Errorf("updateverify: read artefact: %w", err))
	}
	if n != r.Release.Length || subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return fail(refuse(ReasonTamper, "artefact", "quarantined artefact changed after verification"))
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return f, nil
}
