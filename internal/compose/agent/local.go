package agent

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
)

// Local is the agent's install-time configuration (contract §3: local ceilings). It lives in the
// install directory, which the service SID can read but not write, so a compromised agent or server
// cannot widen its own limits. Parsed strictly: an unknown key, a trailing document or an oversize
// file is refused, never skipped.
type Local struct {
	DataDir            string `json:"data_dir"`
	EnrollmentDir      string `json:"enrollment_dir"`
	OutboxMaxBytes     uint32 `json:"outbox_max_bytes"`
	BatchMaxBytes      uint32 `json:"batch_max_bytes"`
	MaxEventsPerSecond uint32 `json:"max_events_per_second"`
	ReportedDCGUID     string `json:"reported_dc_guid"`
}

const maxLocalBytes = 16 << 10

// Defaults for the ceilings when an installer does not set them.
const (
	DefaultOutboxMaxBytes     = 256 << 20
	DefaultBatchMaxBytes      = 256 << 10
	DefaultMaxEventsPerSecond = 2000
)

// ParseLocal decodes and validates a local configuration document.
func ParseLocal(b []byte) (Local, error) {
	var l Local
	if len(b) == 0 || len(b) > maxLocalBytes {
		return l, errors.New("agent: local configuration has an invalid size")
	}
	// v2 Unmarshal rejects trailing data, duplicate names and invalid UTF-8 by itself.
	if err := json.Unmarshal(b, &l, json.RejectUnknownMembers(true)); err != nil {
		return Local{}, fmt.Errorf("agent: local configuration: %w", err)
	}
	if l.OutboxMaxBytes == 0 {
		l.OutboxMaxBytes = DefaultOutboxMaxBytes
	}
	if l.BatchMaxBytes == 0 {
		l.BatchMaxBytes = DefaultBatchMaxBytes
	}
	if l.MaxEventsPerSecond == 0 {
		l.MaxEventsPerSecond = DefaultMaxEventsPerSecond
	}
	if !filepath.IsAbs(l.DataDir) || !filepath.IsAbs(l.EnrollmentDir) || len(l.ReportedDCGUID) > 64 {
		return Local{}, errors.New("agent: data_dir and enrollment_dir must be absolute paths")
	}
	if !l.ceilings().Valid() {
		return Local{}, errors.New("agent: ceilings are outside the supported range")
	}
	return l, nil
}

func (l Local) ceilings() kernel.Ceilings {
	return kernel.Ceilings{OutboxMaxBytes: l.OutboxMaxBytes, BatchMaxBytes: l.BatchMaxBytes, MaxEventsPerSecond: l.MaxEventsPerSecond}
}

// LoadLocal reads the file at path.
func LoadLocal(path string) (Local, error) {
	f, err := os.Open(path)
	if err != nil {
		return Local{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxLocalBytes+1))
	if err != nil {
		return Local{}, err
	}
	return ParseLocal(b)
}
