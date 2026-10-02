package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Config is tools/fitness/profiles/manifest.json: the machine-readable half of ADR-0002's
// fitness function. It uses the ADR-0001 manifest mechanism (strict JSON, every exception cites a
// ratified or accepted ADR file in decisionsDir, a stale entry fails).
type Config struct {
	DecisionsDir string `json:"decisionsDir"`

	// P1 composition boundary.
	CompositionRoot  []string `json:"compositionRoot"` // cmd/ plus every package under internal/compose/
	ExemptRoots      []string `json:"exemptRoots"`     // build tooling: not domain code
	ConfigLoader     []string `json:"configLoader"`    // the only places that may read the environment
	ComposePackage   string   `json:"composePackage"`  // importing it (or anything under it) outside the root fails
	ProfilePackage   string   `json:"profilePackage"`  // where the manifests are
	CapabilityPkg    string   `json:"capabilityPackage"`
	ProfileEnvRegexp string   `json:"profileEnvRegexp"` // env var names that select a profile
	IdentDenylist    []string `json:"identifierDenylist"`
	LiteralDenylist  []string `json:"literalDenylist"`
	Manifests        []string `json:"manifests"`  // profile ids that must be found in ProfilePackage
	SelfHosted       []string `json:"selfHosted"` // the two profiles that must have equal capabilities
	SaaSProfile      string   `json:"saasProfile"`
	IsolatedRoles    []string `json:"isolatedRoles"` // roles that may share a process with no other role (rule 2)
	ADProvider       string   `json:"adProvider"`
	ADCapability     string   `json:"adCapability"`

	// U2.
	PlatformRoot      string   `json:"platformRoot"`
	PlatformForbidden []string `json:"platformForbidden"`

	// U1.
	UEMDenylist    string      `json:"uemDenylist"`   // file in the stack manifest's denylistExtends format
	StackManifest  string      `json:"stackManifest"` // must list UEMDenylist in denylistExtends
	ReplaceExcepts []Exception `json:"replaceExceptions"`

	// P7.
	BranchAllow []string `json:"branchAllow"` // regular expressions, anchored by the tool

	// Activation table.
	Activation []Activation `json:"activation"`
}

// Exception is one declared exception; it cites an ADR file (F5 mechanism).
type Exception struct {
	Path   string `json:"path"`
	ADR    string `json:"adr"`
	Reason string `json:"reason"`
}

// Activation is one row of the activation table: a check that cannot run until its subject lands.
type Activation struct {
	Check   string   `json:"check"`   // P2..P6, U3, U4
	Subject string   `json:"subject"` // what the check guards, for the printed table
	Paths   []string `json:"paths"`   // any existing path (a glob; "dir/*" matches a sub-directory) activates the check
	Command []string `json:"command"` // the implemented check, run from the repository root; empty = not implemented
	Reason  string   `json:"reason"`  // why these paths are the subject
}

// uemDeny is the denylist file shared with fitness-stack F3 (same shape as its denylistExtends files).
type uemDeny struct {
	Denylist []struct {
		Prefix string `json:"prefix"`
		Reason string `json:"reason"`
	} `json:"denylist"`
}

func strictDecode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// LoadConfig reads and validates the shape of the manifest.
func LoadConfig(root, rel string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return nil, err
	}
	var c Config
	if err := strictDecode(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	if c.DecisionsDir == "" || c.ProfilePackage == "" || c.CapabilityPkg == "" || c.PlatformRoot == "" || c.UEMDenylist == "" || c.SaaSProfile == "" {
		return nil, fmt.Errorf("%s: decisionsDir, profilePackage, capabilityPackage, platformRoot, uemDenylist and saasProfile are required", rel)
	}
	if _, err := regexp.Compile(c.ProfileEnvRegexp); err != nil {
		return nil, fmt.Errorf("%s: profileEnvRegexp: %w", rel, err)
	}
	for _, p := range c.BranchAllow {
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("%s: branchAllow %q: %w", rel, p, err)
		}
	}
	return &c, nil
}

func loadUEMDeny(root, rel string) (*uemDeny, error) {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return nil, err
	}
	var d uemDeny
	if err := strictDecode(b, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	return &d, nil
}

// jsonLoose decodes JSON ignoring fields the target does not name (another job's manifest).
func jsonLoose(b []byte, v any) error { return json.Unmarshal(b, v) }
