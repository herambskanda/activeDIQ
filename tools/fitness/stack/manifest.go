package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest is tools/fitness/stack/manifest.json: the machine-readable half of ADR-0001. Every
// exception to the stack rules is an entry here, and F5 refuses an entry that does not cite a
// ratified or accepted ADR, so "quietly allow C++ here" becomes an ADR amendment a reviewer sees.
type Manifest struct {
	DecisionsDir   string          `json:"decisionsDir"`
	LicenceReg     string          `json:"licenceRegister"`
	ExemptZones    []string        `json:"exemptZones"`
	BuildMatrix    []string        `json:"buildMatrix"`
	TestTags       []string        `json:"testTags"`
	ToolchainTags  []string        `json:"toolchainTags"`
	LanguageZones  map[string]Zone `json:"languageZones"`
	Banned         []string        `json:"bannedLanguages"`
	Binaries       []Binary        `json:"binaries"`
	Denylist       []DenyEntry     `json:"denylist"`
	Extends        []string        `json:"denylistExtends"`
	Exceptions     Exceptions      `json:"exceptions"`
	LicenceExcepts []LicenceExcept `json:"licenceExceptions"`
}

// Zone says where a language may live. Anywhere means everywhere except Deny; otherwise only under
// Allow (path prefixes relative to the repository root).
type Zone struct {
	Anywhere bool     `json:"anywhere"`
	Allow    []string `json:"allow"`
	Deny     []string `json:"deny"`
}

// Binary is a shipped Go binary (tier S or A). F3 and the F4 transitive scan look at its closure.
type Binary struct {
	Name    string `json:"name"`
	Tier    string `json:"tier"`
	Module  string `json:"module"`  // directory of the go.mod, default "."
	Package string `json:"package"` // package path relative to Module, e.g. ./cmd/server
}

// DenyEntry bans an import path prefix from every shipped binary (F3).
type DenyEntry struct {
	Prefix string `json:"prefix"`
	Reason string `json:"reason"`
}

// Exception is one declared exception to a rule. Every one cites an ADR file (F5).
type Exception struct {
	Path     string `json:"path"`
	ADR      string `json:"adr"`
	Reason   string `json:"reason"`
	Tier     string `json:"tier,omitempty"`     // nativeComponents: must be "N"
	Platform string `json:"platform,omitempty"` // nativeComponents: must be "windows"
}

// Exceptions groups the exception kinds of ADR-0001 rule 5.
type Exceptions struct {
	PlatformAdapters []Exception `json:"platformAdapters"`
	Sidecars         []Exception `json:"sidecars"`
	CppFallbacks     []Exception `json:"cppFallbacks"`
	ExtraGoModules   []Exception `json:"extraGoModules"`
	ThirdParty       []Exception `json:"thirdParty"`
	BuildScripts     []Exception `json:"buildScripts"`
	DevNodeTools     []Exception `json:"devNodeTools"`
	NativeComponents []Exception `json:"nativeComponents"`
}

// LicenceExcept allows one module whose licence text trips the strong-copyleft scan (F4).
type LicenceExcept struct {
	Module string `json:"module"`
	ADR    string `json:"adr"`
	Reason string `json:"reason"`
}

// denyFile is a denylist contributed by another job's manifest (for example fitness-profiles check
// U1 appending the UEM/PatchIQ module denylist). Listed in Manifest.Extends.
type denyFile struct {
	Denylist []DenyEntry `json:"denylist"`
}

func strictDecode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// LoadManifest reads and validates the shape of the manifest, then folds in extended denylists.
func LoadManifest(root, rel string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := strictDecode(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	if m.DecisionsDir == "" || m.LicenceReg == "" {
		return nil, fmt.Errorf("%s: decisionsDir and licenceRegister are required", rel)
	}
	for _, e := range m.Extends {
		eb, err := os.ReadFile(filepath.Join(root, e))
		if err != nil {
			return nil, fmt.Errorf("%s: denylistExtends: %w", rel, err)
		}
		var df denyFile
		if err := strictDecode(eb, &df); err != nil {
			return nil, fmt.Errorf("%s: %w", e, err)
		}
		m.Denylist = append(m.Denylist, df.Denylist...)
	}
	return &m, nil
}

// allExceptions lists every exception with a label, for F5.
func (m *Manifest) allExceptions() []labelled {
	var out []labelled
	add := func(kind string, es []Exception) {
		for i, e := range es {
			out = append(out, labelled{fmt.Sprintf("exceptions.%s[%d] (%s)", kind, i, e.Path), e.ADR, e.Path, kind})
		}
	}
	x := m.Exceptions
	add("platformAdapters", x.PlatformAdapters)
	add("sidecars", x.Sidecars)
	add("cppFallbacks", x.CppFallbacks)
	add("extraGoModules", x.ExtraGoModules)
	add("thirdParty", x.ThirdParty)
	add("buildScripts", x.BuildScripts)
	add("devNodeTools", x.DevNodeTools)
	add("nativeComponents", x.NativeComponents)
	for i, l := range m.LicenceExcepts {
		out = append(out, labelled{fmt.Sprintf("licenceExceptions[%d] (%s)", i, l.Module), l.ADR, "", "licence"})
	}
	return out
}

type labelled struct {
	label, adr, path, kind string
}
