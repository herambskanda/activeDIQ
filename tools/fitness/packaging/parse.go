package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// parseScript is a constant: the files to parse are found inside the read-only mount, never spliced into
// script text; the directory arrives as data in ADIQ_PS_ROOT. It prints one "file:line: message" per ParseError.
const parseScript = `Get-ChildItem -LiteralPath $env:ADIQ_PS_ROOT -Recurse -Filter *.ps1 | ForEach-Object {
  $errs = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errs)
  foreach ($e in $errs) { '{0}:{1}: {2}' -f $_.FullName, $e.Extent.StartLineNumber, $e.Message }
}`

var digestRe = regexp.MustCompile(`PwshImage\s*=\s*"([^"]+)"`)

// pwshImage reuses the digest-pinned image of the oracles (one pin to bump, not two).
func pwshImage(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "tools/fitness/oracles/engine.go"))
	if err != nil {
		return "", err
	}
	m := digestRe.FindSubmatch(b)
	if m == nil {
		return "", fmt.Errorf("PwshImage not found in oracles/engine.go")
	}
	return string(m[1]), nil
}

// parsePowerShell runs PowerShell's own parser over every packaging/**/*.ps1 and reports each ParseError.
// No engine (pwsh nor Docker) is a violation: a gate that cannot run must not pass.
func parsePowerShell(root, pinRoot string) []string {
	dir, err := filepath.Abs(filepath.Join(root, "packaging"))
	if err != nil {
		return []string{err.Error()}
	}
	var cmd *exec.Cmd
	if _, err := exec.LookPath("pwsh"); err == nil {
		cmd = exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-Command", parseScript)
		cmd.Env = append(os.Environ(), "ADIQ_PS_ROOT="+dir)
	} else {
		img, err := pwshImage(pinRoot)
		if err != nil {
			return []string{"ps1 parse: " + err.Error()}
		}
		cmd = exec.Command("docker", "run", "--rm", "--network", "none", "-e", "ADIQ_PS_ROOT=/w", "-v", dir+":/w:ro", img, "pwsh", "-NoProfile", "-NonInteractive", "-Command", parseScript)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return []string{fmt.Sprintf("ps1 parse: no PowerShell parser available (install pwsh or start Docker): %v %s", err, strings.TrimSpace(errb.String()))}
	}
	var v []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			v = append(v, "PowerShell parse error: "+l)
		}
	}
	return v
}
