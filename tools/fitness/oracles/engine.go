package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PwshImage is the pinned PowerShell container the Linux oracle runs in (MIT; the multi-arch index
// digest of mcr.microsoft.com/powershell:lts-ubuntu-22.04, PowerShell 7.4.x). Pinning by digest keeps
// the oracle's parser the same on every machine; bump it deliberately.
const PwshImage = "mcr.microsoft.com/powershell@sha256:663a172849444279d8e7b50e19977b6e42380eae6856bdc8931ca08e2e03e92a"

// Engine runs a constant PowerShell script with the data on stdin as JSON. The script text is a
// constant of this program, never built from data (the rule the primitives enforce on the product
// applies to the oracle too).
type Engine struct {
	Name string // docker, pwsh or powershell
}

func (e Engine) command(script string) (*exec.Cmd, error) {
	switch e.Name {
	case "docker":
		return exec.Command("docker", "run", "--rm", "-i", PwshImage, "pwsh", "-NoProfile", "-NonInteractive", "-Command", script), nil
	case "pwsh":
		return exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-Command", script), nil
	case "powershell":
		return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script), nil
	}
	return nil, fmt.Errorf("unknown engine %q (docker, pwsh or powershell)", e.Name)
}

// Run feeds input (marshalled to JSON) to the script and decodes its JSON result.
func (e Engine) Run(script string, input, result any) error {
	cmd, err := e.command(script)
	if err != nil {
		return err
	}
	in, err := json.Marshal(input)
	if err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(in)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s oracle failed: %v\n%s%s", e.Name, err, stdout.String(), stderr.String())
	}
	// The script prints exactly one JSON document; PowerShell may add warnings before it.
	out := strings.TrimSpace(stdout.String())
	if i := strings.LastIndex(out, "\n["); i >= 0 {
		out = out[i+1:]
	}
	if err := json.Unmarshal([]byte(out), result); err != nil {
		return fmt.Errorf("%s oracle printed something that is not JSON: %v\n%s", e.Name, err, out)
	}
	return nil
}

// Version asks the engine for its PowerShell version, so a log shows which parser answered.
func (e Engine) Version() string {
	var v []string
	if err := e.Run(`[Console]::Out.Write((ConvertTo-Json -InputObject @($PSVersionTable.PSVersion.ToString()) -Compress)); $null = [Console]::In.ReadToEnd()`, []string{}, &v); err != nil || len(v) == 0 {
		return "unknown"
	}
	return v[0]
}
