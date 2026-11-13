package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	dcCondition = `Installed OR (MsiNTProductType <> 2)`
	dcMessage   = "cannot be installed on a domain controller"
)

// sequenceTables are the authored-sequence containers. Server.wxs carries none: the only way to move,
// suppress or condition the LaunchConditions action is to author one of these.
var sequenceTables = map[string]bool{
	"InstallExecuteSequence": true, "InstallUISequence": true, "AdminExecuteSequence": true,
	"AdminUISequence": true, "AdvertiseExecuteSequence": true,
}

// forbiddenElements can change what runs, or what a property holds, before or after LaunchConditions.
var forbiddenElements = map[string]bool{
	"CustomAction": true, "Custom": true, "SetProperty": true, "SetProperties": true,
	"SetDirectory": true, "LaunchConditions": true, "Binary": true,
}

// protectedProps are read from the OS and must never be authored, overridden or sequenced around.
var protectedProps = []string{"MsiNTProductType", "Installed", "LaunchConditions"}

// checkServerWxs judges the structure of Server.wxs with a real XML parse. Substring matching is not
// enough: a commented-out <Launch>, a single-quoted <Property Id='MsiNTProductType'>, or a
// <LaunchConditions Suppress="yes"/> in a sequence table all leave the "needed" text in the file while
// removing the refusal (T-0635 security review).
func checkServerWxs(file string, src []byte) []string {
	var v []string
	bad := func(format string, a ...any) { v = append(v, fmt.Sprintf("%s: ", file)+fmt.Sprintf(format, a...)) }

	dec := xml.NewDecoder(bytes.NewReader(src))
	var stack []string
	exact := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			bad("not well-formed XML: %v", err)
			return v
		}
		switch t := tok.(type) {
		case xml.ProcInst:
			// WiX preprocessor <?if?> / <?define?> can compile the refusal away. Only the declaration is allowed.
			if t.Target != "xml" {
				bad("preprocessor instruction <?%s?> is not allowed: it can compile the domain-controller refusal out", t.Target)
			}
		case xml.StartElement:
			name := t.Name.Local
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, name)
			if sequenceTables[name] {
				bad("<%s> must not be authored: it can suppress, move or condition the LaunchConditions action", name)
			}
			if forbiddenElements[name] {
				bad("<%s> is not allowed: the refusal is a LaunchCondition; custom actions and set-property actions run after costing or can rewrite MsiNTProductType", name)
			}
			for _, a := range t.Attr {
				for _, p := range protectedProps {
					if strings.EqualFold(strings.TrimSpace(a.Value), p) {
						bad("<%s %s=%q> references %s, which must not be authored, overridden or sequenced", name, a.Name.Local, a.Value, p)
					}
				}
				if strings.Contains(a.Value, "LocalSystem") {
					bad("<%s> names LocalSystem: the server never runs as LocalSystem", name)
				}
			}
			if name == "Launch" {
				cond, msg := "", ""
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "Condition":
						cond = a.Value
					case "Message":
						msg = a.Value
					}
				}
				if cond == dcCondition {
					exact++
					if parent != "Package" {
						bad("the domain-controller <Launch> must be a direct child of <Package> (found under <%s>)", parent)
					}
					if !strings.Contains(msg, dcMessage) {
						bad("the domain-controller <Launch> message must contain %q: the lab proof matches it", dcMessage)
					}
				}
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	if exact != 1 {
		bad("the server MSI must have exactly one <Launch Condition=%q> that refuses a domain controller (ProductType 2) with a LaunchCondition; Installed stays exempt so uninstall works (found %d)", dcCondition, exact)
	}
	return v
}

// checkBuiltMsi inspects a built MSI (ADIQ_SERVER_MSI): the LaunchCondition row must be present and
// LaunchConditions must be in the InstallExecuteSequence, unconditioned. Skipped when msidump is absent.
func checkBuiltMsi(msi string) []string {
	if msi == "" {
		return nil
	}
	if _, err := os.Stat(msi); err != nil {
		return []string{"ADIQ_SERVER_MSI: " + err.Error()}
	}
	if _, err := exec.LookPath("msidump"); err != nil {
		return nil
	}
	tmp, err := os.MkdirTemp("", "msidump-")
	if err != nil {
		return []string{err.Error()}
	}
	defer os.RemoveAll(tmp)
	if out, err := exec.Command("msidump", "-d", tmp, "-t", msi).CombinedOutput(); err != nil {
		return []string{"msidump failed: " + strings.TrimSpace(string(out))}
	}
	return judgeMsiTables(readTable(tmp, "LaunchCondition"), readTable(tmp, "InstallExecuteSequence"))
}

func readTable(dir, name string) string {
	b, _ := os.ReadFile(dir + "/" + name + ".idt")
	return string(b)
}

// judgeMsiTables takes the idt text of the LaunchCondition and InstallExecuteSequence tables.
func judgeMsiTables(launch, seq string) []string {
	var v []string
	if !strings.Contains(launch, dcCondition) || !strings.Contains(launch, dcMessage) {
		v = append(v, "built MSI: LaunchCondition table has no domain-controller refusal row")
	}
	found := false
	for _, line := range strings.Split(seq, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) >= 3 && f[0] == "LaunchConditions" {
			found = true
			if strings.TrimSpace(f[1]) != "" {
				v = append(v, "built MSI: the LaunchConditions action in InstallExecuteSequence is conditioned ("+f[1]+")")
			}
		}
	}
	if !found {
		v = append(v, "built MSI: LaunchConditions is missing from InstallExecuteSequence (the refusal would never run)")
	}
	return v
}
