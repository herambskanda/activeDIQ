// Package hostcheck is the TM-F-HOST proof (threat-model §15; TM-TB1-T2, TM-TB4-T1, TM-TB5, TM-TB14-T3,
// TM-TB16-T1..T3, T6, T7). One evaluator turns what a collector observed on a booted install into named
// cases; two collectors feed it: the linux-oci collector (oci.go: builds the real cmd/server, boots it in a
// container against PostgreSQL) and the Windows lab collector (packaging/windows/Get-HostObservation.ps1,
// run on a lab host where the MSI is installed). A section the collector could not observe is nil and the
// case is reported INACTIVE with the ticket that delivers its subject; it is never silently green.
package hostcheck

import (
	"fmt"
	"sort"
	"strings"
)

// Observation is the collector-to-evaluator contract (JSON, stable field names).
type Observation struct {
	Profile string `json:"profile"` // linux-oci | windows
	// Installer is what the installer did when run on a domain controller (TM-TB16-T1).
	Installer *Installer `json:"installer,omitempty"`
	// Service is the identity the installed service actually runs as (TM-TB16-T2).
	Service *Service `json:"service,omitempty"`
	// Files are the config, keytab, keystore and TLS-directory entries of the install (TM-TB16-T3, TB5, TB14-T3).
	Files []File `json:"files,omitempty"`
	// First is the state of a booted install before anyone has configured it (TM-TB1-T2).
	First *FirstRun `json:"first_run,omitempty"`
	// Setup is the one-time setup secret life cycle (TM-TB16-T7).
	Setup *Setup `json:"setup,omitempty"`
	// Dumps is the crash-dump posture of the running service (TM-TB16-T6).
	Dumps *Dumps `json:"dumps,omitempty"`
	// DSN lists the remote-database DSNs the booted server was offered (TM-TB4-T1).
	DSN []DSNProbe `json:"dsn,omitempty"`
}

type Installer struct {
	OnDomainController bool `json:"on_domain_controller"`
	Refused            bool `json:"refused"`   // the installer exited non-zero with the DC message
	Installed          bool `json:"installed"` // a service or files exist afterwards
}

type Service struct {
	Account string `json:"account"` // gMSA / virtual account / "LocalSystem" / "uid:gid"
	UID     *int   `json:"uid,omitempty"`
}

type File struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // config | keytab | keystore | tls-dir | tls-key | binary
	// ReadableByOthers: a principal other than the service identity and administrators/root can read it.
	ReadableByOthers bool `json:"readable_by_others"`
	// WritableByOthers matters for kind=binary and tls-dir (TM-TB16-T4, TM-TB14-T3).
	WritableByOthers bool   `json:"writable_by_others"`
	Mode             string `json:"mode,omitempty"`
	Owner            string `json:"owner,omitempty"`
}

type FirstRun struct {
	Listeners          []Listener `json:"listeners"`
	DefaultCredentials []string   `json:"default_credentials"` // each "user" a bare login accepted with a well-known password
}

type Listener struct {
	Addr string `json:"addr"`
	// PlaintextResponds: a plain-text request got an application-level answer (HTTP status line, etc.).
	PlaintextResponds bool `json:"plaintext_responds"`
	TLS               bool `json:"tls"`
}

type Setup struct {
	// UsedOnce: the secret was accepted the first time. AcceptedAgain: it worked a second time.
	UsedOnce      bool `json:"used_once"`
	AcceptedAgain bool `json:"accepted_again"`
	// ExpiredAccepted: a secret past its expiry was accepted.
	ExpiredAccepted bool `json:"expired_accepted"`
	// ReadableByOthers: the written secret is readable by someone but the installing administrator.
	ReadableByOthers bool `json:"readable_by_others"`
}

type Dumps struct {
	CoreLimitZero  bool `json:"core_limit_zero"` // RLIMIT_CORE == 0 (Linux)
	NotDumpable    bool `json:"not_dumpable"`    // PR_SET_DUMPABLE == 0 (Linux)
	TracebackCrash bool `json:"traceback_crash"` // GOTRACEBACK=crash set
	PprofListens   bool `json:"pprof_listens"`
	WERLocalDumps  bool `json:"wer_local_dumps"` // HKLM\...\Windows Error Reporting\LocalDumps has an entry for the service (Windows)
}

type DSNProbe struct {
	Mode     string `json:"mode"`   // as written: disable, require, verify-ca (no root), verify-full ...
	Remote   bool   `json:"remote"` // host is not loopback / unix socket
	Accepted bool   `json:"accepted"`
	// Contacted: the server tried to connect to the remote host before refusing.
	Contacted bool `json:"contacted"`
	// MustAccept marks the compliant control (verify-full): it must not be refused for TLS reasons.
	MustAccept bool `json:"must_accept"`
}

// Case names. Each is a build-failing case; the failing fixtures in host_test.go prove each fires.
const (
	CaseDC        = "HOST-DC-REFUSED"
	CaseIdent     = "HOST-SERVICE-NOT-PRIVILEGED"
	CasePerms     = "HOST-FILE-PERMISSIONS"
	CaseCred      = "HOST-NO-DEFAULT-CREDENTIAL"
	CasePlaintext = "HOST-NO-PLAINTEXT-LISTENER"
	CaseSetup     = "HOST-SETUP-SECRET-SINGLE-USE"
	CaseDumps     = "HOST-NO-DUMPS"
	CaseDSN       = "HOST-REMOTE-DSN-FULL-TLS"
)

// Cases is the full list, in report order.
var Cases = []string{CaseDC, CaseIdent, CasePerms, CaseCred, CasePlaintext, CaseSetup, CaseDumps, CaseDSN}

// Result is one case's verdict.
type Result struct {
	Case     string
	Inactive string   // non-empty: not observed; says why
	Failures []string // non-empty: the build fails
}

// Evaluate judges an observation. Every case appears exactly once in the result.
func Evaluate(o Observation) []Result {
	res := map[string]*Result{}
	for _, c := range Cases {
		res[c] = &Result{Case: c}
	}
	fail := func(c, f string, a ...any) { res[c].Failures = append(res[c].Failures, fmt.Sprintf(f, a...)) }

	if o.Installer == nil {
		res[CaseDC].Inactive = "installer not run on a domain controller by this collector"
	} else if o.Installer.OnDomainController {
		if !o.Installer.Refused {
			fail(CaseDC, "the installer did not refuse a domain controller (ADR-0002 rule 9)")
		}
		if o.Installer.Installed {
			fail(CaseDC, "files or a service exist on a domain controller after the installer ran")
		}
	}

	if o.Service == nil {
		res[CaseIdent].Inactive = "no service identity observed"
	} else {
		a := strings.ToLower(strings.TrimSpace(o.Service.Account))
		switch {
		case o.Service.UID != nil && *o.Service.UID == 0:
			fail(CaseIdent, "the service runs as uid 0")
		case a == "root" || a == "0" || strings.HasPrefix(a, "0:"):
			fail(CaseIdent, "the service runs as root (%q)", o.Service.Account)
		case a == "localsystem" || a == "system" || a == "nt authority\\system" || a == "s-1-5-18":
			fail(CaseIdent, "the service runs as LocalSystem")
		case a == "":
			fail(CaseIdent, "the service identity is empty (treated as the default, which is root or LocalSystem)")
		}
	}

	if len(o.Files) == 0 {
		res[CasePerms].Inactive = "no config, keytab, keystore or TLS files observed"
	}
	for _, f := range o.Files {
		if f.ReadableByOthers {
			fail(CasePerms, "%s (%s, mode %s) is readable by a principal other than the service and administrators", f.Path, f.Kind, f.Mode)
		}
		if f.WritableByOthers && (f.Kind == "binary" || f.Kind == "tls-dir") {
			fail(CasePerms, "%s (%s) is writable by an unprivileged principal (binary or directory replacement, TM-TB14-T3/T4)", f.Path, f.Kind)
		}
	}

	if o.First == nil {
		res[CaseCred].Inactive = "no booted first-run state observed"
		res[CasePlaintext].Inactive = "no booted first-run state observed"
	} else {
		for _, c := range o.First.DefaultCredentials {
			fail(CaseCred, "a default credential works at first run: %s", c)
		}
		if len(o.First.Listeners) == 0 {
			fail(CasePlaintext, "no listener observed on a booted install (the probe saw nothing to judge)")
		}
		for _, l := range o.First.Listeners {
			if l.PlaintextResponds {
				fail(CasePlaintext, "%s answers a plaintext request", l.Addr)
			}
			if !l.TLS {
				fail(CasePlaintext, "%s does not complete a TLS handshake", l.Addr)
			}
		}
	}

	if o.Setup == nil {
		res[CaseSetup].Inactive = "the product has no one-time setup secret yet"
	} else {
		if !o.Setup.UsedOnce {
			fail(CaseSetup, "the setup secret was not accepted the first time (the probe proves nothing)")
		}
		if o.Setup.AcceptedAgain {
			fail(CaseSetup, "the setup secret was accepted a second time")
		}
		if o.Setup.ExpiredAccepted {
			fail(CaseSetup, "an expired setup secret was accepted")
		}
		if o.Setup.ReadableByOthers {
			fail(CaseSetup, "the setup secret is readable by someone other than the installing administrator")
		}
	}

	if o.Dumps == nil {
		res[CaseDumps].Inactive = "no dump posture observed"
	} else {
		d := o.Dumps
		if o.Profile == "windows" {
			if d.WERLocalDumps {
				fail(CaseDumps, "WER LocalDumps is configured for the service")
			}
		} else {
			if !d.CoreLimitZero {
				fail(CaseDumps, "RLIMIT_CORE is not 0")
			}
			if !d.NotDumpable {
				fail(CaseDumps, "the process is dumpable (PR_SET_DUMPABLE is not 0)")
			}
		}
		if d.TracebackCrash {
			fail(CaseDumps, "GOTRACEBACK=crash is set")
		}
		if d.PprofListens {
			fail(CaseDumps, "a pprof endpoint is served")
		}
	}

	if len(o.DSN) == 0 {
		res[CaseDSN].Inactive = "no DSN probes"
	}
	for _, p := range o.DSN {
		switch {
		case p.Remote && !p.MustAccept && p.Accepted:
			fail(CaseDSN, "a remote DSN with %s was accepted", p.Mode)
		case p.Remote && !p.MustAccept && p.Contacted:
			fail(CaseDSN, "the server connected to a remote host with %s before refusing", p.Mode)
		case p.MustAccept && !p.Accepted:
			fail(CaseDSN, "the compliant DSN (%s) was refused: the probe cannot tell a refusal from a broken boot", p.Mode)
		}
	}

	out := make([]Result, 0, len(Cases))
	for _, c := range Cases {
		sort.Strings(res[c].Failures)
		out = append(out, *res[c])
	}
	return out
}

// Merge combines observations of the same profile (a collector may run in stages).
func Merge(a, b Observation) Observation {
	if a.Installer == nil {
		a.Installer = b.Installer
	}
	if a.Service == nil {
		a.Service = b.Service
	}
	a.Files = append(a.Files, b.Files...)
	if a.First == nil {
		a.First = b.First
	}
	if a.Setup == nil {
		a.Setup = b.Setup
	}
	if a.Dumps == nil {
		a.Dumps = b.Dumps
	}
	a.DSN = append(a.DSN, b.DSN...)
	return a
}

// PlaintextServes judges the first bytes a listener sent back to a plaintext HTTP request. Go's TLS
// server answers a clear-text request with "400 Client sent an HTTP request to an HTTPS server" and serves
// nothing; that is a refusal. Any other HTTP answer means the listener speaks plaintext.
func PlaintextServes(first string) bool {
	if !strings.HasPrefix(first, "HTTP/") {
		return false
	}
	return !(strings.HasPrefix(first[strings.Index(first, " ")+1:], "400") && strings.Contains(first, "HTTP request to an HTTPS server"))
}
