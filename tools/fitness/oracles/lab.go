package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// checkLab is the FF-SP6 Samba lab row for P1: every rendered filter is sent to the running lab DC
// (T-0012, `make lab-up`) over LDAPS with certificate verification on, as a base-scope search of the
// domain root, and the DC must accept it (success or noSuchObject; a filter error, protocol error or
// operations error fails). It proves the DC parses what we render; it cannot prove what the filter
// matches on a Windows DC (safe-primitives §9 lists the Windows-only rows). Credentials are read from
// the per-run, uncommitted lab/.lab.env.
func checkLab(root string, cases []Case) (passed, failures []string, err error) {
	env, err := readEnv(filepath.Join(root, "lab", ".lab.env"))
	if err != nil {
		return nil, nil, fmt.Errorf("the lab is not up (%v): run `make lab-up` first", err)
	}
	ca, err := os.ReadFile(filepath.Join(root, "lab", ".lab-ca.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("no lab CA (%v): run `make lab-up` first", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, nil, errors.New("lab CA is not valid PEM")
	}
	port := env["LAB_LDAPS_PORT"]
	if port == "" {
		port = "636"
	}
	conn, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot reach the lab DC on ldaps://localhost:%s: %w", port, err)
	}
	defer conn.Close()
	if err := conn.Bind("svc-activediq@lab.activediq.test", env["LAB_SVC_PASSWORD"]); err != nil {
		return nil, nil, fmt.Errorf("lab bind failed: %w", err)
	}
	for _, c := range cases {
		if c.Output == "" {
			continue
		}
		req := ldap.NewSearchRequest("DC=lab,DC=activediq,DC=test", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, c.Output, []string{"1.1"}, nil)
		_, serr := conn.Search(req)
		var le *ldap.Error
		switch {
		case serr == nil, errors.As(serr, &le) && le.ResultCode == ldap.LDAPResultNoSuchObject:
			passed = append(passed, c.Record.ID)
		default:
			failures = append(failures, fmt.Sprintf("%s: the lab DC refuses the rendered filter %s: %v", c.Record.ID, quoteASCII(c.Output), serr))
		}
	}
	if len(passed)+len(failures) == 0 {
		return nil, nil, errors.New("no ldapfilter record with a rendered output to send")
	}
	return passed, failures, nil
}

func readEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return m, sc.Err()
}
