package main

import (
	"bytes"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// checkLDAPFilter is the FF-SP6 P1 oracle: go-ldap's own parser (an independent implementation of
// RFC 4515) must accept every rendered filter, re-render and re-parse it to the same BER, and, for a
// single-assertion call (Eq, Ge, Le, Approx), read exactly one assertion whose attribute and value
// octets are the record's input. A value that escaped its assertion (LF-01's `*)(uid=*`) fails here.
func checkLDAPFilter(cases []Case) (checked int, failures []string) {
	for _, c := range cases {
		if c.Output == "" {
			continue
		}
		checked++
		fail := func(format string, a ...any) {
			failures = append(failures, fmt.Sprintf("%s: %s: %s", c.Record.ID, quoteASCII(c.Output), fmt.Sprintf(format, a...)))
		}
		p, err := ldap.CompileFilter(c.Output)
		if err != nil {
			fail("go-ldap rejects the rendered filter: %v", err)
			continue
		}
		back, err := ldap.DecompileFilter(p)
		if err != nil {
			fail("go-ldap cannot re-render it: %v", err)
			continue
		}
		p2, err := ldap.CompileFilter(back)
		if err != nil || !bytes.Equal(p.Bytes(), p2.Bytes()) {
			fail("parse, re-render, parse changed the filter (%s): %v", quoteASCII(back), err)
			continue
		}
		tag := map[string]uint64{"Eq": ldap.FilterEqualityMatch, "Ge": ldap.FilterGreaterOrEqual, "Le": ldap.FilterLessOrEqual, "Approx": ldap.FilterApproxMatch}
		want, single := tag[c.Record.Call]
		if !single {
			continue
		}
		attr, aerr := c.Record.Arg("attr")
		val, verr := c.Record.Arg("value")
		if aerr != nil || verr != nil {
			continue
		}
		switch {
		case uint64(p.Tag) != want || len(p.Children) != 2:
			fail("%s must be one %s assertion, go-ldap read tag %d with %d children", c.Record.Call, c.Record.Call, p.Tag, len(p.Children))
		case !bytes.Equal(p.Children[0].Data.Bytes(), attr.Raw):
			fail("attribute differs: go-ldap read %s, the call had %s", quoteASCII(string(p.Children[0].Data.Bytes())), quoteASCII(attr.Text()))
		case !bytes.Equal(p.Children[1].Data.Bytes(), val.Raw):
			fail("value octets differ: go-ldap read %x, the call had %x", p.Children[1].Data.Bytes(), val.Raw)
		}
	}
	return checked, failures
}
