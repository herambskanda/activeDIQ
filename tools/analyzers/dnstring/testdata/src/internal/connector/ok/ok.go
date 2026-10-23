package ok

import "internal/directory/dn"

// The sanctioned wire path.
func wire(d dn.DN) (string, error) { return dn.DNRef(d).ForRequest() }

// A DN may be passed by value and compared; only text extraction is banned.
func same(a, b dn.DN) bool { return a == b }

func fine(d dn.DNString) string { return string(d) } // want `conversion of a DNString`
