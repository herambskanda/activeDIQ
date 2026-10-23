package ok

import "internal/directory/dn"

func fine(d dn.DNString) string { return string(d) }

// The sanctioned wire path.
func wire(d dn.DN) (string, error) { return dn.DNRef(d).ForRequest() }
