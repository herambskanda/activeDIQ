package m

import (
	"bytes"
	"strings"

	"internal/directory/dn"
)

func bad(d dn.DNString, ou string) {
	_ = string(d)                         // want `conversion of a DNString to string`
	_ = []byte(d)                         // want `conversion of a DNString to \[\]byte`
	_ = strings.HasSuffix(string(d), ou)  // want `conversion of a DNString`
	_ = strings.Contains(d.Display(), ou) // display text is allowed
	_ = d + ",OU=x"                       // want `joined with \+`
	_ = bytes.Equal(nil, nil)
}
