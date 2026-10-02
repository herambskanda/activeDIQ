// aeskeytab rewrites a keytab keeping only AES (etype 17/18) entries: the "AES-only keytab" of ADR-0001 /
// feasibility §2.4. Samba's exportkeytab also emits RC4; the spike must prove it binds without it.
package main

import (
	"fmt"
	"os"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: aeskeytab IN OUT")
		os.Exit(2)
	}
	kt, err := keytab.Load(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	kept := kt.Entries[:0]
	dropped := 0
	for _, e := range kt.Entries {
		if e.Key.KeyType == etypeID.AES128_CTS_HMAC_SHA1_96 || e.Key.KeyType == etypeID.AES256_CTS_HMAC_SHA1_96 {
			kept = append(kept, e)
		} else {
			dropped++
		}
	}
	kt.Entries = kept
	b, err := kt.Marshal()
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("kept %d AES entries, dropped %d non-AES\n", len(kept), dropped)
}
