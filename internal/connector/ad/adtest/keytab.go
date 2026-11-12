// Package adtest holds test support for code that needs an AD service keytab but lives outside
// internal/connector, where the Kerberos library may not be imported (ADR-0002 P3). Not shipped:
// tests import it.
package adtest

import (
	"errors"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
)

// AESOnlyKeytab reads the keytab at path and returns its serialised form with only the AES128 and
// AES256 CTS-HMAC-SHA1-96 entries, which is what the connector's Kerberos bind accepts. It returns
// an error when the file holds no such entry.
func AESOnlyKeytab(path string) ([]byte, error) {
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, err
	}
	kept := kt.Entries[:0]
	for _, e := range kt.Entries {
		if e.Key.KeyType == etypeID.AES128_CTS_HMAC_SHA1_96 || e.Key.KeyType == etypeID.AES256_CTS_HMAC_SHA1_96 {
			kept = append(kept, e)
		}
	}
	kt.Entries = kept
	b, err := kt.Marshal()
	if err != nil {
		return nil, err
	}
	if len(kept) == 0 {
		return nil, errNoAES
	}
	return b, nil
}

var errNoAES = errors.New("adtest: keytab has no AES entry")
