package ops

import (
	"errors"
	"strconv"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/unicodepwd"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// ClearLockout is kind 8: replace lockoutTime with 0, the documented unlock (KB 305144). It writes
// nothing else; the UAC LOCKOUT bit is computed and read-only.
func ClearLockout() ad.AccountSender {
	return func(m ad.Modifier, dn string, _ unicodepwd.SecureConn) error {
		req := ldap.NewModifyRequest(dn, nil)
		req.Replace("lockoutTime", []string{"0"})
		return m.Modify(req)
	}
}

// ReplaceUAC is kinds 9 and 10: delete the userAccountControl value just read and add the new one in
// one Modify, so a concurrent change to any bit fails the delete (compare-and-set, ADR-0005 rule 4).
// The values are the decimal text of the int32 the caller computed with the UAC codec.
func ReplaceUAC(oldV, newV int32) ad.AccountSender {
	return func(m ad.Modifier, dn string, _ unicodepwd.SecureConn) error {
		req := ldap.NewModifyRequest(dn, nil)
		req.Delete("userAccountControl", []string{strconv.FormatInt(int64(oldV), 10)})
		req.Add("userAccountControl", []string{strconv.FormatInt(int64(newV), 10)})
		return m.Modify(req)
	}
}

// ResetPassword is kind 7: replace unicodePwd (the codec's quoted UTF-16LE form, only over the
// verified-TLS proof the session hands in) and, when mustChange, pwdLastSet = 0 in the same Modify.
// pwdLastSet is never written as -1. The policy-hints control makes the DC apply history and minimum
// age. The encoded value is zeroed after the send; go-ldap copies it into a string for the wire, which
// Go cannot zero (the limit safe-primitives §5.6 names).
func ResetPassword(pw secret.Secret, mustChange bool) ad.AccountSender {
	return func(m ad.Modifier, dn string, sc unicodepwd.SecureConn) error {
		mod, err := unicodepwd.Replace(pw, sc)
		if err != nil {
			return errors.New("password not encodable")
		}
		defer mod.Destroy()
		if err := mod.Verify(); err != nil { // PW-17: the connection is still the verified one
			return errors.New("connection no longer secure")
		}
		req := ldap.NewModifyRequest(dn, []ldap.Control{ad.PolicyHintsControl()})
		for _, c := range mod.Mods {
			if c.Op != unicodepwd.OpReplace {
				return errors.New("unexpected password modification")
			}
			c.Expose(func(vals [][]byte) {
				strs := make([]string, len(vals))
				for i, v := range vals {
					strs[i] = string(v)
				}
				req.Replace(c.Attr, strs)
			})
		}
		if mustChange {
			req.Replace("pwdLastSet", []string{"0"})
		}
		return m.Modify(req)
	}
}
