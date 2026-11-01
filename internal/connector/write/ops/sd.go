// Package ops holds the bodies of directory write operations: the only code under internal/connector
// that may build an LDAP write request (fitness TM-F-T0GUARD). Only internal/connector/write imports it.
package ops

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
)

// ReplaceSD is the ad.ReplaceSDFunc for nTSecurityDescriptor: one Modify, one replace, no other
// attribute, with the controls the planner's DACLWrite carries (critical DACL-only SD_FLAGS).
func ReplaceSD(m ad.Modifier, dn string, value []byte, controls []ldap.Control) error {
	req := ldap.NewModifyRequest(dn, controls)
	req.Replace("nTSecurityDescriptor", []string{string(value)})
	return m.Modify(req)
}
