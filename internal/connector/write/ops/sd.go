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

// ModifyDN sends one ModifyDN built from the session's rendered parts.
func ModifyDN(m ad.ObjectConn, c ad.DNChange) error {
	return m.ModifyDN(ldap.NewModifyDNRequest(c.Entry, c.NewRDN, c.DeleteOldRDN, c.NewSuperior))
}

// Restore sends the one Modify that restores a deleted object: delete isDeleted, replace
// distinguishedName, with the show-deleted control the session supplies.
func Restore(m ad.ObjectConn, c ad.RestoreChange) error {
	req := ldap.NewModifyRequest(c.Entry, c.Controls)
	req.Delete("isDeleted", nil)
	req.Replace("distinguishedName", []string{c.NewDN})
	return m.Modify(req)
}
