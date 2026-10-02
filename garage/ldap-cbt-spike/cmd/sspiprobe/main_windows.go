//go:build windows

package main

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
)

var _ ldap.GSSAPIClient = (*gssapi.SSPIClient)(nil)

func main() {}
