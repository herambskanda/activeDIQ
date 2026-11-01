// Package ad is the minimum AD session layer of the connector (connector-contract §5.1, §5.3,
// threat-model §6.5): LDAPS connect to a configured DC, simple bind with the connection credential,
// rootDSE, paged streaming search and Read of one object, including the constructed attributes
// tokenGroups, allowedAttributesEffective, allowedChildClassesEffective and sDRightsEffective.
//
// Everything a caller can influence is typed. Filters are ldapfilter.Filter values rendered against a
// schema, bases are dn.ObjectRef values, attribute names pass ldapfilter.ParseAttrName, and the SD
// flags control is built from SDPart values that have no SACL member. Certificate validation is
// always on and there is no plaintext or StartTLS path. The one write is Session.WriteDACL (sdwrite.go):
// a VerifyBase-gated replace of nTSecurityDescriptor with the DACL-only SD_FLAGS control, on the bound
// DC. The DirSync primitive (dirsync.go, controls in package scope) is the change feed's connector half:
// object-security mode, show-deleted, incremental values decoded into set/cleared/added/removed, the
// mandatory attribute set, SecretAttrs refused when named and stripped when unrequested. Out of scope here: the gRPC feed, cookie pre-checks, other writes, DC
// discovery (the caller supplies the DC list) and the gRPC servers.
//
// Authentication is one of two, never both: SASL GSSAPI (Config.Kerberos, the primary mechanism: a
// keytab for a gMSA or service account, AES enctypes only) or the AD-password fallback, a simple
// bind over LDAPS. The GSSAPI bind (kerberos.go, adapter in package gssapi) carries the RFC 5929
// tls-server-end-point channel binding of the certificate the DC presented on every bind, never
// binds without one, and selects SASL security layer "none" (RFC 4752): TLS is the protection and AD
// forbids a SASL layer on top of it. The SPN is ldap/<DC DNS name>, so IP-only servers need ServerName.
// The bind password and the keytab are secret.Secret values, exposed only while binding, and never stored on a Session.
// A cancelled context closes the connection, so it ends the Session.
package ad
