// Package ad is the minimum AD session layer of the connector (connector-contract §5.1, §5.3,
// threat-model §6.5): LDAPS connect to a configured DC, simple bind with the connection credential,
// rootDSE, paged streaming search and Read of one object, including the constructed attributes
// tokenGroups, allowedAttributesEffective, allowedChildClassesEffective and sDRightsEffective.
//
// Everything a caller can influence is typed. Filters are ldapfilter.Filter values rendered against a
// schema, bases are dn.ObjectRef values, attribute names pass ldapfilter.ParseAttrName, and the SD
// flags control is built from SDPart values that have no SACL member. Certificate validation is
// always on and there is no plaintext or StartTLS path. Out of scope here: change feeds, writes, DC
// discovery (the caller supplies the DC list) and the gRPC servers.
//
// Authentication is the AD-password fallback only: a simple bind over LDAPS. The primary mechanism
// (SASL GSSAPI with signing and channel binding for a gMSA or keytab identity) is still to be built.
// The bind password is a secret.Secret, exposed only inside bind(), and never stored on a Session.
// A cancelled context closes the connection, so it ends the Session.
package ad
