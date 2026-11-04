package read

// readEmptyOK lists the attributes a live search may report as "read, empty" when the DC omits
// them. A DC omits an attribute with no value and one the caller may not read identically, so the
// claim is made only for attributes that are never confidential and carry the default
// Authenticated-Users read grant. Anything else omitted stays "not read".
var readEmptyOK = map[string]bool{
	"lockouttime": true, "member": true, "memberof": true, "serviceprincipalname": true,
	"accountexpires": true, "manager": true, "mail": true, "description": true,
	"displayname": true, "givenname": true, "sn": true, "title": true, "department": true,
	"company": true, "telephonenumber": true, "userprincipalname": true, "badpwdcount": true,
	"managedby": true, "info": true, "homedirectory": true, "scriptpath": true,
	"msds-allowedtodelegateto": true, "sidhistory": true, "lastlogontimestamp": true,
}
