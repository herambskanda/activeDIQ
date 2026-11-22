package read

// readEmptyOK lists the attributes a live search may report as "read, empty" when the DC omits
// them. A DC omits an attribute with no value and one the caller may not read identically, so the
// claim is made only for attributes that are never confidential and carry the default
// Authenticated-Users read grant. Anything else omitted stays "not read".
var readEmptyOK = map[string]bool{
	"lockouttime": true, "accountexpires": true, "manager": true, "mail": true, "description": true,
	"displayname": true, "givenname": true, "sn": true, "title": true, "department": true,
	"company": true, "telephonenumber": true, "userprincipalname": true, "badpwdcount": true,
	"managedby": true, "info": true, "lastlogontimestamp": true,
}

// Deliberately NOT listed: servicePrincipalName, sIDHistory, msDS-AllowedToDelegateTo, member,
// memberOf, scriptPath, homeDirectory. An owner of an object can add a deny-read ACE for the
// service account and turn "has an SPN / SID history / delegation / members" into a confident
// negative. They re-enter only behind T-1536's denial detection.
