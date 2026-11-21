package objects

import "github.com/skenzeriq/activediq/internal/directory/objectdef"

// Fixtures of the store tests. They mirror internal/directory/objectdef's own, which are not exported.
const (
	ouA  = "11111111-1111-4111-8111-111111111111"
	fmt1 = "22222222-2222-4222-8222-222222222222"
)

func userTemplate() objectdef.Template {
	return objectdef.Template{
		Name: "Standard user", Kind: objectdef.KindUser, Provider: objectdef.ProviderAD, Purpose: objectdef.PurposeCreate,
		Fields: []objectdef.FieldRule{
			{Attribute: "givenName", Mode: objectdef.ModeEditable, Mandatory: true},
			{Attribute: "sn", Mode: objectdef.ModeEditable, Mandatory: true},
			{Attribute: "department", Mode: objectdef.ModeEditable, Default: "Sales"},
			{Attribute: "company", Mode: objectdef.ModeReadOnly, Default: "Contoso", Mandatory: true},
			{Attribute: "description", Mode: objectdef.ModeHidden},
		},
		NamingFormats:     map[objectdef.NamePurpose]objectdef.Pin{objectdef.PurposeSAMAccountName: {ID: fmt1, Version: 1}},
		DuplicateCheck:    &objectdef.DuplicateCheck{Attributes: []string{"mail"}, Scope: objectdef.ScopeForest},
		AllowedContainers: []string{ouA},
	}
}

func tok(a string, take int) objectdef.Token {
	return objectdef.Token{Kind: objectdef.TokenAttr, Attr: a, Take: take, Case: objectdef.CaseLower}
}

var sam = objectdef.NamingFormat{
	Name: "initial.surname", Purpose: objectdef.PurposeSAMAccountName, CollisionSuffix: objectdef.CollisionNumeric,
	Alternatives: []objectdef.Alternative{
		{When: objectdef.Condition{Op: objectdef.OpNotEmpty, Attr: "givenName"}, Tokens: []objectdef.Token{tok("givenName", 1), tok("sn", 0)}},
		{When: objectdef.Condition{Op: objectdef.OpAlways}, Tokens: []objectdef.Token{tok("sn", 0)}},
	},
}
