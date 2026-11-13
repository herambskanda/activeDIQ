package objects

import (
	"errors"
	"testing"
)

const (
	ouA  = "11111111-1111-4111-8111-111111111111"
	fmt1 = "22222222-2222-4222-8222-222222222222"
)

func userTemplate() Template {
	return Template{
		Name: "Standard user", Kind: KindUser, Provider: ProviderAD, Purpose: PurposeCreate,
		Fields: []FieldRule{
			{Attribute: "givenName", Mode: ModeEditable, Mandatory: true},
			{Attribute: "sn", Mode: ModeEditable, Mandatory: true},
			{Attribute: "department", Mode: ModeEditable, Default: "Sales"},
			{Attribute: "company", Mode: ModeReadOnly, Default: "Contoso", Mandatory: true},
			{Attribute: "description", Mode: ModeHidden},
		},
		NamingFormats:     map[NamePurpose]Pin{PurposeSAMAccountName: {ID: fmt1, Version: 1}},
		DuplicateCheck:    &DuplicateCheck{Attributes: []string{"mail"}, Scope: ScopeForest},
		AllowedContainers: []string{ouA},
	}
}

func TestMandatoryFieldBlocksNamingTheField(t *testing.T) {
	tpl := userTemplate()
	if err := tpl.Validate(); err != nil {
		t.Fatal(err)
	}
	vs := tpl.CheckInput(Input{"givenName": "Jane", "sn": " "})
	if len(vs) != 1 || vs[0].Field != "sn" {
		t.Fatalf("violations = %v", vs)
	}
	if vs := tpl.CheckInput(Input{"givenName": "Jane", "sn": "Smith"}); len(vs) != 0 {
		t.Fatalf("clean input blocked: %v", vs)
	}
}

func TestHiddenAndReadOnly(t *testing.T) {
	tpl := userTemplate()
	vs := tpl.CheckInput(Input{"givenName": "J", "sn": "S", "description": "x", "company": "Other"})
	got := map[string]bool{}
	for _, v := range vs {
		got[v.Field] = true
	}
	if len(vs) != 2 || !got["description"] || !got["company"] {
		t.Fatalf("violations = %v", vs)
	}
	if vs := tpl.CheckInput(Input{"givenName": "J", "sn": "S", "company": "contoso"}); len(vs) != 0 {
		t.Fatalf("repeating the read-only default is fine: %v", vs)
	}
	eff := tpl.Effective(Input{"givenName": "J", "sn": "S"})
	if eff["department"] != "Sales" || eff["company"] != "Contoso" {
		t.Fatalf("defaults not applied: %v", eff)
	}
}

func TestTemplateValidate(t *testing.T) {
	mut := func(f func(*Template)) Template { t := userTemplate(); f(&t); return t }
	bad := map[string]Template{
		"kind":              mut(func(t *Template) { t.Kind = "server" }),
		"provider":          mut(func(t *Template) { t.Provider = "ldap" }),
		"duplicate field":   mut(func(t *Template) { t.Fields = append(t.Fields, FieldRule{Attribute: "SN", Mode: ModeEditable}) }),
		"hidden mandatory":  mut(func(t *Template) { t.Fields = []FieldRule{{Attribute: "x", Mode: ModeHidden, Mandatory: true}} }),
		"container is a DN": mut(func(t *Template) { t.AllowedContainers = []string{"OU=Sales,DC=corp,DC=example"} }),
		"naming for wrong kind": mut(func(t *Template) {
			t.Kind = KindOU
			t.NamingFormats = map[NamePurpose]Pin{PurposeSAMAccountName: {ID: fmt1, Version: 1}}
		}),
		"unpinned version":  mut(func(t *Template) { t.NamingFormats = map[NamePurpose]Pin{PurposeCN: {ID: fmt1}} }),
		"entra scope on ad": mut(func(t *Template) { t.DuplicateCheck.Scope = ScopeEntra }),
		"password on group": mut(func(t *Template) {
			t.Kind = KindGroup
			t.NamingFormats = nil
			t.PasswordPolicy = &Pin{ID: fmt1, Version: 1}
		}),
		"pick list not an ID": mut(func(t *Template) { t.Fields[2].PickList = "departments" }),
	}
	for n, tpl := range bad {
		err := tpl.Validate()
		var ve *ViolationError
		if !errors.As(err, &ve) {
			t.Errorf("%s: accepted or untyped: %v", n, err)
		}
	}
}

func TestContainerAllowed(t *testing.T) {
	tpl := userTemplate()
	if !tpl.ContainerAllowed("11111111-1111-4111-8111-111111111111") || tpl.ContainerAllowed("33333333-3333-4333-8333-333333333333") {
		t.Fatal("allowed-container list not honoured")
	}
	tpl.AllowedContainers = nil
	if !tpl.ContainerAllowed("33333333-3333-4333-8333-333333333333") {
		t.Fatal("an empty list should not restrict")
	}
}
