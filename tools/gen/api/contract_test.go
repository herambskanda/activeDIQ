package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// edit changes one file of a copy of the fixture contract: old is replaced by new (old must occur),
// or, when old is empty, the file is created with new as its content.
type edit struct{ file, old, new string }

// contract copies the fixture contract to a temp dir, applies the edits and generates from it.
func contract(t *testing.T, edits ...edit) error {
	t.Helper()
	src := filepath.Join("testdata", "fixture", "openapi")
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return writeFile(filepath.Join(dst, rel), b)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range edits {
		p := filepath.Join(dst, filepath.FromSlash(e.file))
		if e.old == "" {
			if err := writeFile(p, []byte(e.new)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), e.old) {
			t.Fatalf("%s does not contain %q", e.file, e.old)
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(b), e.old, e.new, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := fixtureConfig(t)
	cfg.Root = dst
	_, err = Generate(cfg)
	return err
}

// mustFail asserts the generator refuses the contract with a message that names every want.
func mustFail(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the generator accepted a contract it must refuse (want %q)", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the error does not name %q:\n%v", w, err)
		}
	}
}

const gadgetsHead = `paths:
  /gadgets:
    get:
      tags: [gadgets]
      operationId: listGadgets
      x-permission: gadgets.read
      x-activediq-stability: stable
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: modules/gadgets.yaml#/components/schemas/GadgetList
components:
  schemas:
    GadgetList:
      type: object
      required: [items]
      properties:
        items:
          type: array
          maxItems: 10
          items:
            type: string
            maxLength: 8
`

const gadgetsTag = "  - name: widgets\n    description: The fixture tag.\n  - name: gadgets\n"

func addGadgets(extra string) []edit {
	return []edit{
		{"modules/gadgets.yaml", "", gadgetsHead + extra},
		{"openapi.yaml", "  - name: widgets\n    description: The fixture tag.\n", gadgetsTag},
	}
}

func TestFixtureContractIsAccepted(t *testing.T) {
	if err := contract(t); err != nil {
		t.Fatal(err)
	}
	if err := contract(t, addGadgets("")...); err != nil {
		t.Fatalf("a second tag with its own components is fine: %v", err)
	}
}

func TestBundleRefusesACollision(t *testing.T) {
	// Two files declaring one component name: the bundle fails and names the component and both files.
	err := contract(t, addGadgets("    Labels:\n      type: string\n      maxLength: 4\n")...)
	mustFail(t, err, "Labels", "modules/gadgets.yaml", "modules/widgets.yaml")
}

func TestBundleRefusesACrossModuleRef(t *testing.T) {
	err := contract(t, addGadgets("    GadgetLabels:\n      type: object\n      required: [l]\n      properties:\n        l:\n          $ref: modules/widgets.yaml#/components/schemas/Labels\n")...)
	mustFail(t, err, "modules/gadgets.yaml", "modules/widgets.yaml", "Labels")
}

func TestBundleRefusesASharedRefIntoAModule(t *testing.T) {
	err := contract(t, edit{"shared/paging.yaml", "          type: [string, \"null\"]\n          maxLength: 1024", "          $ref: modules/widgets.yaml#/components/schemas/Labels"})
	mustFail(t, err, "shared/paging.yaml", "Labels")
}

func TestBundleRefusesAnOperationTagThatIsNotItsFile(t *testing.T) {
	err := contract(t, edit{"modules/widgets.yaml", "      tags: [widgets]\n      operationId: getWidget", "      tags: [other]\n      operationId: getWidget"})
	mustFail(t, err, "getWidget", "widgets")
}

func TestBundleRefusesATagMissingFromTheRoot(t *testing.T) {
	err := contract(t, edit{"modules/gadgets.yaml", "", gadgetsHead})
	mustFail(t, err, "gadgets", "root tag list")
	err = contract(t, edit{"openapi.yaml", "  - name: widgets\n", "  - name: ghosts\n  - name: widgets\n"})
	mustFail(t, err, "ghosts")
}

func TestBundleRefusesDuplicateOperationIDs(t *testing.T) {
	err := contract(t, edit{"modules/widgets.yaml", "operationId: deleteWidget", "operationId: getWidget"})
	mustFail(t, err, "getWidget")
}

func TestBundleRefusesNamesOutsideTheConventions(t *testing.T) {
	mustFail(t, contract(t, edit{"modules/widgets.yaml", "operationId: deleteWidget", "operationId: Delete_Widget"}), "Delete_Widget")
	mustFail(t, contract(t, edit{"modules/widgets.yaml", "  /widgets/export:", "  /widgets/Export/:"}), "/widgets/Export/")
	mustFail(t, contract(t, edit{"modules/widgets.yaml", "    ImportResult:", "    importResult:"}), "importResult")
	mustFail(t, contract(t, edit{"stray.yaml", "", "x: 1\n"}), "stray.yaml")
}

func TestDialectRefusesWhatRule2Bans(t *testing.T) {
	cases := []struct {
		name string
		e    edit
		want []string
	}{
		{"allOf", edit{"modules/widgets.yaml", "        count:\n          type: integer\n          minimum: 0\n          maximum: 100\n        enabled:", "        count:\n          allOf: [{type: string}]\n        enabled:"}, []string{"allOf", "WidgetCreate"}},
		{"anyOf", edit{"modules/widgets.yaml", "        enabled:\n          type: boolean", "        enabled:\n          anyOf: [{type: string}]"}, []string{"anyOf"}},
		{"not", edit{"modules/widgets.yaml", "        enabled:\n          type: boolean", "        enabled:\n          not: {type: string}"}, []string{"not"}},
		{"default", edit{"modules/widgets.yaml", "        enabled:\n          type: boolean", "        enabled:\n          type: boolean\n          default: true"}, []string{"default"}},
		{"readOnly", edit{"modules/widgets.yaml", "        enabled:\n          type: boolean", "        enabled:\n          type: boolean\n          readOnly: true"}, []string{"readOnly"}},
		{"uniqueItems", edit{"modules/widgets.yaml", "      minItems: 0\n      maxItems: 8", "      maxItems: 8\n      uniqueItems: true"}, []string{"uniqueItems"}},
		{"number", edit{"modules/widgets.yaml", "        enabled:\n          type: boolean", "        enabled:\n          type: number"}, []string{"number"}},
		{"format outside the list", edit{"modules/widgets.yaml", "          format: email", "          format: hostname"}, []string{"hostname"}},
		{"format binary inside JSON", edit{"modules/widgets.yaml", "          format: email", "          format: binary"}, []string{"binary"}},
		{"unknown x- key on a schema", edit{"modules/widgets.yaml", "      description: A request object, every optional and required form.", "      x-go-type: foo.Bar"}, []string{"x-go-type"}},
		{"unknown x- key on an operation", edit{"modules/widgets.yaml", "      operationId: getWidget\n", "      operationId: getWidget\n      x-codegen-bar: 1\n"}, []string{"x-codegen-bar"}},
		{"integer without bounds", edit{"modules/widgets.yaml", "          minimum: 0\n          maximum: 100\n        enabled:", "          minimum: 0\n        enabled:"}, []string{"maximum"}},
		{"integer beyond 2^53", edit{"modules/widgets.yaml", "          maximum: 100\n        enabled:", "          maximum: 9007199254740993\n        enabled:"}, []string{"2^53"}},
		{"pattern that does not compile", edit{"modules/widgets.yaml", "pattern: ^[a-z][a-z0-9-]*$", "pattern: ^(?=a)[a-z]*$"}, []string{"pattern"}},
		{"pattern with a backreference", edit{"modules/widgets.yaml", "pattern: ^[a-z][a-z0-9-]*$", `pattern: ^(a)\1$`}, []string{"pattern"}},
		{"map with properties", edit{"modules/widgets.yaml", "      maxProperties: 4\n      additionalProperties:", "      maxProperties: 4\n      properties:\n        a: {type: string, maxLength: 1}\n      additionalProperties:"}, []string{"Labels"}},
		{"request object that allows extra members", edit{"modules/widgets.yaml", "    WidgetPart:\n      type: object\n      required: [name]\n      additionalProperties: false", "    WidgetPart:\n      type: object\n      required: [name]"}, []string{"WidgetPart", "additionalProperties"}},
		{"response object that allows extra members", edit{"modules/widgets.yaml", "    ImportResult:\n      type: object\n", "    ImportResult:\n      type: object\n      additionalProperties: true\n"}, []string{"ImportResult"}},
		{"optional and nullable member", edit{"modules/widgets.yaml", "        contact:\n          type: string\n          format: email", "        contact:\n          type: [string, \"null\"]\n          format: email"}, []string{"contact", "nullable"}},
		{"inline object member", edit{"modules/widgets.yaml", "        enabled:\n          type: boolean", "        enabled:\n          type: object\n          additionalProperties: false\n          properties:\n            a: {type: string, maxLength: 1}"}, []string{"enabled"}},
		{"union variant without a kind const", edit{"modules/widgets.yaml", "        kind:\n          type: string\n          const: equals\n", "        kind:\n          type: string\n"}, []string{"RuleEquals", "kind"}},
		{"union variant with kind not required", edit{"modules/widgets.yaml", "      required: [kind, field, value]", "      required: [field, value]"}, []string{"RuleEquals", "kind"}},
		{"discriminator not on kind", edit{"modules/widgets.yaml", "        propertyName: kind", "        propertyName: type"}, []string{"Rule", "kind"}},
		{"two variants with one kind", edit{"modules/widgets.yaml", "          const: or", "          const: and"}, []string{"and"}},
		{"secret that is not SecretInput", edit{"modules/widgets.yaml", "        hint:\n          type: string\n          maxLength: 32", "        hint:\n          type: string\n          maxLength: 32\n          writeOnly: true"}, []string{"writeOnly"}},
		{"missing x-permission", edit{"modules/widgets.yaml", "      x-permission: widgets.read\n      x-activediq-stability: stable\n      parameters:\n        - name: widgetId", "      x-activediq-stability: stable\n      parameters:\n        - name: widgetId"}, []string{"x-permission"}},
		{"missing stability", edit{"modules/widgets.yaml", "      x-activediq-stability: preview\n", ""}, []string{"x-activediq-stability"}},
		{"deprecated without a sunset", edit{"modules/widgets.yaml", "      x-activediq-stability: preview\n", "      x-activediq-stability: preview\n      deprecated: true\n"}, []string{"sunset"}},
		{"PATCH body that is not merge-patch", edit{"modules/widgets.yaml", "          application/merge-patch+json:", "          application/json:"}, []string{"PATCH"}},
		{"GET with a body", edit{"modules/widgets.yaml", "      operationId: exportWidgets\n", "      operationId: exportWidgets\n      requestBody:\n        content:\n          application/json:\n            schema:\n              $ref: modules/widgets.yaml#/components/schemas/ImportResult\n"}, []string{"GET"}},
		{"inline error response", edit{"modules/widgets.yaml", "        \"404\":\n          $ref: shared/problems.yaml#/components/responses/NotFound\n    patch:", "        \"404\":\n          description: nope\n    patch:"}, []string{"problem"}},
		{"undeclared path parameter", edit{"modules/widgets.yaml", "  /widgets/export:", "  /widgets/export/{nope}:"}, []string{"nope"}},
		{"query parameter holding a secret", edit{"modules/widgets.yaml", "        - name: active\n          in: query\n          required: false\n          schema:\n            type: boolean", "        - name: active\n          in: query\n          required: false\n          schema:\n            $ref: shared/secret.yaml#/components/schemas/SecretInput"}, []string{"active"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustFail(t, contract(t, c.e), c.want...)
		})
	}
}

func TestDialectRefusesAnEnumInARequestAndAResponse(t *testing.T) {
	// WidgetSize is a closed request enum; using it in a response member makes it reachable from both.
	err := contract(t, edit{"modules/widgets.yaml", "        expires:\n          type: string\n          format: date\n    WidgetPage:", "        expires:\n          type: string\n          format: date\n        size:\n          $ref: modules/widgets.yaml#/components/schemas/WidgetSize\n    WidgetPage:"})
	mustFail(t, err, "WidgetSize", "request", "response")
}

func TestDialectRefusesAClosedResponseEnum(t *testing.T) {
	err := contract(t, edit{"modules/widgets.yaml", "      x-activediq-enum: open\n", ""})
	mustFail(t, err, "WidgetStatus", "open")
}

func TestDialectRefusesAnUnreachableSecretInAResponse(t *testing.T) {
	err := contract(t, edit{"modules/widgets.yaml", "        expires:\n          type: string\n          format: date\n    WidgetPage:", "        expires:\n          type: string\n          format: date\n        token:\n          $ref: shared/secret.yaml#/components/schemas/SecretInput\n    WidgetPage:"})
	mustFail(t, err, "SecretInput", "Widget")
}

func TestDialectRefusesNullInsideAPatchArray(t *testing.T) {
	err := contract(t, edit{"modules/widgets.yaml", "        labels:\n          $ref: modules/widgets.yaml#/components/schemas/Labels\n    WidgetCredential:", "        labels:\n          $ref: modules/widgets.yaml#/components/schemas/Labels\n        parts:\n          type: array\n          maxItems: 2\n          items:\n            type: string\n            maxLength: 2\n    WidgetCredential:"})
	mustFail(t, err, "WidgetPatch", "parts")
}
