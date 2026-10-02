package tenant

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNewIsRandomV4(t *testing.T) {
	seen := map[ID]bool{}
	for range 1000 {
		id := New()
		if id.IsZero() {
			t.Fatal("New returned the zero ID")
		}
		if seen[id] {
			t.Fatalf("New repeated %s", id)
		}
		seen[id] = true
		s := id.String()
		if s[14] != '4' || !strings.ContainsRune("89ab", rune(s[19])) {
			t.Fatalf("%s is not a version 4 / RFC 4122 UUID", s)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	for range 100 {
		id := New()
		got, err := Parse(id.String())
		if err != nil || got != id {
			t.Fatalf("Parse(%s) = %v, %v", id, got, err)
		}
		up, err := Parse(strings.ToUpper(id.String()))
		if err != nil || up != id {
			t.Fatalf("Parse(upper %s) = %v, %v", id, up, err)
		}
		if up.String() != id.String() {
			t.Fatalf("String is not canonical lower case: %s", up)
		}
	}
}

// SQL-03: a hostile tenant string fails UUID parsing, before any SQL could see it. (The literal
// `x'; SET ROLE postgres; --` vector is in store's test: T5 keeps SET text out of every package but store.)
func TestParseRejectsHostileStrings(t *testing.T) {
	for name, s := range map[string]string{
		"tautology":        "' OR '1'='1",
		"empty":            "",
		"nil uuid":         "00000000-0000-0000-0000-000000000000",
		"braces":           "{3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f}",
		"urn":              "urn:uuid:3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f",
		"no hyphens":       "3f2b8a405c1d4e6a9b7f0a1b2c3d4e5f",
		"trailing space":   "3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f ",
		"leading newline":  "\n3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5",
		"quote inside":     "3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e'f",
		"non hex":          "3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5g",
		"hyphen misplaced": "3f2b8a405-c1d-4e6a-9b7f-0a1b2c3d4e5f",
		"NUL":              "3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5\x00",
		"unicode digit":    "3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5٣",
		"too long":         "3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f0",
		"two uuids":        "3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f,3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f",
		"drop table":       "'; DROP TABLE tenants; --",
	} {
		t.Run(name, func(t *testing.T) {
			id, err := Parse(s)
			if err == nil || !id.IsZero() {
				t.Fatalf("Parse(%q) = %v, %v; want an error and the zero ID", s, id, err)
			}
			if strings.Contains(err.Error(), s) && s != "" {
				t.Fatalf("the error echoes the input: %v", err)
			}
		})
	}
}

func TestZeroValue(t *testing.T) {
	var id ID
	if !id.IsZero() {
		t.Fatal("the zero value must be IsZero")
	}
	if got := id.String(); got != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("zero String = %q", got)
	}
}

// ADR-0002 rule 5: no decoder may mint an ID from input. T5 checks this statically; this keeps the
// failure local to the package that owns the type.
func TestNoDecoderMethods(t *testing.T) {
	typ := reflect.TypeOf(&ID{})
	for _, name := range []string{"UnmarshalJSON", "UnmarshalText", "UnmarshalBinary", "UnmarshalYAML", "Scan", "Set", "DecodeValue"} {
		if _, ok := typ.MethodByName(name); ok {
			t.Errorf("tenant.ID has a %s method", name)
		}
	}
	var into struct{ T ID }
	// The unexported field cannot be filled by encoding/json: the document is accepted and ignored.
	if err := json.Unmarshal([]byte(`{"T":"3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f"}`), &into); err == nil && !into.T.IsZero() {
		t.Fatalf("encoding/json minted a tenant ID: %v", into.T)
	}
}

func TestMarshalText(t *testing.T) {
	id := New()
	b, err := json.Marshal(id)
	if err != nil || string(b) != `"`+id.String()+`"` {
		t.Fatalf("json.Marshal = %s, %v", b, err)
	}
}
