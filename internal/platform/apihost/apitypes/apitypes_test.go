package apitypes

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
)

func strict() json.Options { return json.RejectUnknownMembers(true) }

func TestUUID(t *testing.T) {
	var u UUID
	if err := json.Unmarshal([]byte(`"3F2504E0-4F89-11D3-9A0C-0305E82C3301"`), &u, strict()); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(u)
	if string(out) != `"3f2504e0-4f89-11d3-9a0c-0305e82c3301"` {
		t.Fatalf("encode is lower case: %s", out)
	}
	for _, bad := range []string{`""`, `"3f2504e0-4f89-11d3-9a0c-0305e82c330"`, `"3f2504e04f8911d39a0c0305e82c3301"`, `"{3f2504e0-4f89-11d3-9a0c-0305e82c3301}"`, `"zf2504e0-4f89-11d3-9a0c-0305e82c3301"`, `5`} {
		if err := json.Unmarshal([]byte(bad), &u, strict()); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestDateAndTimestamp(t *testing.T) {
	var d Date
	if err := json.Unmarshal([]byte(`"2024-02-29"`), &d, strict()); err != nil || d.String() != "2024-02-29" {
		t.Fatalf("leap day: %v %v", d, err)
	}
	for _, bad := range []string{`"2025-02-29"`, `"2025-2-9"`, `"2025-02-09T00:00:00Z"`, `"20250209"`} {
		if err := json.Unmarshal([]byte(bad), &d, strict()); err == nil {
			t.Errorf("date %s must be refused", bad)
		}
	}
	var ts Timestamp
	if err := json.Unmarshal([]byte(`"2026-10-02T12:00:00+05:30"`), &ts, strict()); err != nil {
		t.Fatal(err)
	}
	if ts.Time().Location() != time.UTC || ts.Time().Hour() != 6 {
		t.Fatalf("an offset decodes to UTC: %v", ts.Time())
	}
	out, _ := json.Marshal(ts)
	if string(out) != `"2026-10-02T06:30:00Z"` {
		t.Fatalf("always UTC with Z: %s", out)
	}
	for _, bad := range []string{`"2026-10-02"`, `"2026-10-02 12:00:00Z"`, `"yesterday"`} {
		if err := json.Unmarshal([]byte(bad), &ts, strict()); err == nil {
			t.Errorf("timestamp %s must be refused", bad)
		}
	}
}

func TestInt64String(t *testing.T) {
	var n Int64String
	for in, want := range map[string]int64{`"9007199254740993"`: 9007199254740993, `"-9223372036854775808"`: -9223372036854775808, `"0"`: 0} {
		if err := json.Unmarshal([]byte(in), &n, strict()); err != nil || int64(n) != want {
			t.Errorf("%s: %v %v", in, n, err)
		}
	}
	for _, bad := range []string{`"9223372036854775808"`, `"1e3"`, `"+1"`, `""`, `"-"`, `1`, `"1 "`} {
		if err := json.Unmarshal([]byte(bad), &n, strict()); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	out, _ := json.Marshal(Int64String(7))
	if string(out) != `"7"` {
		t.Fatal(string(out))
	}
}

func TestOptThreeStates(t *testing.T) {
	type body struct {
		A Opt[string] `json:"a,omitzero"`
		B Opt[string] `json:"b,omitzero"`
		C Opt[int64]  `json:"c,omitzero"`
	}
	var b body
	if err := json.Unmarshal([]byte(`{"a":null,"b":"x"}`), &b, strict()); err != nil {
		t.Fatal(err)
	}
	if !b.A.Present() || !b.A.IsNull() || b.B.IsNull() || b.C.Present() {
		t.Fatalf("%+v", b)
	}
	if v, ok := b.B.Value(); !ok || v != "x" {
		t.Fatal("value")
	}
	if b.A.Ptr() != nil || b.C.Ptr() != nil || *b.B.Ptr() != "x" {
		t.Fatal("Ptr is nil unless a value is held")
	}
	out, err := json.Marshal(b)
	if err != nil || string(out) != `{"a":null,"b":"x"}` {
		t.Fatalf("%s %v", out, err)
	}
	if err := json.Unmarshal([]byte(`{"c":"x"}`), &b, strict()); err == nil {
		t.Fatal("a wrong type is refused")
	}
	if got, _ := json.Marshal(body{A: Some("q"), C: Null[int64]()}); string(got) != `{"a":"q","c":null}` {
		t.Fatalf("%s", got)
	}
}

func TestPresence(t *testing.T) {
	var p Presence
	if p.Decoded() {
		t.Fatal("a zero Presence belongs to a value built in code")
	}
	p.Begin()
	p.Mark(3, false)
	p.Mark(63, true)
	if !p.Decoded() || !p.Has(3) || p.IsNull(3) || !p.Has(63) || !p.IsNull(63) || p.Has(4) {
		t.Fatalf("%+v", p)
	}
}

func TestDecodeArrayAndMapRefuseNull(t *testing.T) {
	var s []string
	d := jsontext.NewDecoder(strings.NewReader(`["a",null]`))
	err := DecodeArray(d, &s)
	if v, ok := ViolationOf(err); !ok || v.Code != CodeNull {
		t.Fatalf("%v", err)
	}
	var m map[string]string
	d = jsontext.NewDecoder(strings.NewReader(`{"a":"x","b":null}`))
	if v, ok := ViolationOf(DecodeMap(d, &m)); !ok || v.Code != CodeNull {
		t.Fatal("a null map value is a violation")
	}
	d = jsontext.NewDecoder(strings.NewReader(`["a","b"]`))
	if err := DecodeArray(d, &s); err != nil || len(s) != 2 {
		t.Fatalf("%v %v", s, err)
	}
	d = jsontext.NewDecoder(strings.NewReader(`[]`))
	if err := DecodeArray(d, &s); err != nil || s == nil || len(s) != 0 {
		t.Fatal("an empty array decodes to an empty, non-nil slice, so absent and empty differ")
	}
}

func TestChecks(t *testing.T) {
	var e Errors
	CheckLen(&e, InBody, "/a", strings.Repeat("é", 5), 1, 4)
	CheckLen(&e, InBody, "/b", "", 1, -1)
	CheckInt(&e, InQuery, "limit", 0, 1, 10)
	CheckInt(&e, InQuery, "limit", 11, 1, 10)
	CheckCount(&e, InBody, "/c", 3, 0, 2, CodeMaxItems)
	CheckCount(&e, InBody, "/d", 0, 1, -1, CodeMaxItems)
	got := []string{}
	for _, v := range e.All() {
		got = append(got, v.Code)
	}
	want := []string{CodeMaxLength, CodeMinLength, CodeMinimum, CodeMaximum, CodeMaxItems, CodeMinItems}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	for in, ok := range map[string]bool{"a@example.com": true, "Bob <b@example.com>": false, "": false, "a@b@c": false, "a@example.com (c)": false, strings.Repeat("a", 250) + "@b.co": false} {
		if CheckEmail(in) != ok {
			t.Errorf("CheckEmail(%q) should be %v", in, ok)
		}
	}
}

func TestViolationOf(t *testing.T) {
	var s struct{ A int }
	err := json.Unmarshal([]byte(`{"A":"x"}`), &s, strict())
	if v, ok := ViolationOf(err); !ok || v.Code != CodeType || v.Pointer != "/A" {
		t.Fatalf("a wrong JSON type: %+v %v", v, ok)
	}
	err = json.Unmarshal([]byte(`{"B":1}`), &s, strict())
	if v, ok := ViolationOf(err); !ok || v.Code != CodeUnknownMember {
		t.Fatalf("an unknown member: %+v %v", v, ok)
	}
	if _, ok := ViolationOf(json.Unmarshal([]byte(`{"A":1,"A":2}`), &s, strict())); ok {
		t.Fatal("a duplicate member is malformed input, not a violation")
	}
	if _, ok := ViolationOf(errors.New("other")); ok {
		t.Fatal("a plain error is not a violation")
	}
	wrapped := Rebase("/rule", &ViolationError{Violation{Pointer: "/kind", Code: CodeKind}})
	if v, _ := ViolationOf(wrapped); v.Pointer != "/rule/kind" {
		t.Fatalf("Rebase: %v", v.Pointer)
	}
}

func TestViolationDetailNeverEchoesInput(t *testing.T) {
	var u UUID
	err := json.Unmarshal([]byte(`"hunter2-not-a-uuid"`), &u, strict())
	if err == nil {
		t.Fatal("expected an error")
	}
	if v, ok := ViolationOf(err); ok && strings.Contains(v.Detail, "hunter2") {
		t.Fatalf("a violation detail must not echo the rejected value: %q", v.Detail)
	}
}

func TestUnionKind(t *testing.T) {
	k, err := UnionKind("/x", jsontext.Value(`{"a":[1,{"kind":"no"}],"kind":"and"}`))
	if err != nil || k != "and" {
		t.Fatalf("only the top-level kind counts: %q %v", k, err)
	}
	for _, bad := range []string{`{"Kind":"and"}`, `{"kind":1}`, `{}`, `[]`, `"and"`} {
		if _, err := UnionKind("/x", jsontext.Value(bad)); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestProblemIsAnError(t *testing.T) {
	var e Errors
	e.Add(InBody, "/a", CodeRequired, "x")
	p := newProblem("/problems/validation", "The request is invalid", 400, "").WithErrors(&e)
	var err error = p
	if !strings.Contains(err.Error(), "/problems/validation") || len(p.Errors) != 1 || p.Detail != nil {
		t.Fatalf("%+v", p)
	}
}
