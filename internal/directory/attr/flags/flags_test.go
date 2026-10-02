package flags

import (
	"encoding/json"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

func names(raw json.RawMessage) []string {
	var out []string
	_ = json.Unmarshal(raw, &out)
	return out
}

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/attr-flags", "attr.flags", func(r corpus.Record) (corpus.Result, error) {
		in, err := r.Arg("value")
		if err != nil {
			return corpus.Result{}, err
		}
		switch r.Call {
		case "DecodeUAC":
			u, err := DecodeUAC(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Value(map[string]any{"flags": u.Names(), "unknown": u.Unknown(), "encoded": u.Encode()})
		case "DecodeUACComputed":
			u, err := DecodeUACComputed(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Value(map[string]any{"lockedOut": u.LockedOut(), "passwordExpired": u.PasswordExpired(), "unknown": u.Unknown(), "encoded": u.Encode()})
		case "DecodeGroupType":
			g, err := DecodeGroupType(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			out := map[string]any{"flags": g.Names(), "unknown": g.Unknown(), "security": g.IsSecurity(), "encoded": g.Encode()}
			if sc, err := g.Scope(); err != nil {
				out["scopeError"] = codec.Code(err)
			} else {
				out["scope"] = string(sc)
			}
			return corpustest.Value(out)
		case "ApplyUAC":
			u, err := DecodeUAC(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			var c Change
			for _, side := range []struct {
				key string
				dst *[]UACFlag
			}{{"set", &c.Set}, {"clear", &c.Clear}} {
				for _, n := range names(r.Args[side.key]) {
					f, ok := ParseUACFlag(n)
					if !ok {
						return corpustest.Err(UnknownFlag), nil
					}
					*side.dst = append(*side.dst, f)
				}
			}
			var priv Privileges
			_ = json.Unmarshal(r.Args["enableDelegation"], &priv.EnableDelegation)
			e, err := u.Apply(c, priv)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Value(map[string]string{"old": e.Old.Encode(), "new": e.New.Encode()})
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

// The stored UAC bits LOCKOUT and PASSWORD_EXPIRED are not interpreted: they come back as unknown
// bits, survive a round trip, and the type has no accessor for either.
func TestStoredUnreliableBitsAreCarriedNotInterpreted(t *testing.T) {
	u, err := DecodeUAC("8388624") // 0x800010 + 0 normal bit
	if err != nil {
		t.Fatal(err)
	}
	if u.Unknown() != 0x800010 || u.Encode() != "8388624" {
		t.Fatalf("Unknown = %#x, Encode = %s", u.Unknown(), u.Encode())
	}
}

func TestApplyEditCarriesOldAndNewForCompareAndSwap(t *testing.T) {
	u, _ := DecodeUAC("514")
	e, err := u.Apply(Change{Clear: []UACFlag{UACAccountDisable}}, Privileges{})
	if err != nil || e.Old.Encode() != "514" || e.New.Encode() != "512" {
		t.Fatalf("Edit = %+v, %v", e, err)
	}
	if _, err := u.Apply(Change{Set: []UACFlag{UACAccountDisable | UACScript}}, Privileges{}); codec.Code(err) != UnknownFlag {
		t.Fatalf("a multi-bit flag must be refused, got %v", err)
	}
	if _, err := u.Apply(Change{Set: []UACFlag{0}}, Privileges{}); codec.Code(err) != UnknownFlag {
		t.Fatalf("the zero flag must be refused, got %v", err)
	}
	if _, err := u.Apply(Change{Set: []UACFlag{0x20000000}}, Privileges{}); codec.Code(err) != UnknownFlag {
		t.Fatalf("a bit outside the table must be refused, got %v", err)
	}
	if _, err := u.Apply(Change{Set: []UACFlag{UACTrustedToAuthForDelegation}}, Privileges{}); codec.Code(err) != PrivilegeRequired {
		t.Fatalf("protocol transition needs the capability, got %v", err)
	}
}

func TestGroupTypeScopeNeedsExactlyOne(t *testing.T) {
	for raw, want := range map[string]string{"-2147483646": "global", "-2147483644": "domainLocal", "-2147483640": "universal", "-2147483643": "domainLocal"} {
		g, err := DecodeGroupType(raw)
		if err != nil {
			t.Fatal(err)
		}
		if sc, err := g.Scope(); err != nil || string(sc) != want {
			t.Errorf("%s: scope %q, %v; want %s", raw, sc, err, want)
		}
	}
	for _, raw := range []string{"0", "-2147483648", "1", "14"} {
		g, _ := DecodeGroupType(raw)
		if _, err := g.Scope(); codec.Code(err) != InvalidScope {
			t.Errorf("%s: want InvalidScope, got %v", raw, err)
		}
	}
	if g, _ := DecodeGroupType("-2147483643"); !g.IsBuiltin() || !g.IsSecurity() {
		t.Error("the builtin groups are security, builtin, domain local")
	}
}

func FuzzFlags(f *testing.F) {
	corpustest.Seed(f, "attr.flags")
	f.Fuzz(func(t *testing.T, in []byte) {
		raw := string(in)
		if u, err := DecodeUAC(raw); err == nil { // roundtrip: every bit survives
			enc := u.Encode()
			checkRaw(t, enc)
			u2, err := DecodeUAC(enc)
			if err != nil || u2 != u {
				t.Fatalf("DecodeUAC(Encode()) = %v, %v; want %v", u2, err, u)
			}
			// A change built from the value's own bits never loses a bit it did not clear, and never
			// moves a bit that is not settable.
			for _, f := range []UACFlag{UACAccountDisable, UACDontExpirePassword, UACNormalAccount} {
				e, err := u.Apply(Change{Set: []UACFlag{f}}, Privileges{})
				if err != nil {
					t.Fatal(err)
				}
				if e.New.bits != u.bits|uint32(f) || e.New.Unknown() != u.Unknown() {
					t.Fatalf("Apply set %v on %d gave %d", f, u.bits, e.New.bits)
				}
			}
			if e, err := u.Apply(Change{Clear: []UACFlag{UACAccountDisable}}, Privileges{}); err != nil || (e.New.bits^u.bits)&^uint32(UACAccountDisable) != 0 {
				t.Fatalf("clearing one flag changed others: %d -> %d, %v", u.bits, e.New.bits, err)
			}
		}
		if u, err := DecodeUACComputed(raw); err == nil {
			enc := u.Encode()
			checkRaw(t, enc)
			if u2, err := DecodeUACComputed(enc); err != nil || u2 != u {
				t.Fatalf("DecodeUACComputed(Encode()) = %v, %v; want %v", u2, err, u)
			}
		}
		if g, err := DecodeGroupType(raw); err == nil {
			enc := g.Encode()
			checkRaw(t, enc)
			if g2, err := DecodeGroupType(enc); err != nil || g2 != g {
				t.Fatalf("DecodeGroupType(Encode()) = %v, %v; want %v", g2, err, g)
			}
		}
	})
}

// noUnescapedSpecial: an encoded flag integer is an optional minus sign and ASCII digits.
func checkRaw(t *testing.T, enc string) {
	t.Helper()
	body := enc
	if len(body) > 0 && body[0] == '-' {
		body = body[1:]
	}
	if body == "" {
		t.Fatal("empty encoding")
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			t.Fatalf("encoding %q holds %q", enc, body[i])
		}
	}
	corpustest.NoUnescapedSpecial(t, body, "*()\\\x00<>,;\"+= #{}\r\n\t")
}
