package codec

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

func TestParseInteger(t *testing.T) {
	for _, c := range []struct {
		in   string
		bits int
		want int64
		code string
	}{
		{"0", 64, 0, ""}, {"-1", 64, -1, ""}, {"512", 32, 512, ""},
		{"9223372036854775807", 64, math.MaxInt64, ""}, {"-9223372036854775808", 64, math.MinInt64, ""},
		{"2147483647", 32, math.MaxInt32, ""}, {"-2147483648", 32, math.MinInt32, ""},
		{"9223372036854775808", 64, 0, Overflow}, {"-9223372036854775809", 64, 0, Overflow},
		{"2147483648", 32, 0, Overflow}, {"-2147483649", 32, 0, Overflow}, {"4294967296", 32, 0, Overflow},
		{"99999999999999999999999999", 64, 0, Overflow},
		{"", 64, 0, BadInteger}, {"-", 64, 0, BadInteger}, {"+1", 64, 0, BadInteger}, {" 1", 64, 0, BadInteger},
		{"1 ", 64, 0, BadInteger}, {"0x10", 64, 0, BadInteger}, {"1e5", 64, 0, BadInteger}, {"-0", 64, 0, BadInteger},
		{"00", 64, 0, BadInteger}, {"0123", 64, 0, BadInteger}, {"-01", 64, 0, BadInteger},
		{"١٢٣", 64, 0, BadInteger}, {"１２３", 64, 0, BadInteger}, {"1\x00", 64, 0, BadInteger},
		{"99999999999999999999999x", 64, 0, BadInteger}, // grammar before range
	} {
		got, err := ParseInteger(c.in, c.bits)
		if Code(err) != c.code || (c.code == "" && got != c.want) {
			t.Errorf("ParseInteger(%q, %d) = %d, %v; want %d, %q", c.in, c.bits, got, err, c.want, c.code)
		}
	}
}

func TestParseIntegerAgreesWithStrconv(t *testing.T) {
	for n := int64(-2000); n <= 2000; n++ {
		s := strconv.FormatInt(n, 10)
		if got, err := ParseInteger(s, 64); err != nil || got != n {
			t.Fatalf("%q = %d, %v", s, got, err)
		}
	}
}

func TestCodeOfWrappedError(t *testing.T) {
	err := errors.Join(errors.New("x"), New(Overflow))
	if Code(err) != Overflow || Code(errors.New("plain")) != "" || Code(nil) != "" {
		t.Fatal("Code")
	}
	if New(BadFormat).Error() != "attr: BadFormat" {
		t.Fatal("message must carry the code only, never the value")
	}
}
