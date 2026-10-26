package authn

import (
	"testing"
	"time"
)

var rfcSeed = []byte("12345678901234567890")

// RFC 6238 Appendix B, SHA-1 column. The RFC prints 8 digits; 6 digits are the last six of the same
// truncated value.
func Test_totp_rfc6238_vectors(t *testing.T) {
	for _, v := range []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		now := time.Unix(v.unix, 0)
		if got := hotp(rfcSeed, stepAt(now)); got != v.code {
			t.Errorf("T=%d: hotp = %s, want %s", v.unix, got, v.code)
		}
		step, ok, _ := matchStep(rfcSeed, v.code, now, -1)
		if !ok || step != stepAt(now) {
			t.Errorf("T=%d: matchStep = %d, %v", v.unix, step, ok)
		}
	}
}

func Test_totp_window(t *testing.T) {
	now := time.Unix(1111111109, 0)
	cur := stepAt(now)
	for off := int64(-3); off <= 3; off++ {
		code := hotp(rfcSeed, cur+off)
		_, ok, _ := matchStep(rfcSeed, code, now, -1)
		want := off >= -1 && off <= 1
		if ok != want {
			t.Errorf("step offset %d: accepted = %v, want %v", off, ok, want)
		}
	}
}

func Test_totp_code_text(t *testing.T) {
	for _, c := range []string{"", "12345", "1234567", "12345a", " 23456", "１２３４５６"} {
		if validCodeText(c) {
			t.Errorf("%q accepted", c)
		}
	}
	if !validCodeText("000123") {
		t.Error("leading zeros must be valid")
	}
}
