package authn

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; HMAC-SHA-1 is not weakened by SHA-1 collisions and authenticator apps expect it.
	"crypto/subtle"
	"encoding/binary"
	"time"
)

// RFC 6238 parameters. Fixed: authenticator apps agree on them and the otpauth URI the caller builds
// states them.
const (
	// StepSeconds is the time step X of RFC 6238 §4.
	StepSeconds = 30
	// Digits is the code length.
	Digits = 6
	// SeedBytes is the seed length: 160 bits, the HMAC-SHA-1 output size RFC 4226 §4 recommends.
	SeedBytes = 20
	// WindowSteps is how many steps either side of the current one are accepted (clock drift).
	WindowSteps = 1
)

const modulus = 1_000_000 // 10^Digits

// stepAt is the time step counter T of RFC 6238 §4 for t.
func stepAt(t time.Time) int64 { return t.Unix() / StepSeconds }

// hotp is RFC 4226 §5.3 with dynamic truncation, reduced to Digits digits.
func hotp(seed []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	n := bin % modulus
	var out [Digits]byte
	for i := Digits - 1; i >= 0; i-- {
		out[i] = byte('0' + n%10)
		n /= 10
	}
	return string(out[:])
}

// validCodeText reports whether code is exactly Digits ASCII digits.
func validCodeText(code string) bool {
	if len(code) != Digits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// matchStep checks code against every step in the window around now, comparing all of them in
// constant time with no early exit. It returns the highest matching step above `after` (the last
// accepted step, -1 for none) and ok. When code matches only steps at or below `after`, replayed is
// true: the code was valid but already spent (or older than one that was).
func matchStep(seed []byte, code string, now time.Time, after int64) (step int64, ok, replayed bool) {
	cur := stepAt(now)
	var fresh, stale int
	for s := cur - WindowSteps; s <= cur+WindowSteps; s++ {
		if s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(seed, s)), []byte(code)) != 1 {
			continue
		}
		if s > after {
			fresh |= 1
			step = s // ascending loop: ends on the highest
		} else {
			stale |= 1
		}
	}
	return step, fresh == 1, fresh == 0 && stale == 1
}
