package limiter

import (
	"fmt"
	"net/netip"
)

// Prefix-length ranges the host may configure (threat model §7.8, per-IP key rule 3).
const (
	DefaultIPv4Bits = 32
	DefaultIPv6Bits = 64
	minIPv4Bits     = 24
	minIPv6Bits     = 48
)

// nat64 is the well-known NAT64 prefix (RFC 6052 §2.1).
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// checkBits fails for a prefix length outside the §7.8 ranges: IPv4 /24../32, IPv6 /48../64.
func checkBits(v4, v6 int) error {
	if v4 < minIPv4Bits || v4 > 32 {
		return fmt.Errorf("limiter: IPv4 prefix length %d is outside /%d../32", v4, minIPv4Bits)
	}
	if v6 < minIPv6Bits || v6 > 64 {
		return fmt.Errorf("limiter: IPv6 prefix length %d is outside /%d../64 (a finer key hands one /64 2^64 buckets)", v6, minIPv6Bits)
	}
	return nil
}

// ipKey derives the canonical masked prefix of a source address (§7.8 rules 1-3). It returns false
// for anything net/netip cannot parse as a bare address; the raw string is never a key.
func ipKey(raw string, v4, v6 int) (string, bool) {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	a = a.WithZone("").Unmap()
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	bits := v6
	if a.Is4() {
		bits = v4
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return "", false
	}
	return p.Masked().String(), true
}
