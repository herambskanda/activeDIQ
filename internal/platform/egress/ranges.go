package egress

import "net/netip"

// blocked are the ranges refused unless the operator allow-lists them. Public addresses are not
// listed: anything outside these ranges is permitted.
var blocked = mustPrefixes(
	"0.0.0.0/8",       // "this network", unspecified
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // CGNAT (also Alibaba metadata 100.100.100.200)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, AWS/Azure/GCP metadata
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments (Oracle metadata 192.0.0.192)
	"192.0.2.0/24",    // documentation
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, broadcast
	"::/128",          // unspecified
	"::1/128",         // loopback
	"::/96",           // deprecated IPv4-compatible
	"::ffff:0:0:0/96", // RFC 2765/6145 IPv4-translated (SIIT): embeds an IPv4 destination
	"64:ff9b::/96",    // NAT64: embeds an IPv4 destination
	"64:ff9b:1::/48",  // RFC 8215 local-use NAT64: embeds an IPv4 destination
	"100::/64",        // discard-only
	"2001::/32",       // Teredo
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4: embeds an IPv4 destination
	"fc00::/7",        // unique local, includes fd00:ec2::254 (AWS metadata)
	"fe80::/10",       // link-local
	"ff00::/8",        // multicast
)

// metadata are the cloud instance-metadata endpoints; no allow-list entry may cover one.
var metadata = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("169.254.170.2"),
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("192.0.0.192"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("168.63.129.16"), // Azure WireServer: public range, platform-only, known SSRF target
}

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// permitted reports whether ip (already unmapped) may be dialled.
func permitted(ip netip.Addr, allow []netip.Prefix) bool {
	if !ip.IsValid() {
		return false
	}
	for _, m := range metadata {
		if ip == m {
			return false
		}
	}
	for _, b := range blocked {
		if b.Contains(ip) {
			for _, a := range allow {
				if a.Contains(ip) {
					return true
				}
			}
			return false
		}
	}
	return true
}

// coversMetadata reports whether an allow-list prefix would include a metadata address.
// translation are the prefixes that embed an IPv4 destination. An allow-list entry overlapping one
// would reach metadata through the embedded address, which the exact-match metadata check cannot
// see; operators allow-list the IPv4 range instead.
var translation = mustPrefixes("::/96", "::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")

func overlapsTranslation(p netip.Prefix) bool {
	for _, t := range translation {
		if p.Overlaps(t) {
			return true
		}
	}
	return false
}

func coversMetadata(p netip.Prefix) bool {
	for _, m := range metadata {
		if p.Contains(m) {
			return true
		}
	}
	return false
}
