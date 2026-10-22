package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// dialer resolves once, vets every answer, then connects to the vetted IP literal. The address it
// hands to the underlying dial is always an IP, so nothing downstream can resolve again.
type dialer struct {
	allow []netip.Prefix
	res   Resolver
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *dialer) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("%w: network %q", ErrDestinationDenied, network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: bad address", ErrBadRequest)
	}
	ips, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, ip := range ips {
		if network == "tcp4" && !ip.Is4() || network == "tcp6" && !ip.Is6() {
			continue
		}
		c, err := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("egress: %s has no usable address for %s", host, network)
	}
	return nil, errors.Join(errs...)
}

// resolve returns the vetted addresses of host. A literal is not looked up. If any answer is not
// permitted the whole destination is refused: a mixed answer is how a rebinding attacker hedges.
func (d *dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = d.res.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("egress: resolving %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("egress: resolving %s: no addresses", host)
		}
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("%w: %s resolves to a zoned address", ErrDestinationDenied, host)
		}
		ip = ip.Unmap()
		if !permitted(ip, d.allow) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrDestinationDenied, host, ip)
		}
		out = append(out, ip)
	}
	return out, nil
}
