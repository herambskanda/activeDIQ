// Package ports is the TM-F-PORTS fitness function (threat model §8.1, §15; TM-TB6-T8, TM-TB14-T6,
// TM-TB16-T10): the listening sockets of a booted install must equal the declared listener table. It reads
// what the kernel says the process holds (/proc/<pid>/net/{tcp,tcp6,udp,udp6} joined to the process's
// socket file descriptors), so a listener opened by any library, debug handler or sidecar is seen whether or
// not the source mentions it. A socket outside the allow-list is a violation that names the port.
//
// Enumeration is Linux (the linux-oci profile and CI). The Windows service is covered by the lab runbook
// (knowledge/development/runbooks/tm-f-ports.md), which runs the same comparison over Get-NetTCPConnection.
package ports

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Socket is one listening socket.
type Socket struct {
	Proto string // tcp or udp
	Addr  netip.Addr
	Port  uint16
}

func (s Socket) String() string {
	return fmt.Sprintf("%s %s", s.Proto, netip.AddrPortFrom(s.Addr, s.Port))
}

// Allowed is one declared listener: a §8.1 row, with the port the install was configured to bind.
type Allowed struct {
	Row   string // L1, L2, L4 …
	Proto string
	Port  uint16
	// Loopback requires the socket to be bound to a loopback address (L4 without a TLS directory).
	Loopback bool
}

// Compare returns one violation per found socket that no allow-list row covers, and one per declared row
// that is not listening (a proof that matches an empty set proves nothing). The "equal" in §8.1 is both ways.
func Compare(found []Socket, allow []Allowed) []string {
	var v []string
	used := make([]bool, len(allow))
	for _, s := range found {
		hit := false
		for i, a := range allow {
			if a.Proto == s.Proto && a.Port == s.Port && (!a.Loopback || s.Addr.IsLoopback()) {
				used[i], hit = true, true
			}
		}
		if !hit {
			v = append(v, fmt.Sprintf("unexpected listener: %s (port %d) is not in threat model §8.1 for this install", s, s.Port))
		}
	}
	for i, a := range allow {
		if !used[i] {
			v = append(v, fmt.Sprintf("declared listener %s (%s port %d) is not listening", a.Row, a.Proto, a.Port))
		}
	}
	sort.Strings(v)
	return v
}

// Listening returns the listening sockets owned by pid (TCP in state LISTEN, UDP bound and unconnected).
func Listening(pid int) ([]Socket, error) { return listening("/proc", strconv.Itoa(pid)) }

func listening(procRoot, pid string) ([]Socket, error) {
	inodes, err := socketInodes(filepath.Join(procRoot, pid, "fd"))
	if err != nil {
		return nil, err
	}
	var out []Socket
	for _, f := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		ss, err := parseNet(filepath.Join(procRoot, pid, "net", f.file), f.proto, inodes)
		if err != nil {
			return nil, err
		}
		out = append(out, ss...)
	}
	return out, nil
}

func socketInodes(fdDir string) (map[string]bool, error) {
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("ports: read %s: %w", fdDir, err)
	}
	m := map[string]bool{}
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue // the fd closed meanwhile
		}
		if rest, ok := strings.CutPrefix(l, "socket:["); ok {
			m[strings.TrimSuffix(rest, "]")] = true
		}
	}
	return m, nil
}

// parseNet reads one /proc/net table. A TCP row counts in state 0A (LISTEN); a UDP row counts in state 07
// (unconnected), which is how a bound datagram socket shows.
func parseNet(path, proto string, inodes map[string]bool) ([]Socket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ports: %w", err)
	}
	defer f.Close()
	want := "0A"
	if proto == "udp" {
		want = "07"
	}
	var out []Socket
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		c := strings.Fields(sc.Text())
		if len(c) < 10 || c[3] != want || !inodes[c[9]] {
			continue
		}
		s, err := parseLocal(c[1], proto)
		if err != nil {
			return nil, fmt.Errorf("ports: %s: %w", path, err)
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// parseLocal decodes "ADDR:PORT" in the kernel's hex form (addresses as little-endian 32-bit words).
func parseLocal(s, proto string) (Socket, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok || (len(h) != 8 && len(h) != 32) {
		return Socket{}, fmt.Errorf("bad local address %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return Socket{}, fmt.Errorf("bad port in %q", s)
	}
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 8 {
		w, err := strconv.ParseUint(h[i:i+8], 16, 32)
		if err != nil {
			return Socket{}, fmt.Errorf("bad address in %q", s)
		}
		b[i/2], b[i/2+1], b[i/2+2], b[i/2+3] = byte(w), byte(w>>8), byte(w>>16), byte(w>>24)
	}
	a, _ := netip.AddrFromSlice(b)
	return Socket{Proto: proto, Addr: a.Unmap(), Port: uint16(port)}, nil
}
