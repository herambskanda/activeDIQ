// Package syslog is the SIEM syslog forwarder (EP-9 notification sink, TM-TB15-T7). It carries
// notifications to a customer's SIEM; it is not the audit chain and holds none of its content.
//
// Transport rules:
//   - A destination that states no transport is TLS (RFC 5425) with certificate verification.
//   - Plaintext TCP exists only when the destination says so explicitly (Transport "tcp" together
//     with PlaintextOptIn). The opt-in is audited (OptInEvent) and visible in every View.
//   - UDP is not offered: it cannot carry TLS and has no delivery signal.
//   - Every connection is made by the egress client, so an internal range needs an operator
//     allow-list entry (TM-F-EGRESS); this package never dials.
package syslog

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/egress"
)

// Transport of a destination. The zero value means TLS.
type Transport string

const (
	TLS Transport = "tls" // RFC 5425, verified; the default
	TCP Transport = "tcp" // plaintext; needs PlaintextOptIn
)

// KindPlaintextOptIn is the audit kind recorded when a destination is configured for plaintext.
const KindPlaintextOptIn audit.Kind = "siem.destination.plaintext_opt_in"

// Typed refusals.
var (
	ErrBadDestination      = errors.New("syslog: invalid destination")
	ErrPlaintextNotOptedIn = errors.New("syslog: plaintext transport requires an explicit opt-in")
)

// Destination is the configuration of one syslog target.
type Destination struct {
	ID   string
	Host string
	Port int // 0 means 6514 for TLS, 514 for TCP
	// Transport: empty means TLS.
	Transport Transport
	// PlaintextOptIn must be true for Transport TCP. It is ignored (and refused) with TLS.
	PlaintextOptIn bool
}

// Normalize applies defaults and validates. Callers store the returned value.
func (d Destination) Normalize() (Destination, error) {
	if d.ID == "" || d.Host == "" || strings.ContainsAny(d.Host, " /@\r\n\t") {
		return d, fmt.Errorf("%w: id and a plain host are required", ErrBadDestination)
	}
	switch d.Transport {
	case "":
		d.Transport = TLS
	case TLS, TCP:
	default:
		return d, fmt.Errorf("%w: transport %q (use tls or tcp)", ErrBadDestination, d.Transport)
	}
	switch {
	case d.Transport == TCP && !d.PlaintextOptIn:
		return d, ErrPlaintextNotOptedIn
	case d.Transport == TLS && d.PlaintextOptIn:
		return d, fmt.Errorf("%w: plaintext opt-in given with TLS", ErrBadDestination)
	}
	if d.Port == 0 {
		d.Port = 6514
		if d.Transport == TCP {
			d.Port = 514
		}
	}
	if d.Port < 1 || d.Port > 65535 {
		return d, fmt.Errorf("%w: port", ErrBadDestination)
	}
	return d, nil
}

// View is what the API returns for a destination: the transport, whether the server certificate
// is verified, and the plaintext opt-in are always stated.
type View struct {
	ID             string `json:"id"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Transport      string `json:"transport"`
	TLSVerified    bool   `json:"tlsVerified"`
	PlaintextOptIn bool   `json:"plaintextOptIn"`
	Warning        string `json:"warning,omitempty"`
}

// View renders a normalized destination.
func (d Destination) View() View {
	v := View{ID: d.ID, Host: d.Host, Port: d.Port, Transport: string(d.Transport), TLSVerified: d.Transport == TLS, PlaintextOptIn: d.PlaintextOptIn}
	if d.Transport == TCP {
		v.Warning = "Events are sent unencrypted and can be read or altered on the network."
	}
	return v
}

// OptInEvent is the audit event for configuring d as plaintext; nil for a TLS destination. The
// caller appends it in the same transaction that stores the destination.
func OptInEvent(eventID string, actor authority.Chain, d Destination, at time.Time) *audit.Event {
	if d.Transport != TCP {
		return nil
	}
	return &audit.Event{
		ID: eventID, Kind: KindPlaintextOptIn, At: at, Actor: actor,
		Component: "notify.syslog", Outcome: audit.Success, Reason: "plaintext_opt_in",
		Details: []chain.Detail{
			{Key: "destination", Value: d.ID},
			{Key: "host", Value: d.Host},
			{Key: "port", Value: strconv.Itoa(d.Port)},
		},
	}
}

// Dialer is the part of the egress client the forwarder uses.
type Dialer interface {
	DialStream(ctx context.Context, host, port string, useTLS bool) (net.Conn, error)
}

var _ Dialer = (*egress.Client)(nil)

// Message is one RFC 5424 record.
type Message struct {
	Facility, Severity int
	Time               time.Time
	Hostname, App, ID  string
	Text               string
}

// Send delivers m to d over its transport, using RFC 6587 octet-counting framing.
func Send(ctx context.Context, dl Dialer, d Destination, m Message) error {
	d, err := d.Normalize()
	if err != nil {
		return err
	}
	conn, err := dl.DialStream(ctx, d.Host, strconv.Itoa(d.Port), d.Transport == TLS)
	if err != nil {
		return fmt.Errorf("syslog: %s:%d: %w", d.Host, d.Port, err)
	}
	defer conn.Close()
	if dead, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dead)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	}
	frame := Format(m)
	if _, err := fmt.Fprintf(conn, "%d %s", len(frame), frame); err != nil {
		return fmt.Errorf("syslog: write to %s:%d: %w", d.Host, d.Port, err)
	}
	return nil
}

// Format renders m as an RFC 5424 record. Header fields are reduced to printable ASCII without
// spaces; the text loses control characters so an event text cannot forge a second record.
func Format(m Message) string {
	pri := (m.Facility&31)*8 + (m.Severity & 7)
	ts := m.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s", pri, ts.UTC().Format("2006-01-02T15:04:05.000Z"),
		field(m.Hostname, 255), field(m.App, 48), field(m.ID, 32), text(m.Text))
}

func field(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
	}
	if out == "" {
		return "-"
	}
	return out
}

func text(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
}
