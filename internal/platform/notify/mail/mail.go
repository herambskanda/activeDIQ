// Package mail sends one message to one recipient over SMTP (EP-9, DM-82 channel kind smtp). Every
// connection is made by the egress client, so a relay on an internal range needs an
// installation-operator allow-list entry and a destination egress refuses is never dialled
// (TM-F-EGRESS, AC-4 of T-0950); this package never dials itself.
//
// Transport rules:
//   - STARTTLS is required, not opportunistic: a relay that does not offer it is refused, and a
//     stripped STARTTLS never degrades to plaintext. Certificates are verified (egress.TLSConfig).
//   - Implicit TLS (SMTPS) is verified the same way.
//   - Plaintext exists only when the relay settings carry the explicit opt-in.
//   - One transaction carries one recipient, so no recipient learns another's address and a
//     rejection is that recipient's alone.
//   - The addresses on MAIL FROM and RCPT TO are the canonical strings of mailaddr, the same strings
//     the allowed-domain classification used.
//
// Failures are *Error with a stable Code and a Permanent flag. Neither carries the relay's reply
// text, an address or a body: the code is what is stored and audited.
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/egress"
	"github.com/skenzeriq/activediq/internal/platform/notify/settings"
)

// Failure codes. They are stored in notify_deliveries.last_error_code, so they are stable.
const (
	CodeDestinationDenied = "destination_denied" // egress refused the relay's address (permanent)
	CodeConnect           = "connect_failed"     // could not connect or the connection broke (transient)
	CodeTLS               = "tls_failed"         // TLS handshake or certificate verification failed (transient)
	CodeNoSTARTTLS        = "starttls_unavailable"
	CodeTimeout           = "timeout"
	CodeSenderRejected    = "sender_rejected"    // 5xx on MAIL FROM (permanent)
	CodeRecipientRejected = "recipient_rejected" // 5xx on RCPT TO (permanent)
	CodeRecipientDeferred = "recipient_deferred" // 4xx on RCPT TO (transient)
	CodeDataRejected      = "data_rejected"      // 5xx after DATA (permanent)
	CodeDataDeferred      = "data_deferred"      // 4xx after DATA (transient)
	CodeServer            = "smtp_error"         // any other SMTP reply
	CodeBadMessage        = "bad_message"        // the message cannot be built (permanent)
	CodeNoRelay           = "no_relay"           // the tenant has no relay configured (permanent until configured)
	CodeBadRelay          = "bad_relay"          // the relay's security value is unknown, or plaintext without the opt-in (permanent)
)

// Error is a failed send. Permanent says retrying the same message to the same relay cannot help.
type Error struct {
	Code      string
	Permanent bool
	cause     error
}

func (e *Error) Error() string { return "mail: " + e.Code }

// Unwrap returns the underlying error for errors.Is/As (for example egress.ErrDestinationDenied) in
// code and tests. The cause must never be logged, stored or shown: a *textproto.Error carries the
// relay's reply text, which commonly echoes the recipient address ("550 5.1.1 <bob@x>: unknown"),
// and a dial error names the relay host. Only Code is for output.
func (e *Error) Unwrap() error { return e.cause }

func badMessage(string) error { return &Error{Code: CodeBadMessage, Permanent: true} }

// Dialer is the part of *egress.Client the sender uses.
type Dialer interface {
	DialStream(ctx context.Context, host, port string, useTLS bool) (net.Conn, error)
	TLSConfig(host string) *tls.Config
}

var _ Dialer = (*egress.Client)(nil)

// Sender sends messages through relays dialled by Dialer.
type Sender struct {
	Dialer Dialer
	// Timeout bounds one whole transaction. Default 60 s.
	Timeout time.Duration
}

// Result is a delivered message.
type Result struct {
	// MessageID is the Message-ID header the message was sent with, brackets included.
	MessageID string
}

// Send delivers m through relay. It returns nil error only after the relay accepted the message for
// the one recipient (a 250 after DATA).
func (s *Sender) Send(ctx context.Context, relay settings.Relay, m Message) (Result, error) {
	// Fail closed on the transport before anything is built or dialled: only the three known values
	// are sent, and plaintext only with the explicit opt-in (the database CHECK is not the only guard).
	switch {
	case relay.Security == settings.StartTLS, relay.Security == settings.ImplicitTLS:
	case relay.Security == settings.Plaintext && relay.PlaintextOptIn:
	default:
		return Result{}, &Error{Code: CodeBadRelay, Permanent: true}
	}
	raw, id, err := m.build()
	if err != nil {
		var me *Error
		if errors.As(err, &me) {
			return Result{}, me
		}
		return Result{}, &Error{Code: CodeBadMessage, Permanent: true, cause: err}
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := s.Dialer.DialStream(ctx, relay.Host, strconv.Itoa(relay.Port), relay.Security == settings.ImplicitTLS)
	if err != nil {
		return Result{}, classifyDial(err, relay)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	c, err := smtp.NewClient(conn, relay.Host)
	if err != nil {
		return Result{}, classifySMTP(err, CodeConnect)
	}
	defer c.Close()
	if err := c.Hello(m.From.Domain()); err != nil {
		return Result{}, classifySMTP(err, CodeServer)
	}
	if relay.Security == settings.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return Result{}, &Error{Code: CodeNoSTARTTLS}
		}
		if err := c.StartTLS(s.Dialer.TLSConfig(relay.Host)); err != nil {
			return Result{}, &Error{Code: CodeTLS, cause: err}
		}
	}
	if err := c.Mail(m.From.String()); err != nil {
		return Result{}, classifySMTP(err, CodeSenderRejected)
	}
	if err := c.Rcpt(m.To.String()); err != nil {
		return Result{}, classifyRcpt(err)
	}
	w, err := c.Data()
	if err != nil {
		return Result{}, classifySMTP(err, CodeDataRejected)
	}
	if _, err := w.Write(raw); err != nil {
		_ = w.Close()
		return Result{}, classifySMTP(err, CodeConnect)
	}
	if err := w.Close(); err != nil {
		return Result{}, classifySMTP(err, CodeDataRejected)
	}
	_ = c.Quit() // the message is accepted; a failed QUIT changes nothing
	return Result{MessageID: id}, nil
}

func classifyDial(err error, relay settings.Relay) error {
	switch {
	case errors.Is(err, egress.ErrDestinationDenied), errors.Is(err, egress.ErrBadRequest):
		return &Error{Code: CodeDestinationDenied, Permanent: true, cause: err}
	case errors.Is(err, context.DeadlineExceeded):
		return &Error{Code: CodeTimeout, cause: err}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &Error{Code: CodeTimeout, cause: err}
	}
	if errors.Is(err, egress.ErrTLSHandshake) {
		return &Error{Code: CodeTLS, cause: err}
	}
	return &Error{Code: CodeConnect, cause: err}
}

// classifySMTP maps an error from the SMTP library: a reply error by its class, a network timeout as
// a timeout, anything else as def (transient unless def says the relay refused).
func classifySMTP(err error, def string) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		perm := te.Code >= 500
		code := def
		switch def {
		case CodeServer, CodeConnect:
			code = CodeServer
		}
		if !perm && def == CodeDataRejected {
			code = CodeDataDeferred
		}
		if !perm && def == CodeSenderRejected {
			code = CodeServer
		}
		return &Error{Code: code, Permanent: perm, cause: err}
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return &Error{Code: CodeTimeout, cause: err}
	}
	return &Error{Code: CodeConnect, cause: err}
}

func classifyRcpt(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		if te.Code >= 500 {
			return &Error{Code: CodeRecipientRejected, Permanent: true, cause: err}
		}
		return &Error{Code: CodeRecipientDeferred, cause: err}
	}
	return classifySMTP(err, CodeConnect)
}
