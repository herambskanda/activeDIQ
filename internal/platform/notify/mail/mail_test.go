package mail_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/egress"
	nm "github.com/skenzeriq/activediq/internal/platform/notify/mail"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailtest"
	"github.com/skenzeriq/activediq/internal/platform/notify/settings"
)

func addr(t *testing.T, s string) mailaddr.Address {
	t.Helper()
	a, err := mailaddr.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func sender(t *testing.T, srv *mailtest.Server) *nm.Sender {
	t.Helper()
	c, err := egress.New(egress.Config{Allow: mailtest.Loopback(), RootCAs: srv.CA()})
	if err != nil {
		t.Fatal(err)
	}
	return &nm.Sender{Dialer: c}
}

func relay(srv *mailtest.Server, sec settings.Security) settings.Relay {
	return settings.Relay{Host: srv.Host(), Port: srv.Port(), Security: sec, From: "noreply@ok.example", PlaintextOptIn: sec == settings.Plaintext}
}

func msg(t *testing.T, to string) nm.Message {
	return nm.Message{From: addr(t, "noreply@ok.example"), To: addr(t, to), Subject: "Weekly report", Text: "Hello\nWorld — ünï"}
}

func TestSendOverEachTransport(t *testing.T) {
	for _, c := range []struct {
		name string
		mode mailtest.Mode
		sec  settings.Security
		tls  bool
	}{
		{"starttls", mailtest.STARTTLS, settings.StartTLS, true},
		{"implicit tls", mailtest.Implicit, settings.ImplicitTLS, true},
		{"plaintext with opt-in", mailtest.Plain, settings.Plaintext, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := mailtest.Start(t, c.mode)
			res, err := sender(t, srv).Send(context.Background(), relay(srv, c.sec), msg(t, "Bob@Ok.Example"))
			if err != nil {
				t.Fatal(err)
			}
			got := srv.Messages()
			if len(got) != 1 || got[0].TLS != c.tls {
				t.Fatalf("messages = %+v, want one (tls=%v)", got, c.tls)
			}
			// RCPT TO and the To header carry the canonical address, the same string classification saw.
			if got[0].To[0] != "Bob@ok.example" || got[0].From != "noreply@ok.example" {
				t.Fatalf("envelope = %q -> %q", got[0].From, got[0].To)
			}
			m, err := mail.ReadMessage(strings.NewReader(string(got[0].Data)))
			if err != nil {
				t.Fatal(err)
			}
			if m.Header.Get("To") != "Bob@ok.example" || m.Header.Get("Message-ID") != res.MessageID {
				t.Fatalf("headers = %v", m.Header)
			}
			body, _ := io.ReadAll(m.Body)
			if !strings.Contains(string(body), "World") {
				t.Fatalf("body = %q", body)
			}
		})
	}
}

func TestStrippedStartTLSIsRefusedNotDowngraded(t *testing.T) {
	srv := mailtest.Start(t, mailtest.StrippedSTARTTLS)
	_, err := sender(t, srv).Send(context.Background(), relay(srv, settings.StartTLS), msg(t, "bob@ok.example"))
	var me *nm.Error
	if !errors.As(err, &me) || me.Code != nm.CodeNoSTARTTLS {
		t.Fatalf("err = %v, want %s", err, nm.CodeNoSTARTTLS)
	}
	if len(srv.Messages()) != 0 || len(srv.RcptAttempts()) != 0 {
		t.Fatal("nothing may be sent over the downgraded connection")
	}
}

func TestUntrustedCertificateIsRefused(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Implicit)
	c, err := egress.New(egress.Config{Allow: mailtest.Loopback()}) // system roots only
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&nm.Sender{Dialer: c}).Send(context.Background(), relay(srv, settings.ImplicitTLS), msg(t, "bob@ok.example"))
	var me *nm.Error
	if !errors.As(err, &me) || me.Code != nm.CodeTLS || me.Permanent {
		t.Fatalf("err = %v, want transient %s", err, nm.CodeTLS)
	}
	srv2 := mailtest.Start(t, mailtest.STARTTLS)
	_, err = (&nm.Sender{Dialer: c}).Send(context.Background(), relay(srv2, settings.StartTLS), msg(t, "bob@ok.example"))
	if !errors.As(err, &me) || me.Code != nm.CodeTLS {
		t.Fatalf("starttls err = %v, want %s", err, nm.CodeTLS)
	}
	if len(srv.Messages())+len(srv2.Messages()) != 0 {
		t.Fatal("a message was delivered over an unverified connection")
	}
}

func TestEgressRefusesAnInternalRelay(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Plain)
	c, err := egress.New(egress.Config{}) // strictest: loopback not allow-listed
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&nm.Sender{Dialer: c}).Send(context.Background(), relay(srv, settings.Plaintext), msg(t, "bob@ok.example"))
	var me *nm.Error
	if !errors.As(err, &me) || me.Code != nm.CodeDestinationDenied || !me.Permanent || !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("err = %v, want permanent %s wrapping egress.ErrDestinationDenied", err, nm.CodeDestinationDenied)
	}
	if srv.Connections() != 0 {
		t.Fatal("egress must refuse before any connection is made")
	}
}

func TestReplyClassification(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Plain)
	srv.RejectRcpt("perm@ok.example", 550)
	srv.RejectRcpt("temp@ok.example", 451)
	srv.RejectData("data5@ok.example", 554)
	srv.RejectData("data4@ok.example", 452)
	s := sender(t, srv)
	for _, c := range []struct {
		to   string
		code string
		perm bool
	}{
		{"perm@ok.example", nm.CodeRecipientRejected, true},
		{"temp@ok.example", nm.CodeRecipientDeferred, false},
		{"data5@ok.example", nm.CodeDataRejected, true},
		{"data4@ok.example", nm.CodeDataDeferred, false},
	} {
		_, err := s.Send(context.Background(), relay(srv, settings.Plaintext), msg(t, c.to))
		var me *nm.Error
		if !errors.As(err, &me) || me.Code != c.code || me.Permanent != c.perm {
			t.Errorf("%s: err = %v, want %s permanent=%v", c.to, err, c.code, c.perm)
		}
		if err != nil && strings.Contains(err.Error(), c.to) {
			t.Errorf("the error names the address: %v", err)
		}
	}
}

func TestRelayDownIsTransient(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Plain)
	srv.Down(true)
	_, err := sender(t, srv).Send(context.Background(), relay(srv, settings.Plaintext), msg(t, "bob@ok.example"))
	var me *nm.Error
	if !errors.As(err, &me) || me.Permanent {
		t.Fatalf("err = %v, want a transient failure", err)
	}
}

// The subject and attachment names come from the caller; no CR/LF reaches a header, and a body line
// that is a lone dot is not the end of DATA.
func TestMessageIsInjectionSafe(t *testing.T) {
	srv := mailtest.Start(t, mailtest.Plain)
	s := sender(t, srv)
	bad := msg(t, "bob@ok.example")
	bad.Subject = "hi\r\nBcc: attacker@evil.example"
	_, err := s.Send(context.Background(), relay(srv, settings.Plaintext), bad)
	var me *nm.Error
	if !errors.As(err, &me) || me.Code != nm.CodeBadMessage || !me.Permanent {
		t.Fatalf("err = %v, want %s", err, nm.CodeBadMessage)
	}
	if len(srv.RcptAttempts()) != 0 {
		t.Fatal("a refused message must not reach the relay")
	}

	m := msg(t, "bob@ok.example")
	m.Text = "line one\n.\nQUIT\r\nRCPT TO:<attacker@evil.example>\n.."
	m.Attachments = []nm.Attachment{{Filename: "../../etc/passwd\r\nX: y", ContentType: "text/csv\r\nX: y", Data: []byte("a,b\n1,2\n")}}
	if _, err := s.Send(context.Background(), relay(srv, settings.Plaintext), m); err != nil {
		t.Fatal(err)
	}
	if got := srv.RcptAttempts(); len(got) != 1 || got[0] != "bob@ok.example" {
		t.Fatalf("RCPT attempts = %v", got)
	}
	got := srv.Messages()
	if len(got) != 1 {
		t.Fatalf("messages = %d", len(got))
	}
	pm, err := mail.ReadMessage(strings.NewReader(string(got[0].Data)))
	if err != nil {
		t.Fatal(err)
	}
	if pm.Header.Get("Bcc") != "" || pm.Header.Get("X") != "" {
		t.Fatalf("injected header: %v", pm.Header)
	}
	_, params, err := mime.ParseMediaType(pm.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(pm.Body, params["boundary"])
	text, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	_ = text
	att, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if fn := att.FileName(); fn != "passwd__X_ y" {
		t.Fatalf("attachment name = %q", fn)
	}
	if att.Header.Get("X") != "" {
		t.Fatal("injected attachment header")
	}
	data, _ := io.ReadAll(att)
	dec, _ := decodeB64(string(data))
	if dec != "a,b\n1,2\n" {
		t.Fatalf("attachment = %q", dec)
	}
}

func decodeB64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(s))
	return string(b), err
}
