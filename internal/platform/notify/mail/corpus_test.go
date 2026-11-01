package mail

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	netmail "net/mail"
	"net/textproto"
	"sort"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
	"github.com/skenzeriq/activediq/internal/platform/httpx"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
)

// builtHeaders is the header set build writes, and the only one: an injected line would add to it.
var builtHeaders = []string{"Auto-Submitted", "Content-Transfer-Encoding", "Content-Type", "Date", "From", "Message-Id", "Mime-Version", "Subject", "To"}

// multipartHeaders is the header set of the multipart/mixed message: the body headers move to the parts.
var multipartHeaders = []string{"Auto-Submitted", "Content-Type", "Date", "From", "Message-Id", "Mime-Version", "Subject", "To"}

func mustAddr(s string) mailaddr.Address {
	a, err := mailaddr.Parse(s)
	if err != nil {
		panic(err)
	}
	return a
}

func baseMessage() Message {
	return Message{From: mustAddr("noreply@ok.example"), To: mustAddr("bob@ok.example"), Subject: "Weekly report", Text: "Hello"}
}

// wireOK is the SMTP-smuggling check of EM-07 and the line bound of EM-12 on what the relay receives: the message has no bare
// CR or LF, and once the DATA writer of net/smtp has dot-stuffed it (net/textproto DotWriter), the
// only line that is a single dot is the terminator.
func wireOK(raw []byte) error {
	for i, c := range raw {
		if c == '\n' && (i == 0 || raw[i-1] != '\r') {
			return errors.New("bare LF in the message")
		}
		if c == '\r' && (i+1 >= len(raw) || raw[i+1] != '\n') {
			return errors.New("bare CR in the message")
		}
	}
	// O7 / EM-12: RFC 5322 section 2.1.1, no line over 998 octets (CRLF excluded).
	for _, line := range bytes.Split(raw, []byte("\r\n")) {
		if len(line) > 998 {
			return fmt.Errorf("a line of %d octets in the message", len(line))
		}
	}
	var wire bytes.Buffer
	bw := bufio.NewWriter(&wire)
	dw := textproto.NewWriter(bw).DotWriter()
	if _, err := dw.Write(raw); err != nil {
		return err
	}
	if err := dw.Close(); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	lines := bytes.Split(bytes.TrimSuffix(wire.Bytes(), []byte("\r\n")), []byte("\r\n"))
	for i, line := range lines {
		if string(line) == "." && i != len(lines)-1 {
			return errors.New("a dot-only line before the terminator reaches the relay")
		}
	}
	return nil
}

func sortedKeys(h map[string][]string) []string {
	var ks []string
	for k := range h {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sameStrings(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }

func lf(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n") }

// inspect reads a built message with independent parsers (net/mail, mime/multipart, mime/quotedprintable).
type inspected struct {
	Headers []string `json:"headers"`
	Subject string   `json:"subject"`
	Parts   int      `json:"parts"`
	// the attachment part, when there is one
	Filename    string   `json:"filename,omitempty"`
	Type        string   `json:"type,omitempty"`
	Disposition string   `json:"disposition,omitempty"`
	PartHeaders []string `json:"partHeaders,omitempty"`
	Body        string   `json:"-"`
}

func inspect(raw []byte) (inspected, error) {
	var out inspected
	if err := wireOK(raw); err != nil {
		return out, err
	}
	m, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	out.Headers = sortedKeys(m.Header)
	for k, v := range m.Header {
		if len(v) != 1 {
			return out, fmt.Errorf("header %s appears %d times", k, len(v))
		}
	}
	if out.Subject, err = new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject")); err != nil {
		return out, err
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil {
		return out, err
	}
	if mt != "multipart/mixed" {
		b, err := io.ReadAll(quotedprintable.NewReader(m.Body))
		out.Body = lf(string(b))
		out.Parts = 1
		return out, err
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out.Parts++
		if out.Parts == 1 {
			b, _ := io.ReadAll(p) // multipart.Part decodes quoted-printable itself
			out.Body = lf(string(b))
			continue
		}
		out.PartHeaders = sortedKeys(p.Header)
		out.Type, _, _ = mime.ParseMediaType(p.Header.Get("Content-Type"))
		out.Disposition, params, err = mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		if err != nil {
			return out, err
		}
		out.Filename = params["filename"]
		if _, err := io.Copy(io.Discard, p); err != nil {
			return out, err
		}
	}
}

func errCode(err error) (corpus.Result, bool) {
	var me *Error
	if errors.As(err, &me) {
		return corpustest.Err(me.Code), true
	}
	return corpus.Result{}, false
}

var formatByName = map[string]httpx.Format{"csv": httpx.CSV, "xlsx": httpx.XLSX, "pdf": httpx.PDF, "html": httpx.HTML, "none": 0}

// TestCorpus runs the mail records (testdata/safe-primitives/mail.jsonl, safe-primitives §12.6, FF-SP4).
// Every built message is read back with net/mail, mime/multipart and mime/quotedprintable.
func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/mail", "mail", func(r corpus.Record) (corpus.Result, error) {
		m := baseMessage()
		switch r.Call {
		case "Subject":
			s, err := r.Arg("subject")
			if err != nil {
				return corpus.Result{}, err
			}
			m.Subject = s.Text()
		case "Body":
			s, err := r.Arg("text")
			if err != nil {
				return corpus.Result{}, err
			}
			m.Text = s.Text()
		case "Attachment":
			base, err := r.Arg("base")
			if err != nil {
				return corpus.Result{}, err
			}
			name, err := r.Arg("format")
			if err != nil {
				return corpus.Result{}, err
			}
			f, ok := formatByName[name.Text()]
			if !ok {
				return corpus.Result{}, fmt.Errorf("unknown format %q", name.Text())
			}
			m.Attachments = []Attachment{{Filename: base.Text(), Format: f, Data: []byte("a,b\n1,2\n")}}
		default:
			return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
		}
		raw, _, err := m.build()
		if res, ok := errCode(err); ok {
			return res, nil
		} else if err != nil {
			return corpus.Result{}, err
		}
		got, err := inspect(raw)
		if err != nil {
			return corpus.Result{}, err
		}
		switch r.Call {
		case "Body":
			return corpustest.Value(map[string]any{
				"headers":   got.Headers,
				"subject":   got.Subject,
				"roundTrip": got.Body == lf(m.Text),
			})
		case "Subject":
			return corpustest.Value(map[string]any{"headers": got.Headers, "subject": got.Subject})
		}
		return corpustest.Value(got)
	})
}

// FuzzMessage is the FF-SP5 target for mail (independentParse): whatever the subject, text and
// attachment base, a message that is built parses with net/mail, holds exactly the headers build
// writes, has no bare CR or LF and no dot-only line on the wire, and carries its body unchanged.
func FuzzMessage(f *testing.F) {
	corpustest.Seed(f, "mail")
	f.Fuzz(func(t *testing.T, in []byte) {
		s := string(in)
		for _, withAttachment := range []bool{false, true} {
			m := baseMessage()
			m.Subject, m.Text = s, s
			if withAttachment {
				m.Attachments = []Attachment{{Filename: s, Format: httpx.CSV, Data: in}}
			}
			raw, _, err := m.build()
			if err != nil {
				var me *Error
				if !errors.As(err, &me) {
					t.Fatalf("untyped error %v for %q", err, s)
				}
				continue
			}
			got, err := inspect(raw)
			if err != nil {
				t.Fatalf("%q: %v", s, err)
			}
			want := builtHeaders
			if withAttachment {
				want = multipartHeaders
			}
			if !sameStrings(got.Headers, want) {
				t.Fatalf("%q: headers %v, want %v", s, got.Headers, want)
			}
			// Header parsers trim the value's edges. A typed "=?" word is decoded by the client until
			// the Subject is always encoded: EM-06, T-1166.
			if got.Body != lf(s) || (!strings.Contains(s, "=?") && strings.TrimSpace(got.Subject) != strings.TrimSpace(s)) {
				t.Fatalf("%q: subject %q body %q", s, got.Subject, got.Body)
			}
			if withAttachment && (got.Parts != 2 || got.Disposition != "attachment" || got.Type != "text/csv" || !strings.HasSuffix(got.Filename, ".csv")) {
				t.Fatalf("%q: attachment part %+v", s, got)
			}
		}
	})
}

// T-1173 (O7, EM-12): a 120 four-byte-rune base in each format builds a message with no line over
// 998 octets, and multipart's own FileName() decodes the mapped name (cut to httpx.MaxPartEncodedBase
// encoded octets: 50 of the 120 runes).
func TestLongAttachmentNameLineBound(t *testing.T) {
	base := strings.Repeat("\U0001F600", httpx.MaxBaseRunes)
	for f, ext := range map[httpx.Format]string{httpx.CSV: ".csv", httpx.XLSX: ".xlsx", httpx.PDF: ".pdf"} {
		want := strings.Repeat("\U0001F600", httpx.MaxPartEncodedBase/12) + ext
		m := baseMessage()
		m.Attachments = []Attachment{{Filename: base, Format: f, Data: []byte("a,b\n")}}
		raw, _, err := m.build()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(raw, []byte("\r\n")) {
			if len(line) > 998 {
				t.Fatalf("format %d: line of %d octets", f, len(line))
			}
		}
		msg, err := netmail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
		mr := multipart.NewReader(msg.Body, params["boundary"])
		if _, err := mr.NextPart(); err != nil {
			t.Fatal(err)
		}
		p, err := mr.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		if got := p.FileName(); got != want {
			t.Fatalf("format %d: FileName() = %q, want %q", f, got, want)
		}
	}
}
