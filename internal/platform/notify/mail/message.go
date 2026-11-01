package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/httpx"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
)

// Size limits of one message. The message is built in memory, so these bound it.
const (
	MaxSubject     = 255
	MaxBody        = 1 << 20
	MaxAttachments = 20
	MaxMessage     = 25 << 20
)

// Attachment is one file of a message.
type Attachment struct {
	// Filename is a base name, mapped by httpx (control and path characters become "_"); the
	// extension and the media type come from Format, never from the name.
	Filename string
	// Format is httpx.CSV, XLSX or PDF. Any other value refuses the message.
	Format httpx.Format
	Data   []byte
}

// Message is one message to one recipient. Every header value is built here from validated parts;
// nothing the caller supplies is written into a header verbatim.
type Message struct {
	From, To    mailaddr.Address
	Subject     string // one line, no CR, LF or NUL
	Text        string // UTF-8 plain text
	Attachments []Attachment
	// At is the Date header. The zero value takes time.Now.
	At time.Time
}

// build returns the RFC 5322 message and its Message-ID (with brackets).
func (m Message) build() (raw []byte, messageID string, err error) {
	if m.From.IsZero() || m.To.IsZero() {
		return nil, "", badMessage("sender and recipient are required")
	}
	if len(m.Subject) > MaxSubject || strings.ContainsAny(m.Subject, "\r\n\x00") || !utf8.ValidString(m.Subject) {
		return nil, "", badMessage("subject must be one valid line")
	}
	if len(m.Text) > MaxBody || !utf8.ValidString(m.Text) || strings.ContainsRune(m.Text, 0) {
		return nil, "", badMessage("body must be valid UTF-8 text")
	}
	if len(m.Attachments) > MaxAttachments {
		return nil, "", badMessage("too many attachments")
	}
	total := len(m.Text)
	for _, a := range m.Attachments {
		total += len(a.Data)
	}
	if total > MaxMessage {
		return nil, "", badMessage("message too large")
	}
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, "", fmt.Errorf("mail: message id: %w", err)
	}
	messageID = "<" + hex.EncodeToString(idb[:]) + "@" + m.From.Domain() + ">"
	at := m.At
	if at.IsZero() {
		at = time.Now()
	}

	var buf bytes.Buffer
	hdr := func(k, v string) { buf.WriteString(k + ": " + v + "\r\n") }
	hdr("From", m.From.String())
	hdr("To", m.To.String())
	hdr("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	hdr("Date", at.UTC().Format(time.RFC1123Z))
	hdr("Message-ID", messageID)
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")

	if len(m.Attachments) == 0 {
		hdr("Content-Type", `text/plain; charset="utf-8"`)
		hdr("Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		if err := writeQP(&buf, m.Text); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), messageID, nil
	}

	mw := multipart.NewWriter(&buf)
	hdr("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
	buf.WriteString("\r\n")
	th := textproto.MIMEHeader{}
	th.Set("Content-Type", `text/plain; charset="utf-8"`)
	th.Set("Content-Transfer-Encoding", "quoted-printable")
	pw, err := mw.CreatePart(th)
	if err != nil {
		return nil, "", err
	}
	if err := writeQP(pw, m.Text); err != nil {
		return nil, "", err
	}
	for _, a := range m.Attachments {
		ah := textproto.MIMEHeader{}
		if err := httpx.PartHeaders(ah, a.Filename, a.Format); err != nil {
			return nil, "", badMessage("attachment format is not supported")
		}
		ah.Set("Content-Transfer-Encoding", "base64")
		w, err := mw.CreatePart(ah)
		if err != nil {
			return nil, "", err
		}
		enc := base64.StdEncoding.EncodeToString(a.Data)
		for len(enc) > 76 {
			_, _ = w.Write([]byte(enc[:76] + "\r\n"))
			enc = enc[76:]
		}
		_, _ = w.Write([]byte(enc + "\r\n"))
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return normalizeCRLF(buf.Bytes()), messageID, nil
}

func writeQP(w interface{ Write([]byte) (int, error) }, s string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := qp.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"))); err != nil {
		return err
	}
	return qp.Close()
}

// normalizeCRLF makes every line end CRLF; multipart.Writer writes bare LF.
func normalizeCRLF(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
}
