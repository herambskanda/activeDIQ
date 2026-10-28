package csv

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/export/cellsafe"
)

// Limits bound a Reader (R5). Zero fields take the defaults.
type Limits struct {
	MaxFieldBytes  int // default 1 MiB
	MaxFields      int // per record; default 16384
	MaxRows        int // default 1 048 576 records
	MaxRecordBytes int // field bytes per record; default 16 MiB
}

// Reader errors.
var (
	ErrFieldTooLong  = errors.New("csv: field exceeds limit")
	ErrTooManyCells  = errors.New("csv: record has too many fields")
	ErrTooManyRows   = errors.New("csv: too many records")
	ErrRecordTooLong = errors.New("csv: record exceeds byte limit")
	ErrSyntax        = errors.New("csv: malformed quoting")
)

// Reader parses RFC 4180 CSV and reverses the neutraliser: from a field it drops one leading TAB
// when the rest classifies as a FormulaLead (rule 5, so Read(Write(v)) == v). It does not use
// encoding/csv because that normalises CRLF inside quoted fields, which would break the round trip.
type Reader struct {
	br       *bufio.Reader
	delim    byte
	lim      Limits
	rows     int
	recBytes int // field bytes accumulated in the current record
	first    bool
}

// NewReader returns a Reader on r. A leading UTF-8 BOM is skipped.
func NewReader(r io.Reader, o Options, l Limits) (*Reader, error) {
	d, ok := o.Delimiter.byte()
	if !ok {
		return nil, ErrDelimiterNotAllowed
	}
	if l.MaxFieldBytes <= 0 {
		l.MaxFieldBytes = 1 << 20
	}
	if l.MaxFields <= 0 {
		l.MaxFields = 16384
	}
	if l.MaxRecordBytes <= 0 {
		l.MaxRecordBytes = 16 << 20
	}
	if l.MaxRows <= 0 {
		l.MaxRows = 1 << 20
	}
	return &Reader{br: bufio.NewReaderSize(r, 64<<10), delim: d, lim: l, first: true}, nil
}

// Row returns the next record, or io.EOF.
func (r *Reader) Row() ([]string, error) {
	if r.first {
		r.first = false
		if b, err := r.br.Peek(3); err == nil && string(b) == bom {
			r.br.Discard(3)
		}
	}
	if _, err := r.br.Peek(1); err != nil {
		return nil, err
	}
	if r.rows >= r.lim.MaxRows {
		return nil, ErrTooManyRows
	}
	r.rows++
	r.recBytes = 0
	var rec []string
	for {
		f, end, err := r.field()
		if err != nil {
			return nil, err
		}
		if len(rec) >= r.lim.MaxFields {
			return nil, ErrTooManyCells
		}
		rec = append(rec, f)
		if end {
			return rec, nil
		}
	}
}

// field reads one field; end is true when the record ended with it.
func (r *Reader) field() (val string, end bool, err error) {
	c, err := r.br.ReadByte()
	if err == io.EOF {
		return "", true, nil
	}
	if err != nil {
		return "", false, err
	}
	var sb strings.Builder
	quoted := c == '"'
	if !quoted {
		r.br.UnreadByte()
	}
	for {
		c, err = r.br.ReadByte()
		if err == io.EOF {
			if quoted {
				return "", false, ErrSyntax
			}
			return finish(sb.String(), quoted), true, nil
		}
		if err != nil {
			return "", false, err
		}
		if quoted {
			if c == '"' {
				n, perr := r.br.Peek(1)
				if perr == nil && n[0] == '"' {
					r.br.ReadByte()
					if err := r.put(&sb, '"'); err != nil {
						return "", false, err
					}
				} else {
					quoted = false
					// after the closing quote only a delimiter or record end may follow
					c2, e2 := r.br.ReadByte()
					switch {
					case e2 == io.EOF:
						return finish(sb.String(), true), true, nil
					case c2 == r.delim:
						return finish(sb.String(), true), false, nil
					case c2 == '\r' || c2 == '\n':
						r.eol(c2)
						return finish(sb.String(), true), true, nil
					default:
						return "", false, ErrSyntax
					}
				}
				continue
			}
		} else {
			if c == r.delim {
				return sb.String(), false, nil
			}
			if c == '\r' || c == '\n' {
				r.eol(c)
				return sb.String(), true, nil
			}
		}
		if err := r.put(&sb, c); err != nil {
			return "", false, err
		}
	}
}

// put appends one byte to a field after enforcing the field and record limits. Every byte that
// grows a field goes through here, the doubled-quote path included.
func (r *Reader) put(sb *strings.Builder, c byte) error {
	if sb.Len() >= r.lim.MaxFieldBytes {
		return ErrFieldTooLong
	}
	if r.recBytes >= r.lim.MaxRecordBytes {
		return ErrRecordTooLong
	}
	r.recBytes++
	sb.WriteByte(c)
	return nil
}

func (r *Reader) eol(c byte) {
	if c == '\r' {
		if n, err := r.br.Peek(1); err == nil && n[0] == '\n' {
			r.br.ReadByte()
		}
	}
}

// finish reverses the neutraliser on quoted fields. Only quoted fields carry it (the writer quotes
// every text field), so an unquoted TAB-led field from another producer is left alone.
func finish(s string, quoted bool) string {
	if quoted && cellsafe.StartsWithTab(s) && cellsafe.Classify(s[1:]) == cellsafe.FormulaLead {
		return s[1:]
	}
	return s
}
