package addc

import (
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Bounds on a rendered event (agentingest accepts at most 64 keys and about 60 KB a field).
const (
	maxFields     = 60
	maxFieldBytes = 8 << 10
	maxXMLBytes   = 256 << 10
)

// ParseEventXML reduces the XML EvtRender produces for an event to a RawEvent. It uses the standard
// decoder with no entity or DTD expansion, rejects oversized input, and truncates fields at a rune
// boundary. Unknown elements are ignored. It never returns the raw XML.
func ParseEventXML(raw []byte) (RawEvent, error) {
	var ev RawEvent
	if len(raw) > maxXMLBytes {
		return ev, io.ErrShortBuffer
	}
	d := xml.NewDecoder(bytes.NewReader(sanitizeXML(raw)))
	d.Strict = true
	d.Entity = nil
	var path []string
	var dataName string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return RawEvent{}, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			switch t.Name.Local {
			case "EventID":
			case "TimeCreated":
				for _, a := range t.Attr {
					if a.Name.Local == "SystemTime" {
						if tm, err := time.Parse(time.RFC3339Nano, a.Value); err == nil {
							ev.At = tm
						}
					}
				}
			case "Data":
				dataName = ""
				for _, a := range t.Attr {
					if a.Name.Local == "Name" {
						dataName = a.Value
					}
				}
			}
		case xml.CharData:
			if len(path) == 0 {
				continue
			}
			s := strings.TrimSpace(string(t))
			switch path[len(path)-1] {
			case "EventID":
				if n, err := strconv.ParseUint(s, 10, 32); err == nil {
					ev.EventID = uint32(n)
				}
			case "EventRecordID":
				if n, err := strconv.ParseUint(s, 10, 64); err == nil {
					ev.RecordID = n
				}
			case "Data":
				if dataName != "" && s != "" && len(ev.Fields) < maxFields {
					ev.Fields = append(ev.Fields, Field{Name: truncate(dataName, 64), Value: truncate(s, maxFieldBytes)})
				}
			}
		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		}
	}
	if ev.RecordID == 0 || ev.EventID == 0 {
		return RawEvent{}, io.ErrUnexpectedEOF
	}
	return ev, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// DecodeEvent is ParseEventXML that never loses the event: when the XML cannot be parsed or is too
// large it returns an Unparsable placeholder carrying the record id when one can be found.
func DecodeEvent(raw []byte) RawEvent {
	if ev, err := ParseEventXML(raw); err == nil {
		return ev
	}
	return RawEvent{Unparsable: true, RecordID: extractRecordID(raw)}
}

// extractRecordID finds <EventRecordID>digits</EventRecordID> by plain text search within the first
// 4 KiB (the System block comes first). It returns 0 when absent.
func extractRecordID(raw []byte) uint64 {
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	const open = "<EventRecordID>"
	i := bytes.Index(raw, []byte(open))
	if i < 0 {
		return 0
	}
	rest := raw[i+len(open):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	n, err := strconv.ParseUint(string(rest[:j]), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// isXMLChar is the XML 1.0 Char production
// (https://www.w3.org/TR/xml/#charsets).
func isXMLChar(r rune) bool {
	return r == 0x9 || r == 0xA || r == 0xD || (r >= 0x20 && r <= 0xD7FF) ||
		(r >= 0xE000 && r <= 0xFFFD) || (r >= 0x10000 && r <= 0x10FFFF)
}

// sanitizeXML replaces characters, and numeric character references, that XML forbids with U+FFFD, so
// an attacker-chosen control character in a directory attribute cannot make the whole event
// unparsable. Output is at most 3x the input; callers check the size first.
func sanitizeXML(raw []byte) []byte {
	const repl = "\uFFFD"
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		if raw[i] == '&' && i+2 < len(raw) && raw[i+1] == '#' {
			j, val, hex := i+2, uint64(0), false
			if raw[j] == 'x' {
				hex = true
				j++
			}
			start, over := j, false
			for j < len(raw) {
				c := raw[j]
				var d uint64
				switch {
				case c >= '0' && c <= '9':
					d = uint64(c - '0')
				case hex && c >= 'a' && c <= 'f':
					d = uint64(c-'a') + 10
				case hex && c >= 'A' && c <= 'F':
					d = uint64(c-'A') + 10
				default:
					d = 99
				}
				if d == 99 {
					break
				}
				if hex {
					val = val*16 + d
				} else {
					val = val*10 + d
				}
				if val > 0x10FFFF {
					val, over = 0x110000, true
				}
				j++
			}
			if j > start && j < len(raw) && raw[j] == ';' {
				if over || !isXMLChar(rune(val)) {
					out = append(out, repl...)
				} else {
					out = append(out, raw[i:j+1]...)
				}
				i = j + 1
				continue
			}
		}
		r, size := utf8.DecodeRune(raw[i:])
		if (r == utf8.RuneError && size <= 1) || !isXMLChar(r) {
			out = append(out, repl...)
		} else {
			out = append(out, raw[i:i+size]...)
		}
		i += size
	}
	return out
}
