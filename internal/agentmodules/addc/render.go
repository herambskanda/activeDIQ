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
	d := xml.NewDecoder(bytes.NewReader(raw))
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
