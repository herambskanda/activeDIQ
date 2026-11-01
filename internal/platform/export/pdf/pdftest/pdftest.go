// Package pdftest is the independent parser of FF-SP10 for PDF (safe-primitives §12.7 rules 2 and 3):
// it reads a finished file through its cross-reference table and objects, never through the writer's own
// tables, and extracts the text a reader would show. Tests of the writer and of the exports that use it
// share it, so a file is always judged by the same oracle.
package pdftest

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/text/encoding/charmap"
)

// Doc is a parsed file.
type Doc struct {
	raw  []byte
	Objs map[int]*Object
}

// Object is one indirect object: its dictionary text and, when it has one, its inflated stream.
type Object struct {
	id     int
	Dict   string // the dictionary text, before any stream
	Stream []byte // inflated, if the dictionary has a FlateDecode filter
}

var (
	reStartXref = regexp.MustCompile(`startxref\n(\d+)\n%%EOF\n$`)
	reLength    = regexp.MustCompile(`/Length (\d+)`)
)

// Parse reads raw through its cross-reference table and fails t when the file is malformed.
func Parse(t testing.TB, raw []byte) *Doc {
	t.Helper()
	if !bytes.HasPrefix(raw, []byte("%PDF-1.4\n")) {
		t.Fatalf("bad header %q", raw[:min(len(raw), 12)])
	}
	m := reStartXref.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("no startxref at the end")
	}
	off, _ := strconv.Atoi(string(m[1]))
	if !bytes.HasPrefix(raw[off:], []byte("xref\n0 ")) {
		t.Fatalf("startxref %d does not point at the xref table", off)
	}
	rest := raw[off+len("xref\n0 "):]
	nl := bytes.IndexByte(rest, '\n')
	n, _ := strconv.Atoi(string(rest[:nl]))
	entries := rest[nl+1:]
	d := &Doc{raw: raw, Objs: map[int]*Object{}}
	for id := 0; id < n; id++ {
		e := string(entries[id*20 : id*20+20])
		if id == 0 {
			continue
		}
		if len(e) != 20 || e[10:] != " 00000 n \n" {
			t.Fatalf("xref entry %d malformed: %q", id, e)
		}
		o, _ := strconv.Atoi(e[:10])
		head := fmt.Sprintf("%d 0 obj\n", id)
		if !bytes.HasPrefix(raw[o:], []byte(head)) {
			t.Fatalf("Object %d is not at its xref offset %d", id, o)
		}
		body := raw[o+len(head):]
		end := bytes.Index(body, []byte("\nendobj\n"))
		if end < 0 {
			t.Fatalf("Object %d has no endobj", id)
		}
		body = body[:end]
		ob := &Object{id: id, Dict: string(body)}
		if i := bytes.Index(body, []byte("\nstream\n")); i >= 0 {
			ob.Dict = string(body[:i])
			lm := reLength.FindStringSubmatch(ob.Dict)
			if lm == nil {
				t.Fatalf("stream Object %d has no /Length", id)
			}
			l, _ := strconv.Atoi(lm[1])
			data := body[i+len("\nstream\n"):]
			if !bytes.HasSuffix(data, []byte("\nendstream")) || len(data) != l+len("\nendstream") {
				t.Fatalf("Object %d: /Length %d does not match the stream (%d bytes)", id, l, len(data)-len("\nendstream"))
			}
			data = data[:l]
			if strings.Contains(ob.Dict, "/FlateDecode") {
				zr, err := zlib.NewReader(bytes.NewReader(data))
				if err != nil {
					t.Fatalf("Object %d: %v", id, err)
				}
				data, err = io.ReadAll(zr)
				if err != nil {
					t.Fatalf("Object %d: %v", id, err)
				}
			}
			ob.Stream = data
		}
		d.Objs[id] = ob
	}
	return d
}

var reRef = regexp.MustCompile(`(\d+) 0 R`)

func refs(s string) []int {
	var out []int
	for _, m := range reRef.FindAllStringSubmatch(s, -1) {
		n, _ := strconv.Atoi(m[1])
		out = append(out, n)
	}
	return out
}

// ForbiddenNames are the rule-3 names that must not appear in any object dictionary.
var ForbiddenNames = []string{"JavaScript", "JS", "OpenAction", "AA", "Launch", "URI", "SubmitForm", "ImportData",
	"EmbeddedFile", "RichMedia", "XFA", "Annots", "Annot", "Action", "AcroForm", "Names", "EmbeddedFiles", "Metadata", "Outlines", "OCProperties"}

var reName = regexp.MustCompile(`/([A-Za-z0-9_.+\-]+)`)

// NamesIn lists the PDF names of a dictionary text, skipping hex strings.
func NamesIn(dict string) []string {
	dict = regexp.MustCompile(`<[0-9A-Fa-f\s]*>`).ReplaceAllString(dict, "")
	var out []string
	for _, m := range reName.FindAllStringSubmatch(dict, -1) {
		out = append(out, m[1])
	}
	return out
}

// AssertNoActions fails t for every object carrying a name of ForbiddenNames.
func (d *Doc) AssertNoActions(t testing.TB) {
	t.Helper()
	for id, o := range d.Objs {
		for _, n := range NamesIn(o.Dict) {
			for _, f := range ForbiddenNames {
				if n == f {
					t.Errorf("object %d carries the forbidden name /%s: %s", id, n, o.Dict)
				}
			}
		}
	}
}

// FontMap maps a code in a font resource to the text a reader extracts for it.
type FontMap map[byte]string

// Fonts maps each font resource name to the text a reader extracts per code.
func (d *Doc) Fonts(t testing.TB) map[string]FontMap {
	t.Helper()
	res := d.Objs[4]
	if res == nil {
		t.Fatalf("no resources object")
	}
	out := map[string]FontMap{}
	re := regexp.MustCompile(`/(F\d+) (\d+) 0 R`)
	for _, m := range re.FindAllStringSubmatch(res.Dict, -1) {
		id, _ := strconv.Atoi(m[2])
		fo := d.Objs[id]
		fm := FontMap{}
		if strings.Contains(fo.Dict, "/ToUnicode") {
			tu := d.Objs[refs(fo.Dict[strings.Index(fo.Dict, "/ToUnicode"):])[0]]
			for _, l := range strings.Split(string(tu.Stream), "\n") {
				var code, u string
				if _, err := fmt.Sscanf(l, "<%2s> <%s", &code, &u); err == nil && strings.HasSuffix(u, ">") {
					c, _ := strconv.ParseUint(code, 16, 8)
					fm[byte(c)] = UTF16Text(strings.TrimSuffix(u, ">"))
				}
			}
		} else {
			if !strings.Contains(fo.Dict, "/WinAnsiEncoding") {
				t.Fatalf("font %s: no WinAnsiEncoding and no ToUnicode", m[1])
			}
			for c := 0; c < 256; c++ {
				fm[byte(c)] = string(charmap.Windows1252.DecodeByte(byte(c)))
			}
		}
		out[m[1]] = fm
	}
	return out
}

// UTF16Text decodes the hex digits of a UTF-16BE string (without its byte order mark).
func UTF16Text(h string) string {
	var u []uint16
	for i := 0; i+4 <= len(h); i += 4 {
		v, _ := strconv.ParseUint(h[i:i+4], 16, 16)
		u = append(u, uint16(v))
	}
	return string(utf16Decode(u))
}

func utf16Decode(u []uint16) []rune {
	var out []rune
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xD800 && u[i] < 0xDC00 && i+1 < len(u) {
			out = append(out, rune(u[i]-0xD800)<<10+rune(u[i+1]-0xDC00)+0x10000)
			i++
			continue
		}
		out = append(out, rune(u[i]))
	}
	return out
}

var (
	reTj = regexp.MustCompile(`<([0-9A-F]*)> Tj`)
	reTf = regexp.MustCompile(`/(F\d+) [\d.]+ Tf`)
)

// pageOf returns the kids of the page tree in order.
// Pages lists the page objects in order.
func (d *Doc) Pages(t testing.TB) []*Object {
	t.Helper()
	cat := d.Objs[1]
	if cat == nil || !strings.Contains(cat.Dict, "/Type /Catalog") {
		t.Fatalf("Object 1 is not the catalog: %v", cat)
	}
	if got := NamesIn(cat.Dict); fmt.Sprint(got) != "[Type Catalog Pages]" {
		t.Errorf("catalog names = %v", got)
	}
	pages := d.Objs[refs(cat.Dict)[0]]
	var out []*Object
	for _, id := range refs(pages.Dict) {
		out = append(out, d.Objs[id])
	}
	if !strings.Contains(pages.Dict, "/Count "+strconv.Itoa(len(out))) {
		t.Errorf("pages dictionary %q: /Count differs from %d kids", pages.Dict, len(out))
	}
	return out
}

// textLines returns, for one page, the text of every text Object (one per drawn line), in drawing order.
// TextLines is the text lines a page shows, in drawing order.
func (d *Doc) TextLines(t testing.TB, page *Object, fonts map[string]FontMap) []string {
	t.Helper()
	content := d.Objs[refs(page.Dict[strings.Index(page.Dict, "/Contents"):])[0]]
	var out []string
	for _, bt := range strings.Split(string(content.Stream), "BT ")[1:] {
		bt = bt[:strings.Index(bt, " ET")]
		var sb strings.Builder
		font := ""
		// walk tokens in order: Tf selects the font, Tj shows hex
		for rest := bt; ; {
			tf, tj := reTf.FindStringSubmatchIndex(rest), reTj.FindStringSubmatchIndex(rest)
			if tj == nil {
				break
			}
			if tf != nil && tf[0] < tj[0] {
				font = rest[tf[2]:tf[3]]
				rest = rest[tf[1]:]
				continue
			}
			h := rest[tj[2]:tj[3]]
			for i := 0; i+2 <= len(h); i += 2 {
				c, _ := strconv.ParseUint(h[i:i+2], 16, 8)
				txt, ok := fonts[font][byte(c)]
				if !ok {
					t.Fatalf("font %s has no mapping for code %02X", font, c)
				}
				sb.WriteString(txt)
			}
			rest = rest[tj[1]:]
		}
		out = append(out, sb.String())
	}
	return out
}

// opShape is a page's content stream with every shown string blanked: what a cell's content can
// change must not change the operator sequence (rule 2).
// OpShape is a page's content stream with every shown string blanked: what a cell's content can
// change must not change the operator sequence (rule 2).
func (d *Doc) OpShape(page *Object) string {
	content := d.Objs[refs(page.Dict[strings.Index(page.Dict, "/Contents"):])[0]]
	return reTj.ReplaceAllString(string(content.Stream), "<> Tj")
}

// Text parses raw, asserts it holds no action, and returns every text line of every page except the
// "Page n of m" footers.
func Text(t testing.TB, raw []byte) []string {
	t.Helper()
	d := Parse(t, raw)
	d.AssertNoActions(t)
	fonts := d.Fonts(t)
	var all []string
	for _, p := range d.Pages(t) {
		for _, l := range d.TextLines(t, p, fonts) {
			if !strings.HasPrefix(l, "Page ") {
				all = append(all, l)
			}
		}
	}
	return all
}
