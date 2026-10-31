package pdf

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

// This file is the independent parser of FF-SP10 for PDF (safe-primitives §12.7 rule 2 and 3): it reads
// the finished file through its cross-reference table and objects, never through the writer's own
// tables, and extracts the text a reader would show.

type doc struct {
	raw  []byte
	objs map[int]*object
}

type object struct {
	id     int
	dict   string // the dictionary text, before any stream
	stream []byte // inflated, if the dictionary has a FlateDecode filter
}

var (
	reStartXref = regexp.MustCompile(`startxref\n(\d+)\n%%EOF\n$`)
	reLength    = regexp.MustCompile(`/Length (\d+)`)
)

func parse(t testing.TB, raw []byte) *doc {
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
	d := &doc{raw: raw, objs: map[int]*object{}}
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
			t.Fatalf("object %d is not at its xref offset %d", id, o)
		}
		body := raw[o+len(head):]
		end := bytes.Index(body, []byte("\nendobj\n"))
		if end < 0 {
			t.Fatalf("object %d has no endobj", id)
		}
		body = body[:end]
		ob := &object{id: id, dict: string(body)}
		if i := bytes.Index(body, []byte("\nstream\n")); i >= 0 {
			ob.dict = string(body[:i])
			lm := reLength.FindStringSubmatch(ob.dict)
			if lm == nil {
				t.Fatalf("stream object %d has no /Length", id)
			}
			l, _ := strconv.Atoi(lm[1])
			data := body[i+len("\nstream\n"):]
			if !bytes.HasSuffix(data, []byte("\nendstream")) || len(data) != l+len("\nendstream") {
				t.Fatalf("object %d: /Length %d does not match the stream (%d bytes)", id, l, len(data)-len("\nendstream"))
			}
			data = data[:l]
			if strings.Contains(ob.dict, "/FlateDecode") {
				zr, err := zlib.NewReader(bytes.NewReader(data))
				if err != nil {
					t.Fatalf("object %d: %v", id, err)
				}
				data, err = io.ReadAll(zr)
				if err != nil {
					t.Fatalf("object %d: %v", id, err)
				}
			}
			ob.stream = data
		}
		d.objs[id] = ob
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

// forbiddenNames are the rule-3 names that must not appear in any object dictionary.
var forbiddenNames = []string{"JavaScript", "JS", "OpenAction", "AA", "Launch", "URI", "SubmitForm", "ImportData",
	"EmbeddedFile", "RichMedia", "XFA", "Annots", "Annot", "Action", "AcroForm", "Names", "EmbeddedFiles", "Metadata", "Outlines", "OCProperties"}

var reName = regexp.MustCompile(`/([A-Za-z0-9_.+\-]+)`)

// namesIn lists the PDF names of a dictionary text, skipping hex strings.
func namesIn(dict string) []string {
	dict = regexp.MustCompile(`<[0-9A-Fa-f\s]*>`).ReplaceAllString(dict, "")
	var out []string
	for _, m := range reName.FindAllStringSubmatch(dict, -1) {
		out = append(out, m[1])
	}
	return out
}

func (d *doc) assertNoActions(t testing.TB) {
	t.Helper()
	for id, o := range d.objs {
		for _, n := range namesIn(o.dict) {
			for _, f := range forbiddenNames {
				if n == f {
					t.Errorf("object %d carries the forbidden name /%s: %s", id, n, o.dict)
				}
			}
		}
	}
}

// fontMap maps a code in a font resource to the text a reader extracts for it.
type fontMap map[byte]string

func (d *doc) fonts(t testing.TB) map[string]fontMap {
	t.Helper()
	res := d.objs[4]
	if res == nil {
		t.Fatalf("no resources object")
	}
	out := map[string]fontMap{}
	re := regexp.MustCompile(`/(F\d+) (\d+) 0 R`)
	for _, m := range re.FindAllStringSubmatch(res.dict, -1) {
		id, _ := strconv.Atoi(m[2])
		fo := d.objs[id]
		fm := fontMap{}
		if strings.Contains(fo.dict, "/ToUnicode") {
			tu := d.objs[refs(fo.dict[strings.Index(fo.dict, "/ToUnicode"):])[0]]
			for _, l := range strings.Split(string(tu.stream), "\n") {
				var code, u string
				if _, err := fmt.Sscanf(l, "<%2s> <%s", &code, &u); err == nil && strings.HasSuffix(u, ">") {
					c, _ := strconv.ParseUint(code, 16, 8)
					fm[byte(c)] = utf16Text(strings.TrimSuffix(u, ">"))
				}
			}
		} else {
			if !strings.Contains(fo.dict, "/WinAnsiEncoding") {
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

func utf16Text(h string) string {
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
func (d *doc) pages(t testing.TB) []*object {
	t.Helper()
	cat := d.objs[1]
	if cat == nil || !strings.Contains(cat.dict, "/Type /Catalog") {
		t.Fatalf("object 1 is not the catalog: %v", cat)
	}
	if got := namesIn(cat.dict); fmt.Sprint(got) != "[Type Catalog Pages]" {
		t.Errorf("catalog names = %v", got)
	}
	pages := d.objs[refs(cat.dict)[0]]
	var out []*object
	for _, id := range refs(pages.dict) {
		out = append(out, d.objs[id])
	}
	if !strings.Contains(pages.dict, "/Count "+strconv.Itoa(len(out))) {
		t.Errorf("pages dict %q: /Count differs from %d kids", pages.dict, len(out))
	}
	return out
}

// textLines returns, for one page, the text of every text object (one per drawn line), in drawing order.
func (d *doc) textLines(t testing.TB, page *object, fonts map[string]fontMap) []string {
	t.Helper()
	content := d.objs[refs(page.dict[strings.Index(page.dict, "/Contents"):])[0]]
	var out []string
	for _, bt := range strings.Split(string(content.stream), "BT ")[1:] {
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
func (d *doc) opShape(page *object) string {
	content := d.objs[refs(page.dict[strings.Index(page.dict, "/Contents"):])[0]]
	return reTj.ReplaceAllString(string(content.stream), "<> Tj")
}
