package pdf

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
	"github.com/skenzeriq/activediq/internal/platform/export"
)

// countActions is the object scan of rule 3: how many dictionary names in the file are an action,
// a link, a script, an attachment or a form name.
func countActions(d *doc) int {
	n := 0
	for _, o := range d.objs {
		for _, name := range namesIn(o.dict) {
			for _, f := range forbiddenNames {
				if name == f {
					n++
				}
			}
		}
	}
	return n
}

var (
	reRun  = regexp.MustCompile(`/F\d+ [0-9.]+ Tf <> Tj`)
	reRuns = regexp.MustCompile(`RUN( RUN)+`)
)

// normalise folds a page's operator shape so that the only thing a cell's content may change is how
// many font runs it is drawn in (a character with no glyph in the standard font switches font): every
// run is one "RUN" and neighbours collapse. Any other operator a cell caused would remain visible.
func normalise(shape string) string {
	return reRuns.ReplaceAllString(reRun.ReplaceAllString(shape, "RUN"), "RUN")
}

// cellLine renders one cell and returns the text a reader extracts for it, the page's operator
// shape, and the action count.
func cellLine(t *testing.T, v string) (text, shape string, actions int) {
	t.Helper()
	cols, rows := oneCol(v)
	raw, _ := render(t, Options{}, cols, rows...)
	d := parse(t, raw)
	fonts := d.fonts(t)
	var lines []string
	for _, p := range d.pages(t) {
		for _, l := range d.textLines(t, p, fonts) {
			if !strings.HasPrefix(l, "Page ") {
				lines = append(lines, l)
			}
		}
	}
	return lines[len(lines)-1], normalise(d.opShape(d.pages(t)[0])), countActions(d)
}

// TestCorpus runs PDF-01 to PDF-14 (testdata/safe-primitives/pdf.jsonl, safe-primitives §12.7, FF-SP10):
// PDF-11 and PDF-12 are static (FF-SP1, FF-SP2).
func TestCorpus(t *testing.T) {
	_, baseShape, _ := cellLine(t, "x")
	corpustest.Run(t, "go/pdf", "pdf", func(r corpus.Record) (corpus.Result, error) {
		switch r.Call {
		case "Cell":
			v, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			text, shape, actions := cellLine(t, v.Text())
			return corpustest.Value(map[string]any{"text": text, "sameOperators": shape == baseShape, "actions": actions})
		case "Title":
			v, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			cols, rows := oneCol("v")
			raw, _ := render(t, Options{Title: v.Text()}, cols, rows...)
			d := parse(t, raw)
			info := d.objs[3].dict
			const pre, post = "<< /Title <FEFF", "> /Producer (activeDIQ) >>"
			if !strings.HasPrefix(info, pre) || !strings.HasSuffix(info, post) {
				return corpus.Result{}, fmt.Errorf("info = %q", info)
			}
			title := utf16Text(info[len(pre) : len(info)-len(post)])
			return corpustest.Value(map[string]any{"title": title, "infoKeys": strings.Join(namesIn(info), ","), "actions": countActions(d)})
		case "CellShape":
			v, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			var repeat, cut int
			if err := json.Unmarshal(r.Args["repeat"], &repeat); err != nil {
				return corpus.Result{}, err
			}
			if err := json.Unmarshal(r.Args["cut"], &cut); err != nil {
				return corpus.Result{}, err
			}
			long := strings.Repeat(v.Text(), repeat)[:cut]
			cols := make([]export.Column, MaxColumns) // narrow columns, so the cell is longer than 200 lines
			row := make([]export.Cell, MaxColumns)
			cols[0] = export.Column{Label: "Value"}
			row[0] = export.Text(long)
			for i := 1; i < MaxColumns; i++ {
				cols[i] = export.Column{Label: "c" + strconv.Itoa(i)}
			}
			raw, rep := render(t, Options{}, cols, row)
			var lines []string // the cell's lines: every page repeats the header row, which is not the cell
			for _, l := range extract(t, raw) {
				if l != "Value" && !(len(l) > 1 && l[0] == 'c' && strings.Trim(l[1:], "0123456789") == "") {
					lines = append(lines, l)
				}
			}
			return corpustest.Value(map[string]any{"lines": len(lines), "marker": lines[len(lines)-1], "truncated": rep.Truncated})
		case "Run":
			var n int64
			if err := json.Unmarshal(r.Args["rows"], &n); err != nil {
				return corpus.Result{}, err
			}
			w, err := NewWriter(io.Discard, Options{})
			if err != nil {
				return corpus.Result{}, err
			}
			src := &cappedSource{n: n}
			_, err = export.Run(context.Background(), src, w, MaxRows)
			if errors.Is(err, export.ErrRowCapExceeded) && src.pulled == 0 {
				return corpustest.Err("RowCapExceeded"), nil
			}
			return corpus.Result{}, fmt.Errorf("export of %d rows (pulled %d) returned %v", n, src.pulled, err)
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

type cappedSource struct {
	n      int64
	pulled int
}

func (*cappedSource) Columns() []export.Column               { return []export.Column{{Label: "a"}} }
func (c *cappedSource) Count(context.Context) (int64, error) { return c.n, nil }
func (c *cappedSource) Next(context.Context) ([]export.Cell, error) {
	c.pulled++
	return nil, errors.New("Next called: the cap check must come first")
}
