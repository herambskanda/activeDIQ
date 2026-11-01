package webui

import (
	"io/fs"
	"regexp"
	"testing"
)

// A checkout without a built console embeds only the placeholder: Console must say so, not serve it.
// With one (make web-embed) the shell must carry no inline script, which the console's CSP would refuse.
func TestConsoleShell(t *testing.T) {
	c := Console()
	if c == nil {
		t.Skip("no built console embedded (make web-embed)")
	}
	b, err := fs.ReadFile(c, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`<div id="root"></div>`).Match(b) {
		t.Error("index.html has no #root")
	}
	if regexp.MustCompile(`<script(\s[^>]*)?>\s*[^<\s]`).Match(b) {
		t.Error("index.html has an inline script; the CSP forbids it")
	}
}
