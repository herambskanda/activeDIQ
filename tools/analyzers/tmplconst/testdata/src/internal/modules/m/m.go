package m

import (
	"embed"
	"html/template"
)

//go:embed *.go
var fsys embed.FS

type notEmbed struct{}

func f(src, glob string) {
	template.New("a").Parse("<p>{{.}}</p>")
	template.New("b").Parse(src) // want `non-constant string`
	template.ParseFS(fsys, "*.tmpl")
	template.ParseGlob(glob) // want `reads template code from disk`
	template.ParseFiles(src) // want `reads template code from disk`
}
