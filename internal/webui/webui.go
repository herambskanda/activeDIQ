// Package webui embeds the built admin console (ADR-0001 tier W): web/dist, copied here by
// `make web-embed`, compiled into the server binary. Node is build-time only.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Console returns the built console rooted at its index.html, or nil when the binary was built
// without one (only the .gitkeep placeholder is present): the server then serves the API alone.
func Console() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
