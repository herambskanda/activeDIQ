// Package importscan is the TM-F-CREDPROV import scan: a PE file (and its delay-load
// imports) must not import web-rendering or shell-dialog components.
package importscan

import (
	"debug/pe"
	"fmt"
	"io"
	"strings"
)

// Denied DLLs (lower case). Categories: embedded browser/web view, HTML/URL handlers,
// common/shell dialogs and shell execution, help and print UI.
var Denied = map[string]string{
	"ieframe.dll": "web", "mshtml.dll": "web", "shdocvw.dll": "web", "webview2loader.dll": "web",
	"msedgewebview2.dll": "web", "urlmon.dll": "web", "wininet.dll": "web (use WinHTTP/Schannel)",
	"comdlg32.dll": "dialog", "shell32.dll": "dialog/shell-exec", "shlwapi.dll": "shell helpers",
	"windows.ui.xaml.dll": "ui", "winspool.drv": "print", "xpsprint.dll": "print",
	"hhctrl.ocx": "help", "htmlhelp.dll": "help", "cef.dll": "web", "libcef.dll": "web",
}

// Scan returns violations (empty = pass). readerAt must be a PE image.
func Scan(r io.ReaderAt) ([]string, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("importscan: not a PE: %w", err)
	}
	defer f.Close()
	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, l := range libs {
		l = strings.ToLower(l)
		if cat, ok := Denied[l]; ok {
			bad = append(bad, l+" ("+cat+")")
		}
		if strings.HasPrefix(l, "api-ms-win-shell-") {
			bad = append(bad, l+" (dialog/shell-exec)")
		}
	}
	return bad, nil
}
