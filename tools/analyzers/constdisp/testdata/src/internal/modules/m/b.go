package m

import (
	"net/http"

	"internal/modules/pfx"
)

const cross = P + "Disposition" // want `folds to Content-Disposition`

type name string

const typed name = "content-" + "disposition" // want `folds to Content-Disposition`

const imported = pfx.Prefix + "Disposition" // want `folds to Content-Disposition`

func f(w http.ResponseWriter) {
	w.Header().Set(cross, "inline")    // want `folds to Content-Disposition`
	w.Header().Add(imported, "inline") // want `folds to Content-Disposition`
	w.Header().Set(string(typed), "x") // want `folds to Content-Disposition`
	_ = w.Header()[cross]              // want `folds to Content-Disposition`
	w.Header().Set(P+"Type", "x")
	w.Header().Set("Content-Type", "x")
}
