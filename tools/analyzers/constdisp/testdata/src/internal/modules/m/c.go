package m

import "net/http"

func g(w http.ResponseWriter, dynamic string) {
	w.Header().Set(dynamic, "x")
	w.Header().Set(P+"Length", "1")
}
