// Command vettool runs the safe-primitives go/analysis passes under `go vet`:
//
//	go build -o /tmp/vettool ./tools/vettool && go vet -vettool=/tmp/vettool ./...
//
// `make fitness-safeprim` runs the same passes in process with the rest of FF-SP1 to FF-SP3.
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/skenzeriq/activediq/tools/analyzers"
)

func main() { multichecker.Main(analyzers.All()...) }
