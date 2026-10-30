package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var ts = time.Unix(1790000000, 0)

const lock = `{"packages":{"":{"name":"w"},
"node_modules/react":{"version":"19.3.0","integrity":"sha512-AAAA"},
"node_modules/@scope/pkg":{"version":"1.0.0"},
"node_modules/vitest":{"version":"3.0.0","dev":true}}}`

func TestBuildListsShippedComponentsOnly(t *testing.T) {
	b, err := Build("activediq", "v1.0.0", ts, []goMod{{"example.com/a", "v1.2.3"}, {"example.com/a", "v1.2.3"}, {"std", ""}}, []byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		BomFormat, SpecVersion, SerialNumber string
		Components                           []component
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if d.BomFormat != "CycloneDX" || d.SpecVersion != "1.5" || !strings.HasPrefix(d.SerialNumber, "urn:uuid:") {
		t.Fatalf("header: %+v", d)
	}
	var got []string
	for _, c := range d.Components {
		got = append(got, c.PURL)
	}
	want := "pkg:golang/example.com/a@v1.2.3 pkg:npm/%40scope/pkg@1.0.0 pkg:npm/react@19.3.0"
	if strings.Join(got, " ") != want {
		t.Fatalf("components %v\nwant %s", got, want)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	m := []goMod{{"example.com/a", "v1.2.3"}}
	a, _ := Build("p", "v1", ts, m, []byte(lock))
	b, _ := Build("p", "v1", ts, m, []byte(lock))
	if !bytes.Equal(a, b) {
		t.Fatal("two builds differ")
	}
	c, _ := Build("p", "v2", ts, m, []byte(lock))
	if bytes.Equal(a, c) {
		t.Fatal("version not reflected")
	}
}

func TestBuildRefusesEmpty(t *testing.T) {
	if _, err := Build("p", "v1", ts, nil, nil); err == nil {
		t.Fatal("empty SBOM accepted")
	}
	if _, err := Build("p", "v1", ts, nil, []byte("{")); err == nil {
		t.Fatal("bad lockfile accepted")
	}
}
