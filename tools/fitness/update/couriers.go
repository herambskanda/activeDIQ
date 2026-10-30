package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/skenzeriq/activediq/internal/platform/updateverify"
)

// payload is what a release looks like before a courier moves it.
type payload struct {
	chain      [][]byte
	ts, sn, tg []byte
	artefact   []byte
}

// counter counts the artefact bytes the verifier actually pulled, so an overlong artefact can be shown
// to have been aborted mid-stream.
type counter struct {
	r io.Reader
	n int64
}

func (c *counter) Read(p []byte) (int, error) { n, err := c.r.Read(p); c.n += int64(n); return n, err }

// courier delivers a payload as an Input. Both end in the same updateverify.Input and the same
// Verifier.Verify call (ENH-07 rule 4); the only difference is the transport.
type courier struct {
	name    string
	deliver func(dir string, p payload) (updateverify.Input, *counter, func(), error)
}

// onlineCourier serves the files from a loopback HTTP server and fetches them with GET, the way the
// online courier reads the static metadata and artefact URLs.
var onlineCourier = courier{"online", func(_ string, p payload) (updateverify.Input, *counter, func(), error) {
	mux := http.NewServeMux()
	serve := func(path string, b []byte) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(b) })
	}
	serve("/timestamp.json", p.ts)
	serve("/snapshot.json", p.sn)
	serve("/targets.json", p.tg)
	for i, r := range p.chain {
		serve(fmt.Sprintf("/root/%d.json", i), r)
	}
	mux.HandleFunc("/artefact", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.Copy(w, bytes.NewReader(p.artefact)) })
	srv := httptest.NewServer(mux)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	get := func(path string) ([]byte, error) {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	in := updateverify.Input{}
	var err error
	for i := range p.chain {
		b, e := get(fmt.Sprintf("/root/%d.json", i))
		if e != nil {
			err = e
		}
		in.RootChain = append(in.RootChain, b)
	}
	for _, f := range []struct {
		path string
		dst  *[]byte
	}{{"/timestamp.json", &in.Timestamp}, {"/snapshot.json", &in.Snapshot}, {"/targets.json", &in.Targets}} {
		b, e := get(f.path)
		if e != nil {
			err = e
		}
		*f.dst = b
	}
	resp, e := client.Get(srv.URL + "/artefact")
	if e != nil {
		srv.Close()
		return in, nil, func() {}, e
	}
	c := &counter{r: resp.Body}
	in.Artifact = c
	return in, c, func() { resp.Body.Close(); client.CloseIdleConnections(); srv.Close() }, err
}}

// offlineCourier writes a bundle (a tar: metadata first, the artefact last) to disk and reads it back
// as a stream, with no socket involved. This is the courier that runs under `--network none`.
var offlineCourier = courier{"offline", func(dir string, p payload) (updateverify.Input, *counter, func(), error) {
	path := filepath.Join(dir, "update-bundle.tar")
	if err := writeBundle(path, p); err != nil {
		return updateverify.Input{}, nil, func() {}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return updateverify.Input{}, nil, func() {}, err
	}
	tr := tar.NewReader(f)
	in := updateverify.Input{}
	for {
		h, err := tr.Next()
		if err != nil {
			f.Close()
			return in, nil, func() {}, fmt.Errorf("bundle has no artefact entry: %w", err)
		}
		if h.Name == "artefact" {
			c := &counter{r: tr}
			in.Artifact = c
			return in, c, func() { f.Close() }, nil
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			f.Close()
			return in, nil, func() {}, err
		}
		switch h.Name {
		case "timestamp.json":
			in.Timestamp = b
		case "snapshot.json":
			in.Snapshot = b
		case "targets.json":
			in.Targets = b
		default:
			in.RootChain = append(in.RootChain, b)
		}
	}
}}

func writeBundle(path string, p payload) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	add := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b))}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	for i, r := range p.chain {
		if err := add(fmt.Sprintf("root-%04d.json", i), r); err != nil {
			return err
		}
	}
	for _, e := range []struct {
		n string
		b []byte
	}{{"timestamp.json", p.ts}, {"snapshot.json", p.sn}, {"targets.json", p.tg}} {
		if err := add(e.n, e.b); err != nil {
			return err
		}
	}
	if err := add("artefact", p.artefact); err != nil {
		return err
	}
	return tw.Close()
}
