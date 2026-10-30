package chain

import (
	"bytes"
	"strings"
	"testing"
)

// json/v2 omitempty keeps numeric 0; a current key (RetiredSeq 0) must not gain "retired_seq" (v1 bytes).
func TestWriteBundleOmitsZeroRetiredSeq(t *testing.T) {
	var buf bytes.Buffer
	b := Bundle{Tenant: "t", Keys: []KeyInfo{{KeyID: "k1", PublicKey: []byte{1}, CreatedSeq: 1}, {KeyID: "k0", PublicKey: []byte{2}, CreatedSeq: 0, RetiredSeq: 5}}}
	if err := WriteBundle(&buf, b); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if n := strings.Count(out, "retired_seq"); n != 1 || !strings.Contains(out, `"retired_seq": 5`) {
		t.Fatalf("want retired_seq only for the retired key:\n%s", out)
	}
}
