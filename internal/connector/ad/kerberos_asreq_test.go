package ad

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"

	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// TestKerberosClientOmitsPAReqEncPARep pins T-0846: the client the connector builds must not send
// PA-REQ-ENC-PA-REP, because a Windows Server 2025 KDC then sets the EncPARep flag without PA-FX-FAST and
// go-krb5 rejects the AS-REP. The Windows lab (TestWindowsLabKerberosOpen*) proves the bind itself; this
// captures the AS-REQ that actually leaves the client, so the regression is caught without a Windows DC.
func TestKerberosClientOmitsPAReqEncPARep(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan messages.ASReq, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		b := make([]byte, binary.BigEndian.Uint32(hdr[:]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		var req messages.ASReq
		if req.Unmarshal(b) == nil {
			got <- req
		}
	}()

	k := Kerberos{Principal: "svc-t0846", Realm: "LAB.ACTIVEDIQ.TEST", Keytab: secret.FromBytes([]byte{1}), KDCs: []string{ln.Addr().String()}}
	kt := keytab.New()
	if err := kt.AddEntry("svc-t0846", "LAB.ACTIVEDIQ.TEST", "pw-not-secret", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	krb := newKerberosClient(k, kt, k.krb5Config())
	defer krb.Destroy()
	// The fake KDC never answers, so the login fails; only the request it sent matters.
	_ = krb.Login()

	select {
	case req := <-got:
		if req.PAData.Contains(patype.PA_REQ_ENC_PA_REP) {
			t.Fatal("AS-REQ carries PA-REQ-ENC-PA-REP: a WS2025 KDC would answer with EncPARep and go-krb5 would reject it (T-0846)")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no AS-REQ reached the fake KDC")
	}
}
