package fleet_test

import (
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func TestIdentityRoundTripAndStrictness(t *testing.T) {
	tid := tenant.New()
	cid := "00000000-0000-4000-8000-0000000000aa"
	good := &x509.Certificate{URIs: fleet.URIs(tid, "connector", cid), SerialNumber: big.NewInt(255)}
	id, err := fleet.IdentityOf(good)
	if err != nil || id.Tenant != tid || id.Kind != "connector" || id.ComponentID != cid || id.Serial != "ff" {
		t.Fatalf("%+v %v", id, err)
	}
	u := func(s string) *url.URL { x, _ := url.Parse(s); return x }
	bad := map[string]*x509.Certificate{
		"nil":            nil,
		"no uris":        {SerialNumber: big.NewInt(1)},
		"extra dns":      {URIs: good.URIs, DNSNames: []string{"x"}, SerialNumber: big.NewInt(1)},
		"extra ip":       {URIs: good.URIs, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}, SerialNumber: big.NewInt(1)},
		"extra uri":      {URIs: append(append([]*url.URL{}, good.URIs...), u("urn:x:y")), SerialNumber: big.NewInt(1)},
		"two tenants":    {URIs: []*url.URL{good.URIs[0], good.URIs[0]}, SerialNumber: big.NewInt(1)},
		"bare agent":     {URIs: []*url.URL{good.URIs[0], u("urn:activediq:component:agent:" + cid)}, SerialNumber: big.NewInt(1)},
		"unknown kind":   {URIs: []*url.URL{good.URIs[0], u("urn:activediq:component:dc:" + cid)}, SerialNumber: big.NewInt(1)},
		"upper-case id":  {URIs: []*url.URL{good.URIs[0], u("urn:activediq:component:addc:00000000-0000-4000-8000-0000000000AA")}, SerialNumber: big.NewInt(1)},
		"foreign scheme": {URIs: []*url.URL{u("spiffe://x/tenant"), good.URIs[1]}, SerialNumber: big.NewInt(1)},
	}
	for name, c := range bad {
		if _, err := fleet.IdentityOf(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestIdentityKindIsTheClosedModuleVocabulary(t *testing.T) {
	tid := tenant.New()
	cid := "00000000-0000-4000-8000-0000000000aa"
	for _, k := range []string{fleet.KindConnector, fleet.KindADDC, fleet.KindFileServer} {
		id, err := fleet.IdentityOf(&x509.Certificate{URIs: fleet.URIs(tid, k, cid), SerialNumber: big.NewInt(1)})
		if err != nil || id.Kind != k {
			t.Errorf("%s: %+v %v", k, id, err)
		}
	}
	for _, k := range []string{"agent", "", "ADDC", "addc ", "file-server", "dc"} {
		if _, err := fleet.IdentityOf(&x509.Certificate{URIs: fleet.URIs(tid, k, cid), SerialNumber: big.NewInt(1)}); !errors.Is(err, fleet.ErrIdentity) {
			t.Errorf("kind %q: got %v, want ErrIdentity", k, err)
		}
	}
}
