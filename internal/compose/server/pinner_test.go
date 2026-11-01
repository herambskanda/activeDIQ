package server

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

const (
	dsaA  = "11111111-2222-3333-4444-555555555555"
	dsaB  = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	dsaA2 = "bbbbbbbb-2222-3333-4444-555555555555" // dc1 rebuilt under the same name
)

type fakeDCs struct {
	list []client.WritableDC
	err  error
}

func (f *fakeDCs) WritableDCs(context.Context, string, authority.NamingContextID) ([]client.WritableDC, error) {
	return f.list, f.err
}

func pinnerOver(t *testing.T, f *fakeDCs) dcPinner {
	t.Helper()
	p, err := newDCPinner(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPinReturnsHostAndGUIDOfOneDC(t *testing.T) {
	p := pinnerOver(t, &fakeDCs{list: []client.WritableDC{{Host: "dc1.example.test", DSAGUID: dsaA}, {Host: "dc2.example.test", DSAGUID: dsaB}}})
	pin, err := p.Pin(context.Background(), "c1", "nc1", "")
	if err != nil || pin.Host != "dc1.example.test" || pin.DSAGUID != dsaA {
		t.Fatalf("pin = %+v, %v", pin, err)
	}
}

// Pin stability across two steps, and the pin changing when the kept host is rebuilt (AC3, AC5).
func TestPinStableAcrossStepsAndChangesOnRebuild(t *testing.T) {
	f := &fakeDCs{list: []client.WritableDC{{Host: "dc1.example.test", DSAGUID: dsaA}, {Host: "dc2.example.test", DSAGUID: dsaB}}}
	p := pinnerOver(t, f)
	ctx := context.Background()
	first, err := p.Pin(ctx, "c1", "nc1", "")
	if err != nil {
		t.Fatal(err)
	}
	// The list order changes (dc2 sorts first would not matter): the kept host stays pinned.
	f.list = []client.WritableDC{{Host: "dc0.example.test", DSAGUID: dsaB}, {Host: "DC1.example.test", DSAGUID: dsaA}}
	second, err := p.Pin(ctx, "c1", "nc1", first.Host)
	if err != nil || second.DSAGUID != first.DSAGUID {
		t.Fatalf("second = %+v, %v; want the same DSA as %+v", second, err, first)
	}
	// dc1 is rebuilt: same name, new DSA GUID.
	f.list = []client.WritableDC{{Host: "dc1.example.test", DSAGUID: dsaA2}}
	third, err := p.Pin(ctx, "c1", "nc1", first.Host)
	if err != nil || third.DSAGUID != dsaA2 || third.DSAGUID == first.DSAGUID {
		t.Fatalf("third = %+v, %v; want the rebuilt DC's new GUID", third, err)
	}
}

func TestPinMovesWhenPreviousIsNoLongerWritable(t *testing.T) {
	p := pinnerOver(t, &fakeDCs{list: []client.WritableDC{{Host: "dc2.example.test", DSAGUID: dsaB}}})
	pin, err := p.Pin(context.Background(), "c1", "nc1", "dc1.example.test")
	if err != nil || pin.Host != "dc2.example.test" || pin.DSAGUID != dsaB {
		t.Fatalf("pin = %+v, %v", pin, err)
	}
}

func TestPinNeverPartial(t *testing.T) {
	boom := errors.New("read failed")
	cases := map[string]*fakeDCs{
		"read fails":  {err: boom},
		"no writable": {},
		"empty guid":  {list: []client.WritableDC{{Host: "dc1.example.test"}}},
		"empty host":  {list: []client.WritableDC{{DSAGUID: dsaA}}},
	}
	for name, f := range cases {
		pin, err := pinnerOver(t, f).Pin(context.Background(), "c1", "nc1", "")
		if err == nil || pin.Host != "" || pin.DSAGUID != "" {
			t.Errorf("%s: pin = %+v, err = %v; want an error and a zero pin", name, pin, err)
		}
	}
}

func TestNewDCPinnerRequiresLister(t *testing.T) {
	if _, err := newDCPinner(nil); err == nil {
		t.Fatal("nil lister accepted")
	}
}

// PinOther never returns the excluded DC, by host (any case) or by DSA GUID.
func TestPinOtherExcludesPinnedDC(t *testing.T) {
	p := pinnerOver(t, &fakeDCs{list: []client.WritableDC{{Host: "dc1.example.test", DSAGUID: dsaA}, {Host: "dc2.example.test", DSAGUID: dsaB}}})
	got, err := p.PinOther(context.Background(), "c1", "nc1", operation.DCPin{Host: "DC1.example.test", DSAGUID: dsaA})
	if err != nil || got.Host != "dc2.example.test" || got.DSAGUID != dsaB {
		t.Fatalf("got %+v, %v", got, err)
	}
	only := pinnerOver(t, &fakeDCs{list: []client.WritableDC{{Host: "dc1.example.test", DSAGUID: dsaA}}})
	if _, err := only.PinOther(context.Background(), "c1", "nc1", operation.DCPin{Host: "dc1.example.test"}); !errors.Is(err, ErrNoPinnableDC) {
		t.Fatalf("err = %v", err)
	}
}
