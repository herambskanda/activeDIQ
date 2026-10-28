package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// ErrNoPinnableDC is returned when the connection has no reachable writable DC for the naming context.
var ErrNoPinnableDC = errors.New("server: no reachable writable DC to pin for the naming context")

// DCLister lists the writable DCs of a naming context, live (client.DCDirectory).
type DCLister interface {
	WritableDCs(ctx context.Context, connectionID string, nc authority.NamingContextID) ([]client.WritableDC, error)
}

// dcPinner is the operation.Pinner (ADR-0005 rule 5). Host and DSA GUID come from one entry of one
// live DC listing, so they describe the same DC. When previous is still listed its current DSA GUID is
// returned, so a DC rebuilt under the same name yields a different pin; when it is not (gone, RODC,
// unreachable) another writable DC is pinned. Any failure is an error and never a partial pin.
type dcPinner struct{ dcs DCLister }

var _ operation.Pinner = dcPinner{}

func newDCPinner(dcs DCLister) (dcPinner, error) {
	if dcs == nil {
		return dcPinner{}, errors.New("server: DC pinner needs a DC lister")
	}
	return dcPinner{dcs: dcs}, nil
}

func (p dcPinner) Pin(ctx context.Context, connectionID string, nc authority.NamingContextID, previous string) (operation.DCPin, error) {
	list, err := p.dcs.WritableDCs(ctx, connectionID, nc)
	if err != nil {
		return operation.DCPin{}, fmt.Errorf("server: pin: %w", err)
	}
	pick := func(dc client.WritableDC) (operation.DCPin, error) {
		if dc.Host == "" || dc.DSAGUID == "" {
			return operation.DCPin{}, client.ErrDCIdentity
		}
		return operation.DCPin{Host: dc.Host, DSAGUID: dc.DSAGUID}, nil
	}
	if previous != "" {
		for _, dc := range list {
			if strings.EqualFold(dc.Host, previous) {
				return pick(dc)
			}
		}
	}
	if len(list) == 0 {
		return operation.DCPin{}, ErrNoPinnableDC
	}
	return pick(list[0])
}
