package read_test

import (
	"errors"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/refusal"
)

// notFound is the error ad.Session.Read gives for a missing object.
func notFound() error { return ad.NewError(ad.CodeObjectNotFound) }

func asRefusal(err error, r **refusal.Refusal) bool { return errors.As(err, r) }
