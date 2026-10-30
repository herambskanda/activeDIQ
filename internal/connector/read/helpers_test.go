package read_test

import "github.com/skenzeriq/activediq/internal/connector/ad"

// notFound is the error ad.Session.Read gives for a missing object.
func notFound() error { return ad.NewError(ad.CodeObjectNotFound) }
