package step

import "github.com/skenzeriq/activediq/internal/platform/operation/digest"

// The plan digest lives in the leaf package operation/digest so that the connector, which must not
// link the store, recomputes it with the very same function (connector-contract §8.1 step 5).

// Digest is the SHA-256 of one planned write (ADR-0005 rule 2).
type Digest = digest.Digest

// Attr is one attribute of the planned write. A secret value is never hashed: only its presence is.
type Attr = digest.Attr

// Compute returns the digest of (kind, target, attrs); see digest.Compute.
var Compute = digest.Compute
