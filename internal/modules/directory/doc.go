// Package directory is the server module of read-only directory queries (T-0668, walking skeleton).
// Handlers answers searchDirectoryUsers for the principal's tenant through the connector, and
// Classifier adds the TM-D17 hybrid classification to each user. Nothing here builds a directory query
// from client text: the text is a value in a typed filter tree.
package directory

import "github.com/skenzeriq/activediq/internal/platform/authz"

// ReadPermission is what searchDirectoryUsers needs; it is not a step-up permission.
const ReadPermission authz.Permission = "directory.read"
