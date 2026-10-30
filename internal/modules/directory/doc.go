// Package directory is the server module of read-only directory queries (T-0668, walking skeleton).
// Handlers answers searchDirectoryUsers for the principal's tenant through the connector, and
// Classifier adds the TM-D17 hybrid classification to each user. Nothing here builds a directory query
// from client text: the text is a value in a typed filter tree. Results are trimmed to the principal's
// authz.ReadScope for directory.read (T-0875, m2-plan decision 4): the scope's include roots are the
// query's roots and each result is decided by ReadScope.Admits; without a ReadScopes producer nothing is
// answered.
package directory

import "github.com/skenzeriq/activediq/internal/platform/authz"

// ReadPermission is what searchDirectoryUsers needs; it is not a step-up permission.
const ReadPermission authz.Permission = "directory.read"
