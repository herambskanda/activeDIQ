// Package directory is the server module of read-only directory queries (T-0668, walking skeleton).
// Today it holds the generated API types of the `directory` OpenAPI tag (searchDirectoryUsers); the
// handler that answers from the directory lands with the backend ticket that follows. Nothing here
// builds a directory query from client text.
package directory

import "github.com/skenzeriq/activediq/internal/platform/authz"

// ReadPermission is what searchDirectoryUsers needs; it is not a step-up permission.
const ReadPermission authz.Permission = "directory.read"
