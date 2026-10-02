// Package capability holds the named capability IDs that manifests list and modules require
// (blueprint §3.2, §5.1). It is a leaf package: IDs and a set, no behaviour beyond membership.
package capability

// ID names a capability, for example "directory.ad".
type ID string

// The capabilities named by the blueprint (§3.2, §3.3). A capability is added here by the
// ticket that introduces the feature behind it.
const (
	DirectoryAD        ID = "directory.ad"
	DirectoryEntra     ID = "directory.entra"
	TenantProvisioning ID = "tenant-provisioning"
)

// Set is the set of capabilities a process has enabled.
type Set map[ID]struct{}

// NewSet returns a Set holding ids.
func NewSet(ids ...ID) Set {
	s := make(Set, len(ids))
	for _, id := range ids {
		s[id] = struct{}{}
	}
	return s
}

// Enabled reports whether id is in the set.
func (s Set) Enabled(id ID) bool {
	_, ok := s[id]
	return ok
}
