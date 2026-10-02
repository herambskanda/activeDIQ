// Package profile holds the deployment manifest types and the three manifests (blueprint §3.2).
// It is data only: it imports the standard library and platform/capability, never an
// implementation package, so importing it links no adapter, module or connector code into a binary.
// Role packages map the adapter enums to implementations.
package profile

import "github.com/skenzeriq/activediq/internal/platform/capability"

// Role is a process role (ADR-0002 rule 2).
type Role string

// The roles with a binary in the skeleton. radius, fpolicy and t0-connector are added with their
// binaries.
const (
	RoleServer    Role = "server"
	RoleConnector Role = "connector"
	RoleEdge      Role = "edge"
	RoleAgent     Role = "agent"
)

// Provider is a directory provider a connector role serves.
type Provider string

// The directory providers (blueprint §5.3).
const (
	ProviderAD    Provider = "ad"
	ProviderEntra Provider = "entra"
)

// Adapter enums: one per kind, declared here, implemented by the role packages (EP-12).
type (
	// KeyProvider supplies the key-encryption key.
	KeyProvider string
	// ServiceHost is how the process is run by its operating system.
	ServiceHost string
	// Kerberos is the GSSAPI client implementation.
	Kerberos string
)

// Adapter values named by blueprint §3.3. More are added with the adapter that implements them.
const (
	KeyDPAPING KeyProvider = "dpapi-ng"
	KeyTPM2    KeyProvider = "tpm2"
	KeyKMS     KeyProvider = "kms"

	HostWinSvc ServiceHost = "winsvc"
	HostOCI    ServiceHost = "oci"

	KerberosSSPI Kerberos = "sspi"
	KerberosKrb5 Kerberos = "krb5"
)

// Process is one binary and the roles linked into it.
type Process struct {
	Binary    string
	Roles     []Role
	Providers []Provider // for a connector role
}

// Adapters selects one implementation per adapter kind.
type Adapters struct {
	// KeyProviders lists every key provider the profile supports; the operator picks one at install.
	KeyProviders []KeyProvider
	ServiceHost  ServiceHost
	Kerberos     Kerberos
}

// Exception is a declared asymmetry between profiles. It cites the ratified ADR that allows it.
type Exception struct {
	What string
	ADR  string
}

// Manifest is a deployment profile as data.
type Manifest struct {
	Name         string
	Processes    []Process
	Adapters     Adapters
	Capabilities []capability.ID
	Exceptions   []Exception
}
