package profile

import "github.com/skenzeriq/activediq/internal/platform/capability"

// Windows is the MSI profile (blueprint §3.3): a Windows service running the server and the
// embedded connector.
func Windows() Manifest {
	return Manifest{
		Name: "windows",
		Processes: []Process{
			{Binary: "server", Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderAD, ProviderEntra}},
		},
		Adapters: Adapters{
			KeyProviders: []KeyProvider{KeyDPAPING, KeyTPM2},
			ServiceHost:  HostWinSvc,
			Kerberos:     KerberosSSPI,
		},
		Capabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},
	}
}

// LinuxOCI is the container-image profile: the same roles as Windows with the krb5 adapter.
func LinuxOCI() Manifest {
	return Manifest{
		Name: "linux-oci",
		Processes: []Process{
			{Binary: "server", Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderAD, ProviderEntra}},
		},
		Adapters: Adapters{
			KeyProviders: []KeyProvider{KeyTPM2, KeyKMS},
			ServiceHost:  HostOCI,
			Kerberos:     KerberosKrb5,
		},
		Capabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},
	}
}

// SaaS is the hosted-cell profile. It is built in CI only and is not shipped (ADR-0002). Its
// embedded connector serves Entra only; AD is reached through a customer-site connector.
func SaaS() Manifest {
	return Manifest{
		Name: "saas",
		Processes: []Process{
			{Binary: "server", Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderEntra}},
		},
		Adapters: Adapters{
			KeyProviders: []KeyProvider{KeyKMS},
			ServiceHost:  HostOCI,
			Kerberos:     KerberosKrb5,
		},
		Capabilities: []capability.ID{capability.DirectoryEntra, capability.TenantProvisioning},
	}
}
