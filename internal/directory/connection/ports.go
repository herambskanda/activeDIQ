package connection

import "context"

// ConnectorClient is the port through which the registry's callers reach a directory to answer the
// questions a connection's lifecycle depends on. It is declared here, in the registry, so that the
// verification run can depend on it without importing the transport client (`client` imports
// `connection`, never the reverse; blueprint §5.2). `directory/client` implements it.
//
// It is deliberately one method: the V5 identity read that feeds SetDirectoryIdentity. The rest of
// verification (V1–V9, rights, override) is another ticket and extends the port when it lands.
type ConnectorClient interface {
	// ReadIdentity reads the directory identity of the connection's directory: the objectGUID of
	// the forest root domain NC (AD) or the tenant ID (Entra). It never returns secret material.
	ReadIdentity(ctx context.Context, c Connection) (DirectoryIdentity, error)
}
