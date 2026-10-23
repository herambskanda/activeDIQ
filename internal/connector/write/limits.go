package write

import "time"

// Build-time limits of the connector (contract §8.2, §8.3 F3). They are constants on purpose: no
// configuration file, registry value, environment variable, flag, Describe field or request field
// can set or raise them (CC-WRITE-22). Changing one is a code change that ships as a contract
// revision. The gate and the freshness rule read these and nothing else.
const (
	// MaxVerificationAge is the daily scheduled VerifyConnection (DM-24.I7) plus a margin.
	MaxVerificationAge = 26 * time.Hour
	// MaxStatementAge is how old a CorrelationStatement's computed_at may be.
	MaxStatementAge = 15 * time.Minute
	// MaxFutureSkew is how far in the future of the connector's clock computed_at may be.
	MaxFutureSkew = 5 * time.Minute
)
