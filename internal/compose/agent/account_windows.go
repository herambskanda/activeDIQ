//go:build windows

package agent

import "github.com/skenzeriq/activediq/internal/platform/fleet/dial"

// ServiceAccount is the virtual account the MSI runs the service as (ADR-0006 decision 1; the same
// constant as cmd/agentsetup). `agent enroll` is run by an administrator, so the state is written for
// this account, not for that administrator: the service refuses state that names anyone else
// (T-1249).
const ServiceAccount = `NT SERVICE\activeDIQAgent`

func enrolOptions() []dial.Option { return []dial.Option{dial.ForAccount(ServiceAccount)} }
