package addc

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
)

// catalogue is the compiled-in set of event IDs a signed policy may select per channel. A policy
// naming an ID outside it is refused whole (contract §3): the server cannot widen what the agent will
// read, only choose within it. IDs are the Windows Security auditing events the product's audit
// reports need; each is documented at
// https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-<id>.
var catalogue = map[agentpolicy.Channel]map[uint32]struct{}{
	agentpolicy.ChannelSecurity: setOf(
		1102,                         // the audit log was cleared (reported as itself, always subscribed)
		4624, 4625, 4634, 4647, 4648, // logon / logoff
		4662,                                     // an operation was performed on an object (DS access)
		4720, 4722, 4723, 4724, 4725, 4726, 4738, // user account lifecycle and password change/reset
		4740, 4767, // lockout, unlock
		4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, // groups
		4768, 4769, 4771, 4776, // Kerberos TGT / service ticket / pre-auth failure, NTLM validation
		5136, 5137, 5138, 5139, 5141, // directory service object modified / created / undeleted / moved / deleted
	),
	// Directory Service log. 2889 (unsigned LDAP binds) and 1644 (expensive searches) are documented by
	// Microsoft but their exact channel placement on every supported Server version is [UNVERIFIED — lab].
	agentpolicy.ChannelDirectoryService: setOf(1644, 2886, 2887, 2888, 2889),
}

func setOf(ids ...uint32) map[uint32]struct{} {
	m := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

func checkCatalogue(ev agentpolicy.EventRules) error {
	for _, id := range ev.EventIDs {
		ok := false
		for _, ch := range ev.Channels {
			if _, in := catalogue[ch][id]; in {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("event id %d is not in the compiled-in catalogue for the selected channels", id)
		}
	}
	return nil
}

func channelName(c agentpolicy.Channel) string {
	if c == agentpolicy.ChannelDirectoryService {
		return "directory_service"
	}
	return "security"
}

// logName is the Windows channel path wevtapi subscribes to.
func logName(c agentpolicy.Channel) string {
	if c == agentpolicy.ChannelDirectoryService {
		return "Directory Service"
	}
	return "Security"
}

// alwaysIDs are subscribed on a channel whatever the policy selects: losing them hides tampering.
func alwaysIDs(c agentpolicy.Channel) []uint32 {
	if c == agentpolicy.ChannelSecurity {
		return []uint32{1102}
	}
	return nil
}
