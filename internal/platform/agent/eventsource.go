package agent

import (
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/agenthost/hostapi"
)

// channelPath maps the closed channel enum to the Windows channel path. Anything else is refused.
func channelPath(ch hostapi.Channel) (string, error) {
	switch ch {
	case hostapi.ChannelSecurity:
		return "Security", nil
	case hostapi.ChannelDirectoryService:
		return "Directory Service", nil
	}
	return "", hostapi.ErrBadChannel
}

// eventQuery builds the XPath filter from typed numbers only: nothing from a message, a document or a
// module-supplied string is interpolated (record id uint64, event ids uint16).
func eventQuery(after uint64, ids []uint16) string {
	var b strings.Builder
	b.WriteString("*[System[(EventRecordID>")
	b.WriteString(strconv.FormatUint(after, 10))
	b.WriteString(")")
	if len(ids) > 0 {
		b.WriteString(" and (")
		for i, id := range ids {
			if i > 0 {
				b.WriteString(" or ")
			}
			b.WriteString("EventID=")
			b.WriteString(strconv.FormatUint(uint64(id), 10))
		}
		b.WriteString(")")
	}
	b.WriteString("]]")
	return b.String()
}
