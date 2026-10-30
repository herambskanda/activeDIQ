package agent

import (
	"errors"
	"math"
	"testing"

	"github.com/skenzeriq/activediq/internal/agenthost/hostapi"
)

func TestEventQueryExact(t *testing.T) {
	cases := []struct {
		name  string
		after uint64
		ids   []uint16
		want  string
	}{
		{"zero no ids", 0, nil, "*[System[(EventRecordID>0)]]"},
		{"empty ids", 0, []uint16{}, "*[System[(EventRecordID>0)]]"},
		{"after and several ids", 42, []uint16{4624, 4625, 4768},
			"*[System[(EventRecordID>42) and (EventID=4624 or EventID=4625 or EventID=4768)]]"},
		{"maxima", math.MaxUint64, []uint16{math.MaxUint16},
			"*[System[(EventRecordID>18446744073709551615) and (EventID=65535)]]"},
	}
	for _, c := range cases {
		if got := eventQuery(c.after, c.ids); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestChannelPath(t *testing.T) {
	for ch, want := range map[hostapi.Channel]string{
		hostapi.ChannelSecurity:         "Security",
		hostapi.ChannelDirectoryService: "Directory Service",
	} {
		if got, err := channelPath(ch); err != nil || got != want {
			t.Errorf("channel %d: got %q, %v", ch, got, err)
		}
	}
	for _, ch := range []hostapi.Channel{0, 3, 255} {
		if p, err := channelPath(ch); !errors.Is(err, hostapi.ErrBadChannel) || p != "" {
			t.Errorf("channel %d: got %q, %v; want ErrBadChannel", ch, p, err)
		}
	}
}
