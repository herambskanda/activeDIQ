package run

import (
	"errors"
	"regexp"
	"time"
	_ "time/tzdata" // the zone database travels with the binary: a Windows or minimal host has none
)

// ErrBadTimeZone is a time zone the runner named that is not an IANA zone name we know. 400 time_zone_unknown.
var ErrBadTimeZone = errors.New("run: unknown time zone")

var zoneName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)

// ValidZone reports whether name is a loadable IANA zone name (not "Local", which names the server's zone).
func ValidZone(name string) bool {
	if len(name) > 64 || !zoneName.MatchString(name) || name == "Local" {
		return false
	}
	_, err := time.LoadLocation(name)
	return err == nil
}

// Location is the zone the run's PDF and HTML exports show Time cells in; UTC when none was recorded or the
// recorded name no longer loads.
func (r Run) Location() *time.Location {
	if r.Zone == "" {
		return time.UTC
	}
	if loc, err := time.LoadLocation(r.Zone); err == nil {
		return loc
	}
	return time.UTC
}
