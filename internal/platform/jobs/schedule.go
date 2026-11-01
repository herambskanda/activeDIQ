package jobs

// DM-44 Schedule: the recurrence arithmetic every module shares, so none of them reinvents clocks.
//
// A Schedule is a value: a recurrence, an IANA time zone and, for the kinds that need one, an anchor. It
// computes occurrences and nothing else. The owner (an automation policy, a report schedule, a cleanup
// policy) stores the schedule and its next_run_at in UTC (X8), and on each tick asks Schedule.Check what
// is due. Whoever persists the result must record the new NextRunAt in the same transaction that enqueues
// the job, and should enqueue with Decision.UniqueKey so that a crash between the two never fires twice.
//
// Rules (spec reports-2a §8.4, DM-44 I1 and I2):
//
//   - The recurrence is evaluated in the schedule's zone; instants are UTC.
//   - Hourly, and a custom repeat in hours, step in elapsed time, so DST never shifts or repeats them.
//   - Daily, weekly, monthly and a custom repeat in days, weeks or months keep the local wall-clock time.
//     A local time that DST skips (spring forward) runs at the next valid instant, which is the moment
//     the clock jumps. A local time that DST repeats (fall back) runs once, at its first occurrence.
//   - A monthly day beyond the month's end (the 31st in April) runs on the month's last day.
//   - The minimum interval is one hour. A shorter one is refused with ErrIntervalBelowFloor.
//   - After downtime, every occurrence missed while the owner was away is one firing: the next
//     occurrence is the first one after now, never a burst (Check).
//
// Not here: the stored table and the tick loop that reads it, and report-specific limits such as the
// per-DC daily rule (B11).

import (
	"fmt"
	"strings"
	"time"
	_ "time/tzdata" // zone data for hosts without one (Windows servers): schedules must not depend on the OS.
)

// Schedule errors. Each wraps ErrInvalid, so errors.Is(err, ErrInvalid) matches all of them.
var (
	// ErrIntervalBelowFloor is returned when a recurrence repeats more often than the one-hour minimum.
	ErrIntervalBelowFloor = fmt.Errorf("%w: a schedule interval is at least one hour", ErrInvalid)
	// ErrUnknownZone is returned when the zone is not an IANA zone name the host's data knows.
	ErrUnknownZone = fmt.Errorf("%w: unknown IANA time zone", ErrInvalid)
)

// MinInterval is the shortest interval between two occurrences (spec §8.4).
const MinInterval = time.Hour

// Recurrence is the shape of a repeat (DM-44 `recurrence`).
type Recurrence string

const (
	Hourly  Recurrence = "hourly"  // every Every hours from Start
	Daily   Recurrence = "daily"   // every day at Hour:Minute
	Weekly  Recurrence = "weekly"  // on Weekdays at Hour:Minute
	Monthly Recurrence = "monthly" // on DayOfMonth (or the last day) at Hour:Minute
	Custom  Recurrence = "custom"  // from Start, every Every of Unit
)

// Unit is the unit of a custom repeat.
type Unit string

const (
	UnitHours  Unit = "hours"
	UnitDays   Unit = "days"
	UnitWeeks  Unit = "weeks"
	UnitMonths Unit = "months"
)

// LastDay as a DayOfMonth means the last day of each month.
const LastDay = -1

// Schedule is one recurrence in one time zone. Only the fields of its Recurrence may be set; Validate refuses
// the others, so a stored schedule says exactly what it does.
type Schedule struct {
	Recurrence Recurrence `json:"recurrence"`
	Zone       string     `json:"time_zone"` // IANA name, such as "Europe/Berlin"; "UTC" is allowed

	// Hour and Minute are the local time of day (Daily, Weekly, Monthly).
	Hour   int `json:"hour,omitempty"`
	Minute int `json:"minute,omitempty"`
	// Weekdays are the days of a Weekly schedule.
	Weekdays []time.Weekday `json:"weekdays,omitempty"`
	// DayOfMonth is 1..31 or LastDay (Monthly).
	DayOfMonth int `json:"day_of_month,omitempty"`
	// Start is the first occurrence and the anchor of Hourly and Custom. Its local time of day in Zone is
	// the time of day of a custom repeat in days, weeks or months.
	Start time.Time `json:"start,omitzero"`
	// Every is the repeat count of Hourly (hours) and Custom (Unit).
	Every int  `json:"every,omitempty"`
	Unit  Unit `json:"unit,omitempty"`
}

// fields a Recurrence uses; any other field that is set is refused.
const (
	fTime = 1 << iota // Hour, Minute
	fWeekdays
	fDay
	fStart
	fEvery
	fUnit
)

var kindFields = map[Recurrence]int{
	Hourly:  fStart | fEvery,
	Daily:   fTime,
	Weekly:  fTime | fWeekdays,
	Monthly: fTime | fDay,
	Custom:  fStart | fEvery | fUnit,
}

var fieldNames = [...]string{"hour/minute", "weekdays", "day_of_month", "start", "every", "unit"}

func (s Schedule) setFields() int {
	var set int
	for bit, on := range [...]bool{s.Hour != 0 || s.Minute != 0, len(s.Weekdays) > 0, s.DayOfMonth != 0,
		!s.Start.IsZero(), s.Every != 0, s.Unit != ""} {
		if on {
			set |= 1 << bit
		}
	}
	return set
}

// Validate refuses a schedule that cannot be evaluated, with a typed error.
func (s Schedule) Validate() error {
	if _, err := s.location(); err != nil {
		return err
	}
	used, ok := kindFields[s.Recurrence]
	if !ok {
		return invalid("unknown recurrence kind %q", s.Recurrence)
	}
	if stray := s.setFields() &^ used; stray != 0 {
		var names []string
		for bit, n := range fieldNames {
			if stray&(1<<bit) != 0 {
				names = append(names, n)
			}
		}
		return invalid("%s does not use %s", s.Recurrence, strings.Join(names, ", "))
	}
	if used&fTime != 0 && (s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59) {
		return invalid("time of day %02d:%02d is outside 00:00..23:59", s.Hour, s.Minute)
	}
	if used&fStart != 0 && s.Start.IsZero() {
		return invalid("%s needs a start", s.Recurrence)
	}
	if used&fEvery != 0 && s.Every < 1 {
		return fmt.Errorf("%w: %s repeats every %d", ErrIntervalBelowFloor, s.Recurrence, s.Every)
	}
	switch s.Recurrence {
	case Weekly:
		if len(s.Weekdays) == 0 {
			return invalid("weekly needs at least one weekday")
		}
		seen := map[time.Weekday]bool{}
		for _, d := range s.Weekdays {
			if d < time.Sunday || d > time.Saturday || seen[d] {
				return invalid("weekdays must be distinct days Sunday..Saturday")
			}
			seen[d] = true
		}
	case Monthly:
		if s.DayOfMonth != LastDay && (s.DayOfMonth < 1 || s.DayOfMonth > 31) {
			return invalid("day of month %d is neither 1..31 nor the last day", s.DayOfMonth)
		}
	case Custom:
		switch s.Unit {
		case UnitHours, UnitDays, UnitWeeks, UnitMonths:
		default:
			return invalid("custom repeat unit %q is not hours, days, weeks or months", s.Unit)
		}
	}
	return nil
}

func (s Schedule) location() (*time.Location, error) {
	// LoadLocation("") is UTC and "Local" is the host's zone; neither is an IANA name a schedule can keep.
	if s.Zone == "" || s.Zone == "Local" || len(s.Zone) > 64 {
		return nil, fmt.Errorf("%w: %q", ErrUnknownZone, s.Zone)
	}
	loc, err := time.LoadLocation(s.Zone)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownZone, s.Zone)
	}
	return loc, nil
}

// searchDays bounds the day-by-day scan of the wall-clock kinds; the longest gap is a monthly schedule
// on the 31st, which is clamped and so never exceeds 31 days.
const searchDays = 40

// Next returns the first occurrence strictly after t, in UTC.
func (s Schedule) Next(t time.Time) (time.Time, error) {
	if err := s.Validate(); err != nil {
		return time.Time{}, err
	}
	loc, _ := s.location()
	switch s.Recurrence {
	case Hourly:
		return s.nextElapsed(t, time.Duration(s.Every)*time.Hour), nil
	case Custom:
		if s.Unit == UnitHours {
			return s.nextElapsed(t, time.Duration(s.Every)*time.Hour), nil
		}
		return s.nextCustomWall(t, loc), nil
	}
	// Daily, weekly, monthly: scan local dates from the day before t, so a gap-shifted or overlapped
	// occurrence of the previous day is still seen.
	// The scan walks calendar dates (as UTC dates), never local instants: adding days to a local instant
	// would step over a date the zone skipped outright.
	y0, m0, d0 := t.In(loc).Date()
	for i := -1; i < searchDays; i++ {
		y, m, d := time.Date(y0, m0, d0+i, 12, 0, 0, 0, time.UTC).Date()
		if !s.matchesDate(y, m, d, loc) {
			continue
		}
		if at := resolve(y, m, d, s.Hour, s.Minute, loc); at.After(t) {
			return at.UTC(), nil
		}
	}
	return time.Time{}, invalid("no occurrence within %d days of %s", searchDays, t.UTC().Format(time.RFC3339))
}

func (s Schedule) matchesDate(y int, m time.Month, d int, loc *time.Location) bool {
	switch s.Recurrence {
	case Weekly:
		wd := time.Date(y, m, d, 12, 0, 0, 0, loc).Weekday()
		for _, w := range s.Weekdays {
			if w == wd {
				return true
			}
		}
		return false
	case Monthly:
		return d == monthDay(y, m, s.DayOfMonth)
	}
	return true
}

// monthDay is the day of the month a monthly occurrence falls on: the requested day, or the last day when
// the month is shorter (or LastDay was asked for).
func monthDay(y int, m time.Month, want int) int {
	last := time.Date(y, m+1, 0, 12, 0, 0, 0, time.UTC).Day()
	if want == LastDay || want > last {
		return last
	}
	return want
}

// nextElapsed steps in elapsed time from Start: Start, Start+step, Start+2*step…
func (s Schedule) nextElapsed(t time.Time, step time.Duration) time.Time {
	start := s.Start.UTC()
	if t.Before(start) {
		return start
	}
	return start.Add((t.Sub(start)/step + 1) * step)
}

// nextCustomWall is a custom repeat in days, weeks or months: the n-th occurrence is Start's local date
// plus n units at Start's local time of day, computed from Start each time so month clamping never drifts.
func (s Schedule) nextCustomWall(t time.Time, loc *time.Location) time.Time {
	start := s.Start.In(loc)
	if t.Before(start) {
		return start.UTC()
	}
	// Estimate n from the elapsed time using the LONGEST a unit can last (25h for a day, a week plus an hour,
	// 31 days for a month). n units then span at most n*Every*perUnit, so the estimated occurrence is never
	// after t and the estimate never overshoots; stepping forward finds the first occurrence after t. (Using
	// the shortest unit instead would over-count and skip real occurrences.)
	var perUnit time.Duration
	switch s.Unit {
	case UnitDays:
		perUnit = 25 * time.Hour
	case UnitWeeks:
		perUnit = 7*24*time.Hour + time.Hour
	default:
		perUnit = 31 * 24 * time.Hour
	}
	n := max(int(t.Sub(start)/perUnit/time.Duration(s.Every)), 1)
	// Belt and braces: occurrences increase with n, so step back while the previous one is already after t.
	for n > 1 && s.customOccurrence(start, n-1, loc).After(t) {
		n--
	}
	for ; ; n++ {
		if at := s.customOccurrence(start, n, loc); at.After(t) {
			return at.UTC()
		}
	}
}

func (s Schedule) customOccurrence(start time.Time, n int, loc *time.Location) time.Time {
	y, m, d := start.Date()
	k := n * s.Every
	switch s.Unit {
	case UnitDays:
		d += k
	case UnitWeeks:
		d += 7 * k
	case UnitMonths:
		// Month arithmetic from the first of the month, then clamp to the anchor day.
		first := time.Date(y, m+time.Month(k), 1, 12, 0, 0, 0, time.UTC)
		y, m, d = first.Year(), first.Month(), monthDay(first.Year(), first.Month(), d)
	}
	date := time.Date(y, m, d, 12, 0, 0, 0, time.UTC)
	return resolve(date.Year(), date.Month(), date.Day(), start.Hour(), start.Minute(), loc)
}

// resolve returns the instant of a local wall-clock time in loc under the DST rules above: the first
// occurrence when the time repeats, the moment of the clock jump when the time does not exist.
func resolve(y int, m time.Month, d, hour, minute int, loc *time.Location) time.Time {
	wall := time.Date(y, m, d, hour, minute, 0, 0, time.UTC).Unix() // the wall time read as if it were UTC
	offsetAt := func(sec int64) int {
		_, off := time.Unix(sec, 0).In(loc).Zone()
		return off
	}
	// The offset in force a day before and a day after bounds the offsets this wall time can have.
	before, after := offsetAt(wall-86400), offsetAt(wall+86400)
	var best int64
	found := false
	for _, off := range [...]int{before, after} {
		c := wall - int64(off)
		if offsetAt(c) == off && (!found || c < best) {
			best, found = c, true
		}
	}
	if found {
		return time.Unix(best, 0).UTC()
	}
	// The time falls in a gap. The earlier candidate lies in the zone period before the jump, which ends
	// at the jump.
	earlier := wall - int64(max(before, after))
	_, end := time.Unix(earlier, 0).In(loc).ZoneBounds()
	return end.UTC()
}

// WallClock is the schedule evaluator's only source of the current time, so tests drive it.
type WallClock interface {
	Now() time.Time
}

// SystemClock is the real clock.
type SystemClock struct{}

// Now returns the current time.
func (SystemClock) Now() time.Time { return time.Now() }

// Decision is the outcome of Check for one schedule.
type Decision struct {
	// Due is true when the schedule must fire now. It fires once, whatever the number of occurrences that
	// passed while nobody was checking.
	Due bool
	// ScheduledFor is the occurrence that fires (the stored next_run_at); zero when not Due.
	ScheduledFor time.Time
	// Next is the next_run_at to store: the first occurrence after now when Due, nextRunAt unchanged
	// otherwise.
	Next time.Time
}

// UniqueKey is a Job.UniqueKey for the firing, so enqueueing it twice (a retry after a crash between the
// enqueue and the store of Next) leaves one job. id is the owner's schedule identifier.
func (d Decision) UniqueKey(id string) string {
	return "schedule:" + id + ":" + d.ScheduledFor.UTC().Format(time.RFC3339)
}

// First is the next_run_at of a schedule that is created or resumed now.
func (s Schedule) First(c WallClock) (time.Time, error) { return s.Next(c.Now()) }

// Check decides what is due at the clock's now, given the stored nextRunAt. Occurrences missed while the
// owner was down are not replayed: one firing is due, and Next is the first occurrence after now (DM-44
// I2).
func (s Schedule) Check(c WallClock, nextRunAt time.Time) (Decision, error) {
	if nextRunAt.IsZero() {
		return Decision{}, invalid("next run time is not set")
	}
	now := c.Now()
	if now.Before(nextRunAt) {
		if err := s.Validate(); err != nil {
			return Decision{}, err
		}
		return Decision{Next: nextRunAt.UTC()}, nil
	}
	next, err := s.Next(now)
	if err != nil {
		return Decision{}, err
	}
	return Decision{Due: true, ScheduledFor: nextRunAt.UTC(), Next: next}, nil
}
