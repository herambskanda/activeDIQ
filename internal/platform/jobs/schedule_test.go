package jobs

import (
	"errors"
	"testing"
	"time"
)

// manualWallClock is the injected clock.
type manualWallClock struct{ now time.Time }

func (f *manualWallClock) Now() time.Time { return f.now }

func utc(y int, m time.Month, d, h, mi int) time.Time {
	return time.Date(y, m, d, h, mi, 0, 0, time.UTC)
}

func mustNext(t *testing.T, s Schedule, after time.Time) time.Time {
	t.Helper()
	got, err := s.Next(after)
	if err != nil {
		t.Fatalf("Next(%s): %v", after, err)
	}
	return got
}

// series returns n consecutive occurrences after t.
func series(t *testing.T, s Schedule, after time.Time, n int) []time.Time {
	t.Helper()
	var out []time.Time
	for range n {
		after = mustNext(t, s, after)
		out = append(out, after)
	}
	return out
}

func eq(t *testing.T, label string, got []time.Time, want ...time.Time) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d times %v, want %d", label, len(got), got, len(want))
	}
	for i := range want {
		if !got[i].Equal(want[i]) {
			t.Errorf("%s[%d] = %s, want %s", label, i, got[i].UTC().Format(time.RFC3339), want[i].UTC().Format(time.RFC3339))
		}
	}
}

// AC-37: a monthly schedule at 08:00 local follows the zone across both DST changes.
func TestMonthlyAt0800FollowsDST(t *testing.T) {
	s := Schedule{Recurrence: Monthly, Zone: "America/New_York", DayOfMonth: 1, Hour: 8}
	// 2026: EST until Mar 8 02:00, EDT until Nov 1 02:00.
	got := series(t, s, utc(2026, 1, 15, 0, 0), 12)
	eq(t, "monthly", got,
		utc(2026, 2, 1, 13, 0),  // EST, UTC-5
		utc(2026, 3, 1, 13, 0),  // EST: the change is a week later
		utc(2026, 4, 1, 12, 0),  // EDT, UTC-4: 08:00 local is now 12:00 UTC
		utc(2026, 5, 1, 12, 0),  //
		utc(2026, 6, 1, 12, 0),  //
		utc(2026, 7, 1, 12, 0),  //
		utc(2026, 8, 1, 12, 0),  //
		utc(2026, 9, 1, 12, 0),  //
		utc(2026, 10, 1, 12, 0), //
		utc(2026, 11, 1, 13, 0), // back on EST: the change is at 02:00 that morning
		utc(2026, 12, 1, 13, 0), //
		utc(2027, 1, 1, 13, 0),  //
	)
}

func TestMonthlyOnTheDayOfTheChange(t *testing.T) {
	// A monthly 02:30 on Mar 8 2026: that local time does not exist in New York. It runs at the next valid
	// instant, the moment the clock jumps (02:00 EST = 07:00 UTC, which then reads 03:00 EDT).
	s := Schedule{Recurrence: Monthly, Zone: "America/New_York", DayOfMonth: 8, Hour: 2, Minute: 30}
	got := mustNext(t, s, utc(2026, 3, 1, 0, 0))
	if want := utc(2026, 3, 8, 7, 0); !got.Equal(want) {
		t.Errorf("skipped hour: got %s, want %s", got, want)
	}
}

func TestDailySkippedHourRunsAtTheNextValidInstant(t *testing.T) {
	s := Schedule{Recurrence: Daily, Zone: "America/New_York", Hour: 2, Minute: 30}
	got := series(t, s, utc(2026, 3, 7, 12, 0), 3)
	eq(t, "spring forward", got,
		utc(2026, 3, 8, 7, 0),  // 02:30 does not exist: runs at 03:00 EDT = 07:00 UTC
		utc(2026, 3, 9, 6, 30), // back to 02:30 EDT = 06:30 UTC
		utc(2026, 3, 10, 6, 30),
	)
}

func TestDailyRepeatedHourRunsOnce(t *testing.T) {
	s := Schedule{Recurrence: Daily, Zone: "America/New_York", Hour: 1, Minute: 30}
	got := series(t, s, utc(2026, 10, 30, 12, 0), 4)
	eq(t, "fall back", got,
		utc(2026, 10, 31, 5, 30), // 01:30 EDT
		utc(2026, 11, 1, 5, 30),  // 01:30 EDT, the first of the two 01:30s; the second (06:30 UTC) never fires
		utc(2026, 11, 2, 6, 30),  // 01:30 EST
		utc(2026, 11, 3, 6, 30),
	)
}

func TestDailyAtMidnightAndSouthernHemisphere(t *testing.T) {
	// Sydney springs forward on Oct 4 2026 at 02:00 (AEST UTC+10 to AEDT UTC+11).
	s := Schedule{Recurrence: Daily, Zone: "Australia/Sydney", Hour: 2, Minute: 15}
	got := series(t, s, utc(2026, 10, 3, 0, 0), 2)
	eq(t, "sydney", got,
		utc(2026, 10, 3, 16, 0), // Oct 4 02:15 does not exist; the jump is 02:00 AEST = 16:00 UTC Oct 3
		utc(2026, 10, 4, 15, 15),
	)
}

func TestHalfHourDSTZone(t *testing.T) {
	// Lord Howe shifts by 30 minutes: Apr 5 2026 02:00 local falls back to 01:30.
	s := Schedule{Recurrence: Daily, Zone: "Australia/Lord_Howe", Hour: 1, Minute: 45}
	got := series(t, s, utc(2026, 4, 3, 0, 0), 3)
	for i := 1; i < len(got); i++ {
		if !got[i].After(got[i-1]) {
			t.Fatalf("occurrences are not increasing: %v", got)
		}
	}
	// 01:45 repeats on Apr 5; exactly one occurrence falls on that local date.
	loc, _ := time.LoadLocation("Australia/Lord_Howe")
	n := 0
	for _, g := range got {
		if y, m, d := g.In(loc).Date(); y == 2026 && m == time.April && d == 5 {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d occurrences on the repeated day, want 1: %v", n, got)
	}
}

func TestWholeDaySkipped(t *testing.T) {
	// Samoa skipped Dec 30 2011 entirely (UTC-10 to UTC+14). A daily 10:00 for that date runs at the jump.
	s := Schedule{Recurrence: Daily, Zone: "Pacific/Apia", Hour: 10}
	got := series(t, s, utc(2011, 12, 29, 21, 0), 2) // Dec 29 10:00 local (UTC-10) = 20:00 UTC, so after is past it
	if want := utc(2011, 12, 30, 10, 0); !got[0].Equal(want) {
		t.Errorf("skipped day: got %s, want %s", got[0], want)
	}
	if !got[1].After(got[0]) {
		t.Errorf("not increasing: %v", got)
	}
}

func TestWeeklyDays(t *testing.T) {
	s := Schedule{Recurrence: Weekly, Zone: "Europe/Berlin", Weekdays: []time.Weekday{time.Monday, time.Thursday}, Hour: 8}
	got := series(t, s, utc(2026, 3, 22, 12, 0), 4) // Sunday before the Mar 29 change
	eq(t, "weekly", got,
		utc(2026, 3, 23, 7, 0), // Mon CET, UTC+1
		utc(2026, 3, 26, 7, 0), // Thu CET
		utc(2026, 3, 30, 6, 0), // Mon CEST, UTC+2
		utc(2026, 4, 2, 6, 0),
	)
}

func TestMonthlyLastDayAndClamp(t *testing.T) {
	last := Schedule{Recurrence: Monthly, Zone: "UTC", DayOfMonth: LastDay, Hour: 23, Minute: 30}
	eq(t, "last day", series(t, last, utc(2027, 1, 31, 23, 30), 3),
		utc(2027, 2, 28, 23, 30), utc(2027, 3, 31, 23, 30), utc(2027, 4, 30, 23, 30))
	leap := series(t, last, utc(2028, 1, 31, 23, 30), 1)
	eq(t, "leap", leap, utc(2028, 2, 29, 23, 30))

	d31 := Schedule{Recurrence: Monthly, Zone: "UTC", DayOfMonth: 31, Hour: 8}
	eq(t, "the 31st clamps", series(t, d31, utc(2026, 12, 31, 8, 0), 3),
		utc(2027, 1, 31, 8, 0), utc(2027, 2, 28, 8, 0), utc(2027, 3, 31, 8, 0))
}

func TestHourlySteps(t *testing.T) {
	start := utc(2026, 3, 7, 10, 20) // New York, EST
	s := Schedule{Recurrence: Hourly, Zone: "America/New_York", Start: start, Every: 6}
	// Elapsed-time steps: the hour lost on Mar 8 02:00 is not compensated, nothing is skipped or repeated.
	got := series(t, s, utc(2026, 3, 8, 0, 0), 3)
	eq(t, "hourly", got, utc(2026, 3, 8, 4, 20), utc(2026, 3, 8, 10, 20), utc(2026, 3, 8, 16, 20))

	eq(t, "before start", []time.Time{mustNext(t, s, start.Add(-time.Hour))}, start)
	eq(t, "exactly on an occurrence is excluded", []time.Time{mustNext(t, s, start)}, start.Add(6*time.Hour))
	every := Schedule{Recurrence: Hourly, Zone: "UTC", Start: start, Every: 1}
	eq(t, "every hour", series(t, every, start.Add(5*time.Minute), 2), utc(2026, 3, 7, 11, 20), utc(2026, 3, 7, 12, 20))
}

func TestCustomRepeats(t *testing.T) {
	// Start Mar 1 2026 09:15 New York; every 2 weeks keeps 09:15 local across the Mar 8 change.
	loc, _ := time.LoadLocation("America/New_York")
	start := time.Date(2026, 3, 1, 9, 15, 0, 0, loc)
	weeks := Schedule{Recurrence: Custom, Zone: "America/New_York", Start: start, Every: 2, Unit: UnitWeeks}
	eq(t, "two weeks", series(t, weeks, start.Add(-time.Minute), 3),
		utc(2026, 3, 1, 14, 15), // EST
		utc(2026, 3, 15, 13, 15),
		utc(2026, 3, 29, 13, 15))

	days := Schedule{Recurrence: Custom, Zone: "America/New_York", Start: start, Every: 3, Unit: UnitDays}
	eq(t, "three days", series(t, days, start, 3),
		utc(2026, 3, 4, 14, 15), utc(2026, 3, 7, 14, 15), utc(2026, 3, 10, 13, 15))

	// Months from Jan 31 clamp without drifting: Feb 28, Mar 31 (not Mar 28).
	jan31 := time.Date(2027, 1, 31, 6, 0, 0, 0, time.UTC)
	months := Schedule{Recurrence: Custom, Zone: "UTC", Start: jan31, Every: 1, Unit: UnitMonths}
	eq(t, "months", series(t, months, jan31, 3), utc(2027, 2, 28, 6, 0), utc(2027, 3, 31, 6, 0), utc(2027, 4, 30, 6, 0))

	hours := Schedule{Recurrence: Custom, Zone: "America/New_York", Start: start, Every: 36, Unit: UnitHours}
	eq(t, "36 hours", series(t, hours, start, 2), utc(2026, 3, 3, 2, 15), utc(2026, 3, 4, 14, 15))

	// A long absence still lands on the right occurrence (the estimate never overshoots).
	far := mustNext(t, weeks, utc(2036, 6, 1, 0, 0))
	if !far.After(utc(2036, 6, 1, 0, 0)) || far.Sub(utc(2036, 6, 1, 0, 0)) > 14*24*time.Hour {
		t.Errorf("far future occurrence %s is not the first after the instant", far)
	}
}

// DM-44.I2: the server was down across a due time; on restart the schedule fires exactly once.
func TestMissedRunFiresOnce(t *testing.T) {
	s := Schedule{Recurrence: Daily, Zone: "Europe/Berlin", Hour: 8}
	clock := &manualWallClock{now: utc(2026, 5, 1, 0, 0)}
	next, err := s.First(clock)
	if err != nil {
		t.Fatal(err)
	}
	if want := utc(2026, 5, 1, 6, 0); !next.Equal(want) {
		t.Fatalf("first = %s, want %s", next, want)
	}

	// Not due yet: nothing happens and next_run_at is unchanged.
	clock.now = utc(2026, 5, 1, 5, 59)
	d, err := s.Check(clock, next)
	if err != nil || d.Due || !d.Next.Equal(next) {
		t.Fatalf("early check = %+v, %v", d, err)
	}

	// Down from 05:59 on May 1 until the morning of May 4: three occurrences passed.
	clock.now = utc(2026, 5, 4, 9, 30)
	d, err = s.Check(clock, next)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Due || !d.ScheduledFor.Equal(next) {
		t.Fatalf("after downtime = %+v, want one due firing for %s", d, next)
	}
	if want := utc(2026, 5, 5, 6, 0); !d.Next.Equal(want) {
		t.Errorf("next after downtime = %s, want %s (no replay of May 2, 3 or 4)", d.Next, want)
	}

	// Checking again with the stored Next fires nothing: exactly once.
	again, err := s.Check(clock, d.Next)
	if err != nil || again.Due {
		t.Errorf("second check = %+v, %v; want not due", again, err)
	}
}

func TestCheckOnTheInstantFiresOnce(t *testing.T) {
	s := Schedule{Recurrence: Hourly, Zone: "UTC", Start: utc(2026, 1, 1, 0, 0), Every: 1}
	due := utc(2026, 1, 1, 5, 0)
	d, err := s.Check(&manualWallClock{now: due}, due)
	if err != nil || !d.Due || !d.Next.Equal(due.Add(time.Hour)) {
		t.Fatalf("check on the instant = %+v, %v", d, err)
	}
	if got := d.UniqueKey("sch-1"); got != "schedule:sch-1:2026-01-01T05:00:00Z" {
		t.Errorf("unique key = %q", got)
	}
}

func TestCheckRefusesAnUnsetNextRun(t *testing.T) {
	s := Schedule{Recurrence: Daily, Zone: "UTC"}
	if _, err := s.Check(&manualWallClock{now: utc(2026, 1, 1, 0, 0)}, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

// Acceptance 3: an interval below one hour is refused with a typed error.
func TestIntervalBelowOneHourIsRefused(t *testing.T) {
	start := utc(2026, 1, 1, 0, 0)
	for name, s := range map[string]Schedule{
		"hourly zero":     {Recurrence: Hourly, Zone: "UTC", Start: start, Every: 0},
		"hourly negative": {Recurrence: Hourly, Zone: "UTC", Start: start, Every: -2},
		"custom zero":     {Recurrence: Custom, Zone: "UTC", Start: start, Unit: UnitHours},
		"custom days 0":   {Recurrence: Custom, Zone: "UTC", Start: start, Unit: UnitDays, Every: -1},
	} {
		err := s.Validate()
		if !errors.Is(err, ErrIntervalBelowFloor) || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrIntervalBelowFloor", name, err)
		}
		if _, err := s.Next(start); !errors.Is(err, ErrIntervalBelowFloor) {
			t.Errorf("%s: Next err = %v", name, err)
		}
	}
	if err := (Schedule{Recurrence: Hourly, Zone: "UTC", Start: start, Every: 1}).Validate(); err != nil {
		t.Errorf("one hour is the floor and must be accepted: %v", err)
	}
}

// Acceptance 4: an unknown IANA zone is refused.
func TestUnknownZoneIsRefused(t *testing.T) {
	for _, z := range []string{"", "Local", "Mars/Olympus", "est5edt-ish", "../etc/passwd", "Europe/Berlin\x00"} {
		s := Schedule{Recurrence: Daily, Zone: z, Hour: 8}
		if err := s.Validate(); !errors.Is(err, ErrUnknownZone) || !errors.Is(err, ErrInvalid) {
			t.Errorf("zone %q: err = %v, want ErrUnknownZone", z, err)
		}
	}
	if err := (Schedule{Recurrence: Daily, Zone: "UTC", Hour: 8}).Validate(); err != nil {
		t.Errorf("UTC: %v", err)
	}
}

func TestValidateRefusesMalformedSchedules(t *testing.T) {
	start := utc(2026, 1, 1, 0, 0)
	for name, s := range map[string]Schedule{
		"unknown recurrence":   {Recurrence: "yearly", Zone: "UTC"},
		"empty recurrence":     {Zone: "UTC"},
		"hour 24":              {Recurrence: Daily, Zone: "UTC", Hour: 24},
		"minute 60":            {Recurrence: Daily, Zone: "UTC", Minute: 60},
		"negative hour":        {Recurrence: Daily, Zone: "UTC", Hour: -1},
		"weekly no days":       {Recurrence: Weekly, Zone: "UTC"},
		"weekly duplicate day": {Recurrence: Weekly, Zone: "UTC", Weekdays: []time.Weekday{time.Monday, time.Monday}},
		"weekly bad day":       {Recurrence: Weekly, Zone: "UTC", Weekdays: []time.Weekday{7}},
		"monthly day 0":        {Recurrence: Monthly, Zone: "UTC"},
		"monthly day 32":       {Recurrence: Monthly, Zone: "UTC", DayOfMonth: 32},
		"hourly no start":      {Recurrence: Hourly, Zone: "UTC", Every: 1},
		"custom no start":      {Recurrence: Custom, Zone: "UTC", Every: 1, Unit: UnitDays},
		"custom bad unit":      {Recurrence: Custom, Zone: "UTC", Start: start, Every: 1, Unit: "minutes"},
		"daily with weekdays":  {Recurrence: Daily, Zone: "UTC", Weekdays: []time.Weekday{time.Monday}},
		"daily with start":     {Recurrence: Daily, Zone: "UTC", Start: start},
		"hourly with time":     {Recurrence: Hourly, Zone: "UTC", Start: start, Every: 1, Hour: 3},
		"monthly with unit":    {Recurrence: Monthly, Zone: "UTC", DayOfMonth: 1, Unit: UnitDays},
	} {
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestSystemClockAdvances(t *testing.T) {
	if d := time.Since((SystemClock{}).Now()); d < 0 || d > time.Minute {
		t.Errorf("SystemClock.Now is %s off", d)
	}
}

// Across a year in zones with every kind of change, occurrences strictly increase, never come closer than
// the one-hour floor, and a daily schedule fires exactly once per local date (never twice on a repeated
// hour, never zero times on a skipped one).
func TestOccurrencesAreMonotoneAndOncePerLocalDay(t *testing.T) {
	zones := []string{"America/New_York", "Europe/London", "Australia/Lord_Howe", "Pacific/Apia", "Asia/Kolkata", "America/Sao_Paulo", "Africa/Casablanca"}
	for _, z := range zones {
		loc, _ := time.LoadLocation(z)
		for _, hm := range [][2]int{{0, 0}, {1, 30}, {2, 30}, {3, 0}, {23, 59}} {
			s := Schedule{Recurrence: Daily, Zone: z, Hour: hm[0], Minute: hm[1]}
			prev := utc(2024, 1, 1, 0, 0)
			perDay := map[string]int{}
			for range 800 {
				next := mustNext(t, s, prev)
				if next.Sub(prev) < time.Hour && !prev.Equal(utc(2024, 1, 1, 0, 0)) {
					t.Fatalf("%s %02d:%02d: %s follows %s by less than an hour", z, hm[0], hm[1], next, prev)
				}
				perDay[next.In(loc).Format("2006-01-02")]++
				prev = next
			}
			for day, n := range perDay {
				if n != 1 {
					t.Fatalf("%s %02d:%02d: %d occurrences on local date %s", z, hm[0], hm[1], n, day)
				}
			}
		}
	}
}

// TestCustomRepeatsFarFromStart compares Next against sequential enumeration of every occurrence, probing
// years past Start, so an estimate that overshoots (and skips real occurrences) cannot hide.
func TestCustomRepeatsFarFromStart(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	starts := []time.Time{
		time.Date(2026, 1, 31, 8, 0, 0, 0, loc), // 31st: month clamping; 08:00 across both DST changes
		time.Date(2026, 3, 7, 2, 30, 0, 0, loc), // 02:30 falls in the spring-forward gap on Mar 8
	}
	for _, start := range starts {
		for _, unit := range []Unit{UnitDays, UnitWeeks, UnitMonths} {
			for every := 1; every <= 3; every++ {
				s := Schedule{Recurrence: Custom, Zone: "America/New_York", Start: start, Every: every, Unit: unit}
				if err := s.Validate(); err != nil {
					t.Fatal(err)
				}
				// The reference sequence, enumerated from n=0.
				var seq []time.Time
				for n := 0; n < 1200; n++ {
					seq = append(seq, s.customOccurrence(start.In(loc), n, loc))
				}
				horizon := start.AddDate(3, 0, 0)
				for probe := start; probe.Before(horizon); probe = probe.Add(7 * time.Hour) {
					var want time.Time
					for _, o := range seq {
						if o.After(probe) {
							want = o
							break
						}
					}
					got, err := s.Next(probe)
					if err != nil {
						t.Fatal(err)
					}
					if !got.Equal(want) {
						t.Fatalf("start %s unit %v every %d: Next(%s) = %s, want %s", start, unit, every,
							probe.UTC().Format(time.RFC3339), got.Format(time.RFC3339), want.Format(time.RFC3339))
					}
				}
			}
		}
	}
}
