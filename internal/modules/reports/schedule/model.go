package schedule

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
)

// State is the lifecycle of a schedule (DM-73).
type State string

const (
	Active   State = "active"
	Paused   State = "paused"
	Archived State = "archived"
)

// Reasons a schedule is paused: stable codes that equal the API's ReportPausedReason values.
const (
	PauseByUser          = "by_user"
	PauseOwnerDisabled   = "owner_disabled"
	PauseOwnerLostPerm   = "owner_lost_permission"
	PauseReassigned      = "reassigned"
	maxRecipients        = 200
	maxNameLen           = 200
	recipientKindAccount = "account"
	recipientKindEmail   = "email"
)

// Recipient is one named recipient. The JSON is the API's ReportRecipient, so an Action's input is the
// request body (ADR-0005 rule 10: one schema).
type Recipient struct {
	Kind      string   `json:"kind"`
	AccountID string   `json:"accountId,omitempty"`
	AsLink    bool     `json:"asLink,omitempty"`
	Address   string   `json:"address,omitempty"`
	Formats   []string `json:"formats"`
}

// Recurrence is the API's ReportRecurrence: one struct for the nine kinds, with only the fields of its kind set.
type Recurrence struct {
	Kind       string     `json:"kind"`
	Time       string     `json:"time,omitempty"`
	Weekdays   []int      `json:"weekdays,omitempty"`
	DayOfMonth int        `json:"dayOfMonth,omitempty"`
	EveryHours int        `json:"everyHours,omitempty"`
	Minute     *int       `json:"minute,omitempty"`
	Every      int        `json:"every,omitempty"`
	Start      *time.Time `json:"start,omitempty"`
}

// WriteInput is the content of a schedule as written: the API's ReportScheduleWrite, plus the schedule id.
// It is the Input of create and update.
type WriteInput struct {
	ScheduleID        string         `json:"scheduleId"`
	Name              string         `json:"name"`
	DefinitionID      string         `json:"definitionId"`
	DefinitionVersion int            `json:"definitionVersion,omitempty"`
	PresetID          string         `json:"presetId,omitempty"`
	Parameters        jsontext.Value `json:"parameters,omitempty"`
	Recurrence        Recurrence     `json:"recurrence"`
	TimeZone          string         `json:"timeZone"`
	NotifyOnlyIfData  bool           `json:"notifyOnlyIfData"`
	Recipients        []Recipient    `json:"recipients"`
	ConfirmedExternal []string       `json:"confirmedExternal,omitempty"`
}

// Schedule is the stored schedule: the current version's header and recipients.
type Schedule struct {
	ID                string
	Name              string
	DefinitionID      string
	DefinitionVersion int
	Preset            string
	Params            jsontext.Value
	Recurrence        Recurrence
	TimeZone          string
	Owner             string
	NotifyOnlyIfData  bool
	ConfirmedExternal []string
	State             State
	PauseReason       string
	Version           int
	NextRunAt         *time.Time
	LastFireAt        *time.Time
	CreatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Recipients        []Recipient
}

// Content is the before-image of one version (report_schedule_versions.content): everything an undo restores.
type Content struct {
	Name              string         `json:"name"`
	DefinitionID      string         `json:"definitionId"`
	DefinitionVersion int            `json:"definitionVersion"`
	Preset            string         `json:"preset,omitempty"`
	Params            jsontext.Value `json:"params"`
	Recurrence        Recurrence     `json:"recurrence"`
	TimeZone          string         `json:"timeZone"`
	Owner             string         `json:"owner"`
	NotifyOnlyIfData  bool           `json:"notifyOnlyIfData"`
	ConfirmedExternal []string       `json:"confirmedExternal,omitempty"`
	State             State          `json:"state"`
	PauseReason       string         `json:"pauseReason,omitempty"`
	Recipients        []Recipient    `json:"recipients"`
}

// Content returns the schedule's version content.
func (s Schedule) Content() Content {
	return Content{Name: s.Name, DefinitionID: s.DefinitionID, DefinitionVersion: s.DefinitionVersion, Preset: s.Preset, Params: s.Params,
		Recurrence: s.Recurrence, TimeZone: s.TimeZone, Owner: s.Owner, NotifyOnlyIfData: s.NotifyOnlyIfData,
		ConfirmedExternal: s.ConfirmedExternal, State: s.State, PauseReason: s.PauseReason, Recipients: s.Recipients}
}

// Errors of validation. Each is a stable refusal of the write; none carries a request value.
var (
	ErrInvalid = errors.New("schedule: invalid")
	timeRe     = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)
	nameRe     = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// anchor is the fixed instant an hourly recurrence counts elapsed hours from (DM-44: hourly steps in elapsed
// time), so "every 6 hours at minute 15" is the same instants on every host.
var anchor = time.Date(2000, 1, 3, 0, 0, 0, 0, time.UTC)

// Jobs converts the API recurrence to the DM-44 value the tick evaluates. The minimum interval (one hour) is
// checked by jobs.Schedule.Validate.
func (r Recurrence) Jobs(zone string) (jobs.Schedule, error) {
	s := jobs.Schedule{Zone: zone}
	clock := func() error {
		m := timeRe.FindStringSubmatch(r.Time)
		if m == nil {
			return invalid("time must be HH:MM")
		}
		s.Hour, _ = strconv.Atoi(m[1])
		s.Minute, _ = strconv.Atoi(m[2])
		return nil
	}
	switch r.Kind {
	case "hourly":
		if r.EveryHours < 1 || r.EveryHours > 168 || r.Minute == nil || *r.Minute < 0 || *r.Minute > 59 {
			return s, invalid("hourly needs everyHours 1..168 and a minute 0..59")
		}
		s.Recurrence, s.Every, s.Start = jobs.Hourly, r.EveryHours, anchor.Add(time.Duration(*r.Minute)*time.Minute)
	case "daily":
		s.Recurrence = jobs.Daily
		if err := clock(); err != nil {
			return s, err
		}
	case "weekly":
		s.Recurrence = jobs.Weekly
		if err := clock(); err != nil {
			return s, err
		}
		if len(r.Weekdays) == 0 || len(r.Weekdays) > 7 {
			return s, invalid("weekly needs 1..7 weekdays")
		}
		for _, d := range r.Weekdays {
			if d < 1 || d > 7 {
				return s, invalid("weekdays are 1 (Monday) to 7 (Sunday)")
			}
			s.Weekdays = append(s.Weekdays, time.Weekday(d%7)) // 7 is Sunday = 0
		}
	case "monthly_day", "monthly_last_day":
		s.Recurrence = jobs.Monthly
		if err := clock(); err != nil {
			return s, err
		}
		s.DayOfMonth = jobs.LastDay
		if r.Kind == "monthly_day" {
			if r.DayOfMonth < 1 || r.DayOfMonth > 31 {
				return s, invalid("dayOfMonth is 1..31")
			}
			s.DayOfMonth = r.DayOfMonth
		}
	case "custom_hours", "custom_days", "custom_weeks", "custom_months":
		if r.Every < 1 || r.Start == nil {
			return s, invalid("a custom recurrence needs every and start")
		}
		s.Recurrence, s.Every, s.Start = jobs.Custom, r.Every, r.Start.UTC()
		s.Unit = map[string]jobs.Unit{"custom_hours": jobs.UnitHours, "custom_days": jobs.UnitDays, "custom_weeks": jobs.UnitWeeks, "custom_months": jobs.UnitMonths}[r.Kind]
	default:
		return s, invalid("unknown recurrence kind")
	}
	if err := s.Validate(); err != nil {
		return s, err
	}
	return s, nil
}

// MoreOftenThanDaily reports whether the recurrence fires more than once a day: the per-DC floor (AC-38).
func (r Recurrence) MoreOftenThanDaily() bool {
	switch r.Kind {
	case "hourly":
		return r.EveryHours < 24
	case "custom_hours":
		return r.Every < 24
	}
	return false
}

// NextAfter is the first occurrence after t.
func (r Recurrence) NextAfter(zone string, t time.Time) (time.Time, error) {
	js, err := r.Jobs(zone)
	if err != nil {
		return time.Time{}, err
	}
	return js.Next(t)
}

// Validate checks the content a write carries, without the world: shape, bounds and the recurrence.
func (in WriteInput) Validate() error {
	if n := len([]rune(in.Name)); n < 1 || n > maxNameLen || !nameRe.MatchString(in.Name) {
		return invalid("name is 1..200 characters")
	}
	if in.DefinitionID == "" {
		return invalid("definitionId is required")
	}
	if len(in.Recipients) == 0 || len(in.Recipients) > maxRecipients {
		return invalid("recipients: 1..%d", maxRecipients)
	}
	if _, err := in.Recurrence.Jobs(in.TimeZone); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range in.Recipients {
		key, err := r.key()
		if err != nil {
			return err
		}
		if seen[key] {
			return invalid("a recipient is listed twice")
		}
		seen[key] = true
	}
	return nil
}

// key is the identity of a recipient: the account or the canonical (lower-case) address.
func (r Recipient) key() (string, error) {
	if len(r.Formats) == 0 || len(r.Formats) > 4 {
		return "", invalid("each recipient needs 1..4 formats")
	}
	for i, f := range r.Formats {
		if !slices.Contains([]string{"csv", "xlsx", "pdf", "html"}, f) || slices.Contains(r.Formats[:i], f) {
			return "", invalid("formats are csv, xlsx, pdf and html, once each")
		}
	}
	switch r.Kind {
	case recipientKindAccount:
		if !uuidRe.MatchString(r.AccountID) || r.Address != "" {
			return "", invalid("an account recipient names accountId only")
		}
		return "account:" + r.AccountID, nil
	case recipientKindEmail:
		if r.AccountID != "" || r.AsLink {
			return "", invalid("an e-mail recipient has an address and no link")
		}
		a, err := CanonicalAddress(r.Address)
		if err != nil {
			return "", err
		}
		return "email:" + a, nil
	}
	return "", invalid("unknown recipient kind")
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CanonicalAddress parses an address with the platform's strict parser (notify/mailaddr) and returns the
// canonical form the allowed-domain check and the confirmed set use.
func CanonicalAddress(raw string) (string, error) {
	a, err := mailaddr.Parse(raw)
	if err != nil {
		return "", invalid("not a valid e-mail address")
	}
	return a.String(), nil
}
