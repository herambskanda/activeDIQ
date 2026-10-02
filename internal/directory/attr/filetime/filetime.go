// Package filetime is the one codec for Large Integer time values and intervals (syntax 2.5.5.16;
// safe-primitives §5.3). Decoding is attribute-aware: the same integer means "never" on
// accountExpires, "must change at next logon" on pwdLastSet and "no value recorded" on lastLogon,
// so the caller names the attribute, and the sentinel decides the Kind. Lockout and password-expiry
// state is never computed from these values; it comes from msDS-User-Account-Control-Computed
// (package flags).
package filetime

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
)

// Error codes.
const (
	BadInteger         = codec.BadInteger
	Overflow           = codec.Overflow
	InvalidPolicyValue = "InvalidPolicyValue" // a policy interval that is positive (or otherwise impossible)
	UnverifiedValue    = "UnverifiedValue"    // a raw value whose meaning Microsoft does not document: refused, not guessed
	NotEncodable       = "NotEncodable"       // the value has no raw form on this attribute
	UnknownAttribute   = "UnknownAttribute"
	OutOfRange         = "OutOfRange" // a time outside 1601-01-01 to 9999-12-31
)

const (
	ticksPerSecond = 10_000_000
	// unixEpochTicks is 1970-01-01T00:00:00Z in FILETIME ticks (100 ns since 1601-01-01).
	unixEpochTicks = 116_444_736_000_000_000
	// MaxInstantTicks is 9999-12-31T23:59:59.9999999Z. Beyond it a value is OutOfRange: it
	// is shown as "unrepresentable (raw N)", never as a year-30828 date.
	MaxInstantTicks = 2_650_467_743_999_999_999
	maxInt64        = 1<<63 - 1
	minInt64        = -1 << 63
)

// Field is the meaning an attribute gives to a Large Integer instant.
type Field int

// The instant fields the codec knows.
const (
	// AccountExpires: 0 and 0x7FFFFFFFFFFFFFFF both mean Never.
	AccountExpires Field = iota + 1
	// PwdLastSet: 0 means MustChange. Absent means NoValue (the caller, not the codec, sees absence).
	PwdLastSet
	// LastLogon covers lastLogon, lastLogonTimestamp and badPasswordTime: 0 is NoValue, "no logon
	// recorded", which is not "never logged on".
	LastLogon
	// LockoutTime: 0 is NoValue; non-zero is an instant, not a lockout state.
	LockoutTime
	// PasswordExpiryComputed is msDS-UserPasswordExpiryTimeComputed: 0x7FFFFFFFFFFFFFFF is Never.
	PasswordExpiryComputed
)

var fieldByAttr = map[string]Field{
	"accountexpires":                      AccountExpires,
	"pwdlastset":                          PwdLastSet,
	"lastlogon":                           LastLogon,
	"lastlogontimestamp":                  LastLogon,
	"badpasswordtime":                     LastLogon,
	"lockouttime":                         LockoutTime,
	"msds-userpasswordexpirytimecomputed": PasswordExpiryComputed,
}

// FieldFor maps an attribute's LDAP display name (any case) to its field. An attribute the codec
// does not know is not guessed at.
func FieldFor(attribute string) (Field, error) {
	if f, ok := fieldByAttr[strings.ToLower(attribute)]; ok {
		return f, nil
	}
	return 0, codec.New(UnknownAttribute)
}

// Kind classifies a decoded instant field.
type Kind int

const (
	KindInstant    Kind = iota + 1 // Ticks is a point in time
	KindNever                      // documented "never" sentinel
	KindMustChange                 // pwdLastSet 0
	KindNoValue                    // 0 on a logon-style attribute: nothing recorded
	KindOutOfRange                 // not a documented sentinel and not a representable instant
)

var kindNames = map[Kind]string{
	KindInstant: "instant", KindNever: "never", KindMustChange: "mustChange",
	KindNoValue: "noValue", KindOutOfRange: "outOfRange",
}

func (k Kind) String() string { return kindNames[k] }

// Value is a decoded instant field. Ticks is always the raw integer as read.
type Value struct {
	Kind  Kind
	Ticks int64
}

// Time is the instant, in UTC; ok is false unless Kind is KindInstant.
func (v Value) Time() (t time.Time, ok bool) {
	if v.Kind != KindInstant {
		return time.Time{}, false
	}
	return ticksToTime(v.Ticks), true
}

// Raw is the raw integer as a decimal string: what an API carries instead of a 64-bit JSON number
// (2^53 + 1 would round as a number).
func (v Value) Raw() string { return strconv.FormatInt(v.Ticks, 10) }

// MarshalJSON renders {"kind":…,"time":…,"raw":"…"}; time appears only for an instant.
func (v Value) MarshalJSON() ([]byte, error) {
	out := struct {
		Kind string `json:"kind"`
		Time string `json:"time,omitempty"`
		Raw  string `json:"raw"`
	}{Kind: v.Kind.String(), Raw: v.Raw()}
	if t, ok := v.Time(); ok {
		out.Time = t.Format("2006-01-02T15:04:05.9999999Z07:00")
	}
	return json.Marshal(out)
}

func ticksToTime(ticks int64) time.Time {
	return time.Unix(ticks/ticksPerSecond-(unixEpochTicks/ticksPerSecond), (ticks%ticksPerSecond)*100).UTC()
}

// Decode reads the raw LDAP octets of a Large Integer attribute under RFC 4517's integer grammar
// and classifies it for the field.
func Decode(f Field, raw string) (Value, error) {
	if !validField(f) {
		return Value{}, codec.New(UnknownAttribute)
	}
	n, err := codec.ParseInteger(raw, 64)
	if err != nil {
		return Value{}, err
	}
	v := Value{Ticks: n}
	switch {
	case n == 0:
		switch f {
		case AccountExpires:
			v.Kind = KindNever
		case PwdLastSet:
			v.Kind = KindMustChange
		case LastLogon, LockoutTime:
			v.Kind = KindNoValue
		default:
			// msDS-UserPasswordExpiryTimeComputed = 0 is undocumented [UNVERIFIED]: neither 1601 nor "never".
			v.Kind = KindOutOfRange
		}
	case n == maxInt64 && (f == AccountExpires || f == PasswordExpiryComputed):
		v.Kind = KindNever
	case n > 0 && n <= MaxInstantTicks:
		v.Kind = KindInstant
	default:
		v.Kind = KindOutOfRange // negative (pwdLastSet -1 is write-only), or beyond year 9999
	}
	return v, nil
}

func validField(f Field) bool { return f >= AccountExpires && f <= PasswordExpiryComputed }

// Encode returns the raw octets for v on field f. An instant is encodable only on accountExpires:
// pwdLastSet, lastLogon, lastLogonTimestamp, badPasswordTime and lockoutTime are written by the DC
// (or by EncodePwdLastSet), and a forged value would hide an account from stale-account reports. A
// filter value for any field is Value.Raw(), not Encode. Never is 0 on accountExpires and
// 0x7FFFFFFFFFFFFFFF on the computed expiry; MustChange is 0 on pwdLastSet. NoValue and OutOfRange
// have no raw form: absence is not written, and an unrepresentable value is not invented.
func (f Field) Encode(v Value) (string, error) {
	switch {
	case v.Kind == KindInstant && f == AccountExpires && v.Ticks > 0 && v.Ticks <= MaxInstantTicks:
		return strconv.FormatInt(v.Ticks, 10), nil
	case v.Kind == KindNever && f == AccountExpires:
		return "0", nil
	case v.Kind == KindNever && f == PasswordExpiryComputed:
		return strconv.FormatInt(maxInt64, 10), nil
	case v.Kind == KindMustChange && f == PwdLastSet:
		return "0", nil
	}
	return "", codec.New(NotEncodable)
}

// EncodePwdLastSet is the only way pwdLastSet is written: 0 forces a change at next logon and -1
// clears the flag by stamping "now" (gotcha 36). No other value is ever written to it.
func EncodePwdLastSet(mustChange bool) string {
	if mustChange {
		return "0"
	}
	return "-1"
}

// FromTime returns the instant for t, for filter values and accountExpires writes. A time outside
// 1601-01-01 (exclusive of the zero sentinel) to 9999-12-31T23:59:59.9999999Z is OutOfRange.
func FromTime(t time.Time) (Value, error) {
	sec := t.Unix()
	// Guard the multiplication first: seconds outside 1601-01-01 .. 9999-12-31T23:59:59 cannot be an instant.
	if sec < -unixEpochTicks/ticksPerSecond || sec > 253_402_300_799 {
		return Value{}, codec.New(OutOfRange)
	}
	ticks := (sec+unixEpochTicks/ticksPerSecond)*ticksPerSecond + int64(t.Nanosecond())/100
	if ticks <= 0 || ticks > MaxInstantTicks {
		return Value{}, codec.New(OutOfRange)
	}
	return Value{Kind: KindInstant, Ticks: ticks}, nil
}

// IntervalField is the meaning an attribute gives to a Large Integer duration.
type IntervalField int

const (
	// MaxPwdAge covers maxPwdAge and msDS-MaximumPasswordAge: <= 0; -2^63 is Forever (passwords never
	// expire); 0 is undocumented [UNVERIFIED] and refused; positive is InvalidPolicyValue.
	MaxPwdAge IntervalField = iota + 1
	// LockoutDuration covers lockoutDuration and msDS-LockoutDuration: 0 and -2^63 are Forever
	// (locked until an administrator unlocks).
	LockoutDuration
	// PlainInterval covers lockoutObservationWindow and minPwdAge: <= 0, 0 is a zero duration.
	PlainInterval
)

var intervalByAttr = map[string]IntervalField{
	"maxpwdage":                MaxPwdAge,
	"msds-maximumpasswordage":  MaxPwdAge,
	"lockoutduration":          LockoutDuration,
	"msds-lockoutduration":     LockoutDuration,
	"lockoutobservationwindow": PlainInterval,
	"minpwdage":                PlainInterval,
}

// IntervalFieldFor maps an attribute's LDAP display name (any case) to its interval field.
func IntervalFieldFor(attribute string) (IntervalField, error) {
	if f, ok := intervalByAttr[strings.ToLower(attribute)]; ok {
		return f, nil
	}
	return 0, codec.New(UnknownAttribute)
}

// Interval is a decoded duration: Forever, or Ticks of 100 ns (the magnitude; the stored value is
// negative). Ticks is zero when Forever.
type Interval struct {
	Forever bool
	Ticks   int64
}

// Duration converts to a time.Duration; ok is false for Forever and for a span too long to hold.
func (i Interval) Duration() (d time.Duration, ok bool) {
	if i.Forever || i.Ticks > maxInt64/100 {
		return 0, false
	}
	return time.Duration(i.Ticks) * 100, true
}

// MarshalJSON renders {"kind":"forever"} or {"kind":"duration","ticks":"…","seconds":"…"}; the
// numbers are strings so a 64-bit value never passes through a JSON number.
func (i Interval) MarshalJSON() ([]byte, error) {
	if i.Forever {
		return []byte(`{"kind":"forever"}`), nil
	}
	return json.Marshal(struct {
		Kind    string `json:"kind"`
		Ticks   string `json:"ticks"`
		Seconds string `json:"seconds"`
	}{"duration", strconv.FormatInt(i.Ticks, 10), strconv.FormatInt(i.Ticks/ticksPerSecond, 10)})
}

// DecodeInterval reads a policy interval.
func DecodeInterval(f IntervalField, raw string) (Interval, error) {
	n, err := codec.ParseInteger(raw, 64)
	if err != nil {
		return Interval{}, err
	}
	switch {
	case f < MaxPwdAge || f > PlainInterval:
		return Interval{}, codec.New(UnknownAttribute)
	case n > 0:
		return Interval{}, codec.New(InvalidPolicyValue)
	case n == minInt64 && f == PlainInterval:
		return Interval{}, codec.New(UnverifiedValue) // not documented for these attributes
	case n == minInt64:
		return Interval{Forever: true}, nil
	case n == 0 && f == LockoutDuration:
		return Interval{Forever: true}, nil
	case n == 0 && f == MaxPwdAge:
		return Interval{}, codec.New(UnverifiedValue)
	}
	return Interval{Ticks: -n}, nil
}

// EncodeInterval returns the raw octets: Forever is -2^63 on maxPwdAge and 0 on lockoutDuration; a
// duration is its negated tick count. A zero duration on lockoutDuration or maxPwdAge would mean
// Forever or nothing documented, so it is NotEncodable.
func (f IntervalField) EncodeInterval(i Interval) (string, error) {
	switch {
	case f < MaxPwdAge || f > PlainInterval || i.Ticks < 0:
		return "", codec.New(NotEncodable)
	case i.Forever && f == MaxPwdAge:
		return strconv.FormatInt(minInt64, 10), nil
	case i.Forever && f == LockoutDuration:
		return "0", nil
	case i.Forever:
		return "", codec.New(NotEncodable)
	case i.Ticks == 0 && f != PlainInterval:
		return "", codec.New(NotEncodable)
	case i.Ticks == 0:
		return "0", nil
	}
	return strconv.FormatInt(-i.Ticks, 10), nil
}
